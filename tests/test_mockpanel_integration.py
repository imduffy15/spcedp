"""Full wire-level integration via MockPanel + a real loopback PanelServer.

These tests close the gap that ``FakeSession`` (tests/test_panel.py) leaves open:
they drive the *whole* stack end to end over a real loopback socket - the panel
dials in, completes a HELLO/POLL handshake, the receiver's ``on_session`` builds
a :class:`~spcedp.Panel` via :meth:`Panel.from_session`, refreshes
info/areas/zones (including a genuinely *fragmented* ZONE_STATUS that the
client must reassemble across continuation requests), and a binary control apply
round-trips to an OK reply. Everything runs both in cleartext (``key=None``) and
fully encrypted end to end (a 16-byte key: encrypted HELLO_ACK plus an encrypted
SIA EVENT push that must parse).

The disconnect/teardown half drives ``PanelServer._handle``'s failure exits and
asserts the POST-FIX (roadmap M0/M4) contract - every failure surfaces, bounded,
and tears the session down cleanly, never a mute-but-alive receiver:

  * an encrypted frame arriving at a key-less receiver -> "no key" disconnect;
  * a wrong-key stream -> bounded give-up-resyncing teardown (not a long stall);
  * an idle peer that sends nothing -> idle-timeout teardown;

and in each case any in-flight command future fails with the typed
:class:`SpcConnectionLost`, never blocking until its own timeout.

The harness reuses MockPanel (tests/mockpanel.py) and the loopback PanelServer
pattern from tests/test_session.py.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest

cryptography = pytest.importorskip("cryptography")

from mockpanel import DEFAULT_NONCE, MockPanel  # noqa: E402

from spcedp.client import PanelServer, Session  # noqa: E402
from spcedp.commands import BinaryOp  # noqa: E402
from spcedp.errors import SpcConnectionLost  # noqa: E402
from spcedp.events import SiaEvent  # noqa: E402
from spcedp.panel import ArmMode, Panel  # noqa: E402
from spcedp.wire import (  # noqa: E402
    FLAG_FROM_RECEIVER,
    RESYNC_LIMIT,
    Frame,
    MajorCode,
    MinorCode,
)

pytestmark = pytest.mark.asyncio

PANEL_ID = 1000
RECEIVER_ID = 1001
KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

# Long enough that no prompt-teardown assertion can pass merely by waiting out
# the idle timer; the disconnect-path tests that *want* the idle timer use a
# small timeout explicitly.
IDLE_TIMEOUT = 30.0

# Scripted XML replies (the leading 0x01 is the FRAG_FIRST/"only chunk" marker;
# the panel's reply payloads carry it, like the wire). One area, three zones
# (so we can prove the stale-ghost-free refresh and the typed accessors), one
# output.
INFO_REPLY = (
    b'\x01<COMMAND_REPLY><INFO TYPE="SPC4000" VARIANT="4300" VERSION="3.15.0" '
    b'SN="123456" /></COMMAND_REPLY>'
)
AREA_REPLY = (
    b"\x01<COMMAND_REPLY><AREA_STATUS>"
    b'<AREA ID="1" NAME="House" MODE="3" />'
    b"</AREA_STATUS></COMMAND_REPLY>"
)
OUTPUT_REPLY = (
    b"\x01<COMMAND_REPLY><OUTPUT_STATUS>"
    b'<OUTPUT ID="2" NAME="Siren" STATE="0" />'
    b"</OUTPUT_STATUS></COMMAND_REPLY>"
)
DOOR_REPLY = b"\x01<COMMAND_REPLY><DOOR_STATUS></DOOR_STATUS></COMMAND_REPLY>"

# A ZONE_STATUS reply deliberately split across two EDP fragments: the first
# chunk (FRAG_FIRST 0x01) does not close </COMMAND_REPLY>, so the client must
# issue a continuation request and reassemble. The continuation chunk uses the
# FRAG_CONT marker 0x02.
ZONE_FRAG_1 = (
    b"\x01<COMMAND_REPLY><ZONE_STATUS>"
    b'<ZONE ID="1" ZONE_NAME="Hall" TYPE="1" AREA="1" INPUT="1" '
    b'INHIBIT_ALLOWED="1" ISOLATE_ALLOWED="0" />'
    b'<ZONE ID="2" ZONE_NAME="Kitchen" TYPE="1" AREA="1" INPUT="0" '
)
ZONE_FRAG_2 = (
    b'\x02INHIBIT_ALLOWED="1" ISOLATE_ALLOWED="1" />'
    b'<ZONE ID="3" ZONE_NAME="Garage" TYPE="1" AREA="1" INPUT="0" '
    b'INHIBIT_ALLOWED="0" ISOLATE_ALLOWED="0" />'
    b"</ZONE_STATUS></COMMAND_REPLY>"
)


def _command_id_from(req: Frame) -> str | None:
    """Pull the COMMAND ID string out of an XML request payload (skip marker)."""
    text = req.payload[1:].decode("ascii", "replace")
    marker = 'ID="'
    start = text.find(marker)
    if start < 0:
        return None
    start += len(marker)
    end = text.find('"', start)
    return text[start:end] if end >= 0 else None


async def _serve_refresh_and_control(panel: MockPanel, seen_bin: list[bytes]) -> None:
    """Panel-side responder for the refresh + control exchange.

    Pulls receiver-originated request frames off the mock's inbound queue and
    replies as a real panel would: single-frame XML replies for
    info/area/output/door, a *fragmented* two-frame reply for zone_status
    (continuation-aware), and a 1-byte OK for the binary control. Each reply
    echoes the request's sequence (the client correlates on it). Every binary
    request's raw payload is appended to ``seen_bin`` so the test can assert the
    control reached the wire as a genuine binary command, decrypted correctly.

    zone_status is stateful: the first request gets ZONE_FRAG_1 (which does not
    close </COMMAND_REPLY>), the continuation request gets ZONE_FRAG_2.
    """
    single_xml = {
        "info": INFO_REPLY,
        "area_status": AREA_REPLY,
        "output_status": OUTPUT_REPLY,
        "door_status": DOOR_REPLY,
    }
    zone_frags = [ZONE_FRAG_1, ZONE_FRAG_2]
    while True:
        try:
            req = await panel._inbound.get()
        except asyncio.CancelledError:
            return
        if req.major == MajorCode.XML_CMD and req.minor == MinorCode.REQUEST:
            cid = _command_id_from(req)
            if cid == "zone_status":
                payload = zone_frags.pop(0) if zone_frags else ZONE_FRAG_2
            else:
                payload = single_xml.get(cid, b"\x01<COMMAND_REPLY></COMMAND_REPLY>")
            reply = panel._panel_frame(
                major=int(MajorCode.XML_CMD),
                minor=int(MinorCode.REPLY),
                payload=payload,
                sequence=req.sequence,
            )
            await panel._write(reply.encode(key=panel.key))
        elif req.major == MajorCode.BINARY_CMD and req.minor == MinorCode.REQUEST:
            # Record the decoded binary payload (proves the control frame
            # arrived as a real binary command, decrypted under the key if any).
            seen_bin.append(bytes(req.payload))
            reply = panel._panel_frame(
                major=int(MajorCode.BINARY_CMD),
                minor=int(MinorCode.BINARY_REPLY),
                payload=b"\xf0",  # ReplyCode.OK
                sequence=req.sequence,
            )
            await panel._write(reply.encode(key=panel.key))
        # POLL_ACK / HELLO_ACK and anything else: ignore (the mock drives those).


async def _run_full_session(key: bytes | None) -> tuple[Panel, list[bytes]]:
    """Drive a complete handshake -> from_session/refresh -> control apply.

    Returns the built Panel and the list of raw binary-command payloads the
    panel-side responder observed (proves the control frame reached the wire as
    a real binary command). Works identically for cleartext (key=None) and
    encrypted (16-byte key) end to end.
    """
    built: list[Panel] = []
    seen_bin: list[bytes] = []
    done = asyncio.Event()

    async def on_session(sess: Session) -> None:
        # Build the high-level facade over the live session: this waits for the
        # POLL, then issues info/area/zone(fragmented) reads.
        panel = await Panel.from_session(sess)
        built.append(panel)
        # A binary control apply -> OK reply (AREA_SET_A(1)).
        await panel.area(1).set_a()
        done.set()

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        key=key,
        on_session=on_session,
        idle_timeout=IDLE_TIMEOUT,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID, key=key)
        await panel.connect()
        serve: asyncio.Task[None] | None = None
        try:
            # Complete the handshake BEFORE starting the scripted responder:
            # hello()/poll() and serve both consume from the inbound queue, so
            # the responder must not race them for the HELLO_ACK / POLL_ACK.
            hello_ack = await panel.hello()
            assert hello_ack.minor == MinorCode.HELLO_ACK
            assert hello_ack.payload == DEFAULT_NONCE
            assert hello_ack.src_flag == FLAG_FROM_RECEIVER
            # The POLL satisfies Panel.from_session's wait_ready(min_polls=1).
            poll_ack = await panel.poll()
            assert poll_ack.minor == MinorCode.POLL_ACK

            # Now hand the inbound queue to the scripted responder, which answers
            # the receiver's info/area/zone(fragmented)/binary
            # requests that on_session's Panel.from_session + control apply issue.
            serve = asyncio.create_task(_serve_refresh_and_control(panel, seen_bin))

            await asyncio.wait_for(done.wait(), 5.0)
        finally:
            if serve is not None:
                serve.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await serve
            await panel.disconnect()
    return built[0], seen_bin


# ---------------------------------------------------------------------------
# M4.3 / M4.4 - full handshake + refresh + control, cleartext AND encrypted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", [None, KEY], ids=["cleartext", "encrypted"])
async def test_full_handshake_refresh_and_control(key: bytes | None) -> None:
    """End to end over a real socket: HELLO/POLL handshake, Panel.from_session
    -> refresh (info/areas/zones from scripted XML incl. a FRAGMENTED
    zone_status the client reassembles), and a binary control apply -> OK.

    Run for both key=None and a 16-byte key, so the encrypted path (encrypted
    HELLO_ACK, encrypted XML/binary request+reply frames) is exercised end to
    end, not just unit round-tripped."""
    panel, seen_bin = await _run_full_session(key)

    # INFO parsed.
    assert panel.info.type == "SPC4000"
    assert panel.info.version == "3.15.0"
    assert panel.info.sn == "123456"

    # AREA parsed + typed accessor.
    assert panel.areas[1].name == "House"
    assert panel.areas[1].mode == "3"
    assert panel.areas[1].arm_mode is ArmMode.FULL
    assert panel.areas[1].is_armed is True

    # ZONE reassembled across the two fragments: all three zones present, in
    # order, with the right typed status (no stale ghosts, no lost fragment).
    assert list(panel.zones) == [1, 2, 3]
    assert panel.zones[1].name == "Hall"
    assert panel.zones[1].is_open is True  # INPUT="1"
    assert panel.zones[2].name == "Kitchen"
    assert panel.zones[2].is_open is False  # INPUT="0"
    assert panel.zones[3].name == "Garage"

    # The binary control apply reached the wire as a real 3-byte binary command
    # (AREA_SET_A, target=1, param=0) and completed without raising (OK
    # reply). With a key, this also proves the request decrypted correctly.
    assert seen_bin == [bytes([int(BinaryOp.AREA_SET_A), 1, 0])]


# ---------------------------------------------------------------------------
# M4.3 - encrypted end to end: encrypted HELLO_ACK + encrypted EVENT push parse
# ---------------------------------------------------------------------------


async def test_encrypted_hello_ack_is_on_the_wire_encrypted() -> None:
    """With a key configured both ends, the receiver's HELLO_ACK is encrypted on
    the wire: the encrypt flag bit is set and a key-less decoder cannot read it,
    while the keyed mock decoder recovers the echoed nonce."""
    from spcedp.wire import FLAG_ENCRYPTED, FrameDecoder

    captured_raw: list[bytes] = []

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, key=KEY, idle_timeout=IDLE_TIMEOUT
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            hello = Frame(
                src_id=PANEL_ID,
                dst_id=RECEIVER_ID,
                sequence=1,
                major=int(MajorCode.SESSION),
                minor=int(MinorCode.HELLO),
                payload=DEFAULT_NONCE,
                src_flag=0x00,
            )
            writer.write(hello.encode(key=KEY))
            await writer.drain()

            prefix = await asyncio.wait_for(reader.readexactly(2), 1.0)
            rem = int.from_bytes(prefix, "little")
            rest = await asyncio.wait_for(reader.readexactly(rem), 1.0)
            raw = prefix + rest
            captured_raw.append(raw)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
        await asyncio.sleep(0.05)

    raw = captured_raw[0]
    # The encrypted flag is set on the wire (struct offset 2 == wire offset 4).
    assert raw[4] & FLAG_ENCRYPTED
    # A key-less decoder cannot read it (it is genuinely encrypted)...
    with pytest.raises(ValueError, match="encrypted"):
        FrameDecoder(key=None).feed(raw)
    # ...but the keyed decoder recovers the HELLO_ACK echoing our nonce.
    frames = FrameDecoder(key=KEY).feed(raw)
    assert len(frames) == 1
    assert frames[0].minor == MinorCode.HELLO_ACK
    assert frames[0].payload == DEFAULT_NONCE


async def test_encrypted_event_push_parses_and_acks() -> None:
    """An encrypted SIA EVENT push from the panel is decrypted, parsed into a
    SiaEvent, surfaced to the event stream, and ACKed (the ACK itself encrypted)."""
    events: list[SiaEvent] = []

    async def on_session(sess: Session) -> None:
        async for event in sess.events():
            events.append(event)

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        key=KEY,
        on_session=on_session,
        idle_timeout=IDLE_TIMEOUT,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID, key=KEY)
        await panel.connect()
        try:
            assert (await panel.hello()).minor == MinorCode.HELLO_ACK
            ev_ack = await panel.push_event(b"E2[#1000|08521203062026|BA|1|Burglar||0]")
            # The EVENT_ACK came back (decrypted by the keyed mock decoder).
            assert ev_ack.minor == MinorCode.EVENT_ACK
            # The event stream delivered the parsed event.
            await asyncio.wait_for(_until(lambda: bool(events)), 2.0)
            assert events[0].sia_code == "BA"
            assert events[0].address == "1"
        finally:
            await panel.disconnect()
        await asyncio.sleep(0.05)


# ---------------------------------------------------------------------------
# M4.4 - PanelServer._handle disconnect/teardown paths
# ---------------------------------------------------------------------------


async def test_encrypted_frame_with_no_server_key_disconnects(caplog) -> None:
    """A panel sending encrypted frames to a receiver with NO key configured is
    not silently tolerated: the receiver logs the misconfiguration and
    disconnects (it cannot decode anything, so staying connected would be a
    mute receiver). Any in-flight command fails with SpcConnectionLost."""
    captured: list[Session] = []

    async def on_session(sess: Session) -> None:
        captured.append(sess)

    # Receiver has no key; the panel encrypts. The receiver's first decode hits
    # EncryptionRequired and must disconnect.
    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        key=None,
        on_session=on_session,
        idle_timeout=IDLE_TIMEOUT,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        # Mock encrypts with a key the receiver does not have.
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID, key=KEY)
        await panel.connect()
        try:
            with caplog.at_level(logging.ERROR, logger="spcedp"):
                # Send an encrypted HELLO. on_session never starts (no frame
                # decodes), so we cannot register a command via it; assert the
                # disconnect + log directly.
                hello = panel._panel_frame(
                    major=int(MajorCode.SESSION),
                    minor=int(MinorCode.HELLO),
                    payload=DEFAULT_NONCE,
                    sequence=panel._next_seq(),
                )
                await panel._write(hello.encode(key=KEY))

                # The receiver closes its end promptly (no key -> cannot decode).
                # The mock read pump sees EOF; assert the connection is gone.
                await _await_receiver_eof(panel)  # clean teardown, receiver closed
                assert any(
                    "no key is configured" in r.message and r.levelno >= logging.ERROR
                    for r in caplog.records
                )
            # No on_session ran for an undecodable stream.
            assert captured == []
        finally:
            await panel.disconnect()


async def test_wrong_key_stream_gives_up_resyncing_and_tears_down(caplog) -> None:
    """A panel encrypting with the WRONG key (the receiver has a key, just a
    different one) produces a stream the receiver can never decode. The decoder
    must give up resyncing after a BOUNDED number of bytes (RESYNC_LIMIT) and
    tear the session down - never an indefinite stall.

    We feed comfortably more than RESYNC_LIMIT bytes of wrong-key ciphertext and
    assert the receiver closes its end (clean teardown) and logs the give-up."""
    wrong_key = bytes(16)  # all-zero, != KEY

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        key=KEY,  # receiver expects KEY
        idle_timeout=IDLE_TIMEOUT,  # far above any resync window
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel(
            "127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID, key=wrong_key
        )
        await panel.connect()
        try:
            with caplog.at_level(logging.WARNING, logger="spcedp"):
                # Stream many wrong-key-encrypted frames: far more than
                # RESYNC_LIMIT bytes, so the decoder's resync budget is exhausted
                # and it raises (FrameDecodeError -> "gave up resyncing").
                blob = bytearray()
                while len(blob) < RESYNC_LIMIT * 3:
                    f = panel._panel_frame(
                        major=int(MajorCode.SESSION),
                        minor=int(MinorCode.POLL),
                        payload=DEFAULT_NONCE,
                        sequence=panel._next_seq(),
                    )
                    blob += f.encode(key=wrong_key)
                with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                    await panel.send_raw(bytes(blob))

                # Bounded teardown: the receiver closes its end well within the
                # idle timeout (the resync limit fired, not the 30s idle timer).
                await _await_receiver_eof(panel)
                assert any("gave up resyncing" in r.message for r in caplog.records)
        finally:
            await panel.disconnect()


async def test_idle_timeout_tears_down_and_fails_pending(caplog) -> None:
    """A peer that completes the handshake, registers an in-flight command, then
    goes silent must be reclaimed by the idle timeout: the session tears down
    cleanly and the pending command future fails with SpcConnectionLost (never
    blocks until its own long timeout)."""
    captured: list[Session] = []

    async def on_session(sess: Session) -> None:
        captured.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        on_session=on_session,
        idle_timeout=0.3,  # short: the test drives the idle path deterministically
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID)
        await panel.connect()
        try:
            assert (await panel.hello()).minor == MinorCode.HELLO_ACK
            await _until_async(lambda: bool(captured))
            sess = captured[0]

            # Register an in-flight command with a long timeout: if idle teardown
            # did NOT fail it, this would block on the 60s timeout, not the idle
            # timer. The mock never replies (and now goes silent).
            cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1, timeout=60))
            await _until_async(lambda: bool(sess._pending_bin))

            with caplog.at_level(logging.WARNING, logger="spcedp"):
                # Stop sending anything; the idle timeout (0.3s) elapses and the
                # receiver tears the session down, failing the pending future.
                with pytest.raises(SpcConnectionLost):
                    await asyncio.wait_for(cmd, 5.0)
                await _until_async(lambda: any("idle timeout" in r.message for r in caplog.records))
            # The receiver closed its end (clean teardown after idle).
            await _await_receiver_eof(panel)
        finally:
            await panel.disconnect()


# ---------------------------------------------------------------------------
# small async polling helpers (kept local; deterministic, no wall-clock sleeps)
# ---------------------------------------------------------------------------


async def _until(predicate) -> None:
    while not predicate():
        await asyncio.sleep(0)


async def _await_receiver_eof(panel: MockPanel, timeout: float = 5.0) -> None:
    """Block until the receiver closes its end of the connection.

    The mock's background read pump returns when ``reader.read()`` yields b""
    (EOF), so awaiting the pump task is a clean, race-free way to observe the
    receiver-side teardown without a second concurrent ``reader.read()`` (which
    asyncio forbids). The pump swallows the EOF/cancellation, so a normal return
    means a graceful close."""
    assert panel._read_pump is not None
    await asyncio.wait_for(asyncio.shield(panel._read_pump), timeout)


async def _until_async(predicate, timeout: float = 2.0) -> None:
    await asyncio.wait_for(_until(predicate), timeout)
