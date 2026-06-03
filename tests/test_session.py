"""Tests for the async Session: request/reply correlation, dispatch, teardown.

These drive Session against a fake StreamWriter (no real socket) and use the
real PanelServer._dispatch to inject replies, so the future-keyed-by-sequence
correlation, fragment pull loop, reply demux and disconnect handling are all
exercised without a live panel.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest

from spcedp.client import MAX_XML_FRAGMENTS, PanelServer, Session
from spcedp.commands import BinaryOp, PanelOp
from spcedp.errors import SpcConnectionLost, SpcError, SpcProtocolError, SpcTimeout
from spcedp.events import SiaEvent
from spcedp.wire import FLAG_FROM_RECEIVER, Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio

PANEL_ID = 1000
RECEIVER_ID = 1001
INFO_REPLY = (
    b'\x01<COMMAND_REPLY><INFO TYPE="SPC4000" VARIANT="4300" VERSION="3.15.0" /></COMMAND_REPLY>'
)


class FakeWriter:
    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    async def drain(self) -> None:
        return

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, _name: str) -> tuple[str, int]:
        return ("test", 0)


def _make_session() -> tuple[Session, FakeWriter, PanelServer, asyncio.Task]:
    writer = FakeWriter()
    sess = Session(
        panel_id=PANEL_ID,
        receiver_id=RECEIVER_ID,
        reader=None,  # type: ignore[arg-type]
        writer=writer,
    )
    server = PanelServer(receiver_id=RECEIVER_ID)
    writer_task = asyncio.create_task(sess._writer_loop())
    return sess, writer, server, writer_task


async def _wait_for(predicate, timeout: float = 1.0) -> None:
    async def _loop() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(_loop(), timeout)


async def _cancel(*tasks: asyncio.Task) -> None:
    for t in tasks:
        t.cancel()
    for t in tasks:
        with contextlib.suppress(asyncio.CancelledError):
            await t


def _reply(seq: int, payload: bytes, *, major: MajorCode, minor: MinorCode) -> Frame:
    return Frame(
        src_id=PANEL_ID,
        dst_id=RECEIVER_ID,
        sequence=seq,
        major=int(major),
        minor=int(minor),
        payload=payload,
    )


async def test_xml_command_resolves_on_matching_reply() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.xml_command("info"))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    assert req.major == MajorCode.XML_CMD
    assert req.minor == MinorCode.REQUEST
    assert req.src_flag == FLAG_FROM_RECEIVER
    assert req.src_id == RECEIVER_ID and req.dst_id == PANEL_ID

    server._dispatch(
        sess, _reply(req.sequence, INFO_REPLY, major=MajorCode.XML_CMD, minor=MinorCode.REPLY)
    )
    result = await asyncio.wait_for(cmd, 1.0)
    assert result["INFO"][0]["TYPE"] == "SPC4000"
    await _cancel(wt)


async def test_xml_command_does_not_resolve_on_wrong_sequence() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.xml_command("info", timeout=0.2))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    # Reply carries a different sequence; must not satisfy the request.
    server._dispatch(
        sess,
        _reply(req.sequence ^ 0xFF, INFO_REPLY, major=MajorCode.XML_CMD, minor=MinorCode.REPLY),
    )
    with pytest.raises(SpcTimeout):
        await asyncio.wait_for(cmd, 1.0)
    await _cancel(wt)


async def test_xml_command_reassembles_fragments() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.xml_command("area_status"))
    await _wait_for(lambda: len(writer.written) >= 1)
    req1 = Frame.decode(writer.written[-1])
    assert req1.payload[0] == 0x01  # FRAG_FIRST
    server._dispatch(
        sess,
        _reply(
            req1.sequence,
            b'\x01<COMMAND_REPLY><AREA_STATUS><AREA ID="1" NAME="Home" ',
            major=MajorCode.XML_CMD,
            minor=MinorCode.REPLY,
        ),
    )

    # Incomplete reply -> xml_command sends a continuation request.
    await _wait_for(lambda: len(writer.written) >= 2)
    req2 = Frame.decode(writer.written[-1])
    assert req2.payload[0] == 0x02  # FRAG_CONT
    server._dispatch(
        sess,
        _reply(
            req2.sequence,
            b'\x02MODE="0" /></AREA_STATUS></COMMAND_REPLY>',
            major=MajorCode.XML_CMD,
            minor=MinorCode.REPLY,
        ),
    )

    result = await asyncio.wait_for(cmd, 1.0)
    assert result["AREA_STATUS"][0]["NAME"] == "Home"
    await _cancel(wt)


async def test_xml_command_caps_runaway_fragmentation() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.xml_command("zone_status"))
    # Answer every request with a chunk that never closes </COMMAND_REPLY>.
    for i in range(MAX_XML_FRAGMENTS):
        await _wait_for(lambda i=i: len(writer.written) > i)
        req = Frame.decode(writer.written[i])
        server._dispatch(
            sess,
            _reply(
                req.sequence,
                b"\x02<COMMAND_REPLY>still open",
                major=MajorCode.XML_CMD,
                minor=MinorCode.REPLY,
            ),
        )
    with pytest.raises(SpcProtocolError, match="did not close"):
        await asyncio.wait_for(cmd, 2.0)
    await _cancel(wt)


async def test_binary_command_ok_returns_none() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 3, 1))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    assert req.major == MajorCode.BINARY_CMD
    assert req.payload == b"\x01\x03\x01"
    server._dispatch(
        sess,
        _reply(req.sequence, b"\xf0", major=MajorCode.BINARY_CMD, minor=MinorCode.BINARY_REPLY),
    )
    assert await asyncio.wait_for(cmd, 1.0) is None
    await _cancel(wt)


async def test_binary_command_raises_on_error_code() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 3))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    server._dispatch(
        sess,
        _reply(req.sequence, b"\xfc", major=MajorCode.BINARY_CMD, minor=MinorCode.BINARY_REPLY),
    )
    with pytest.raises(SpcError) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert exc.value.code == 0xFC
    await _cancel(wt)


async def test_binary_command_raises_on_empty_reply() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 3))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    server._dispatch(
        sess, _reply(req.sequence, b"", major=MajorCode.BINARY_CMD, minor=MinorCode.BINARY_REPLY)
    )
    with pytest.raises(SpcError):
        await asyncio.wait_for(cmd, 1.0)
    await _cancel(wt)


async def test_panel_command_routes_major5_minor1() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.panel_command(PanelOp.TEST))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    assert req.major == MajorCode.PANEL_CMD
    assert req.payload == bytes([int(PanelOp.TEST)])
    server._dispatch(
        sess, _reply(req.sequence, b"\xf0", major=MajorCode.PANEL_CMD, minor=MinorCode.PANEL_REPLY)
    )
    assert await asyncio.wait_for(cmd, 1.0) is None
    await _cancel(wt)


async def test_reply_echo_mirrors_seq_and_payload() -> None:
    sess, writer, server, wt = _make_session()
    req = Frame(
        src_id=PANEL_ID,
        dst_id=RECEIVER_ID,
        sequence=0xABCD,
        major=int(MajorCode.SESSION),
        minor=int(MinorCode.POLL),
        payload=b"12345678",
        src_flag=0x00,
    )
    sess.reply_echo(req, int(MinorCode.POLL_ACK))
    await _wait_for(lambda: len(writer.written) >= 1)
    ack = Frame.decode(writer.written[-1])
    assert ack.sequence == 0xABCD
    assert ack.payload == b"12345678"
    assert ack.minor == MinorCode.POLL_ACK
    assert ack.src_flag == FLAG_FROM_RECEIVER
    assert ack.src_id == RECEIVER_ID and ack.dst_id == PANEL_ID
    await _cancel(wt)


async def test_fail_pending_unblocks_awaiting_command() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1))
    await _wait_for(lambda: len(writer.written) >= 1)
    sess.fail_pending(ConnectionResetError("panel disconnected"))
    with pytest.raises(ConnectionResetError):
        await asyncio.wait_for(cmd, 1.0)
    await _cancel(wt)


async def test_events_stream_yields_emitted_events() -> None:
    sess, writer, server, wt = _make_session()
    ev = SiaEvent(
        spc_id=PANEL_ID,
        timestamp=None,
        timestamp_raw="08521203062026",
        sia_code="BA",
        address="1",
        description="x",
        verification_id="0",
    )
    sess.emit_event(ev)
    agen = sess.events()
    got = await asyncio.wait_for(agen.__anext__(), 1.0)
    assert got is ev
    await agen.aclose()
    await _cancel(wt)


async def _read_frame(reader: asyncio.StreamReader) -> Frame:
    prefix = await reader.readexactly(2)
    rem = int.from_bytes(prefix, "little")
    rest = await reader.readexactly(rem)
    return Frame.decode(prefix + rest)


async def test_panelserver_handshake_and_event_end_to_end() -> None:
    """Drive the real PanelServer._handle loop over a loopback socket:
    HELLO -> HELLO_ACK, an event -> EVENT_ACK + on_event firing, and a clean
    teardown when the peer disconnects."""
    events: list[SiaEvent] = []
    sessions: list[Session] = []

    async def on_session(sess: Session) -> None:
        sessions.append(sess)

    async def on_event(sess: Session, ev: SiaEvent) -> None:
        events.append(ev)

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        on_session=on_session,
        on_event=on_event,
        idle_timeout=5.0,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        hello = Frame(
            src_id=PANEL_ID,
            dst_id=RECEIVER_ID,
            sequence=1,
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.HELLO),
            payload=b"12345678",
            src_flag=0x00,
        )
        writer.write(hello.encode())
        await writer.drain()
        ack = await asyncio.wait_for(_read_frame(reader), 1.0)
        assert ack.minor == MinorCode.HELLO_ACK
        assert ack.payload == b"12345678"
        assert ack.src_flag == FLAG_FROM_RECEIVER

        ev_frame = Frame(
            src_id=PANEL_ID,
            dst_id=RECEIVER_ID,
            sequence=2,
            major=int(MajorCode.EVENT),
            minor=int(MinorCode.EVENT_PUSH),
            payload=b"E2[#1000|08521203062026|BA|0|Burglar||0]",
            src_flag=0x00,
        )
        writer.write(ev_frame.encode())
        await writer.drain()
        ev_ack = await asyncio.wait_for(_read_frame(reader), 1.0)
        assert ev_ack.minor == MinorCode.EVENT_ACK

        await _wait_for(lambda: len(events) >= 1)
        assert events[0].sia_code == "BA"
        assert sessions and sessions[0].panel_id == PANEL_ID

        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)  # let the server-side handler tear down cleanly


async def test_emit_event_drops_oldest_when_full() -> None:
    sess, writer, server, wt = _make_session()
    sess._events = asyncio.Queue(maxsize=2)
    evs = [
        SiaEvent(
            spc_id=i,
            timestamp=None,
            timestamp_raw="08521203062026",
            sia_code="BA",
            address="",
            description="",
            verification_id="",
        )
        for i in (1, 2, 3)
    ]
    for ev in evs:
        sess.emit_event(ev)
    agen = sess.events()
    first = await agen.__anext__()
    second = await agen.__anext__()
    # The oldest (spc_id=1) was dropped to make room for the newest.
    assert (first.spc_id, second.spc_id) == (2, 3)
    await agen.aclose()
    await _cancel(wt)


async def test_dispatch_survives_malformed_sia_payload() -> None:
    sess, writer, server, wt = _make_session()
    called: list[SiaEvent] = []

    async def on_event(s: Session, e: SiaEvent) -> None:
        called.append(e)

    server._on_event = on_event
    garbage = Frame(
        src_id=PANEL_ID,
        dst_id=RECEIVER_ID,
        sequence=9,
        major=int(MajorCode.EVENT),
        minor=int(MinorCode.EVENT_PUSH),
        payload=b"this is not a SIA event",
    )
    server._dispatch(sess, garbage)  # must not raise

    # The event is still ACKed (connection survives) ...
    await _wait_for(lambda: len(writer.written) >= 1)
    ack = Frame.decode(writer.written[-1])
    assert ack.minor == MinorCode.EVENT_ACK
    assert ack.sequence == 9
    # ... but no event is emitted and the callback is never invoked.
    assert called == []
    assert sess._events.empty()
    await _cancel(wt)


async def test_events_stops_after_session_closed() -> None:
    sess, writer, server, wt = _make_session()
    ev = SiaEvent(
        spc_id=1,
        timestamp=None,
        timestamp_raw="08521203062026",
        sia_code="BA",
        address="",
        description="",
        verification_id="",
    )
    sess.emit_event(ev)
    sess._closed.set()
    # Buffered event is drained, then the iterator stops instead of hanging.
    got = [e async for e in sess.events()]
    assert got == [ev]
    await _cancel(wt)


async def test_disconnect_fails_pending_command_end_to_end() -> None:
    captured: list[Session] = []

    async def on_session(sess: Session) -> None:
        captured.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=5.0
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        hello = Frame(
            src_id=PANEL_ID,
            dst_id=RECEIVER_ID,
            sequence=1,
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.HELLO),
            payload=b"12345678",
            src_flag=0x00,
        )
        writer.write(hello.encode())
        await writer.drain()
        await asyncio.wait_for(_read_frame(reader), 1.0)  # HELLO_ACK
        await _wait_for(lambda: len(captured) >= 1)
        sess = captured[0]

        cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1, timeout=10))
        await _wait_for(lambda: bool(sess._pending_bin))  # request registered

        # Client disconnects: server teardown must fail the in-flight future
        # rather than leaving the caller blocked until its own timeout.
        writer.close()
        await writer.wait_closed()
        with pytest.raises(SpcConnectionLost):
            await asyncio.wait_for(cmd, 2.0)


async def test_on_event_exception_is_logged_and_session_survives(caplog) -> None:
    async def on_event(sess: Session, ev: SiaEvent) -> None:
        raise RuntimeError("boom")

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_event=on_event, idle_timeout=5.0
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        hello = Frame(
            src_id=PANEL_ID,
            dst_id=RECEIVER_ID,
            sequence=1,
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.HELLO),
            payload=b"12345678",
            src_flag=0x00,
        )
        writer.write(hello.encode())
        await writer.drain()
        await asyncio.wait_for(_read_frame(reader), 1.0)  # HELLO_ACK

        with caplog.at_level(logging.ERROR, logger="spcedp"):
            ev = Frame(
                src_id=PANEL_ID,
                dst_id=RECEIVER_ID,
                sequence=2,
                major=int(MajorCode.EVENT),
                minor=int(MinorCode.EVENT_PUSH),
                payload=b"E2[#1000|08521203062026|BA|0|Burglar||0]",
                src_flag=0x00,
            )
            writer.write(ev.encode())
            await writer.drain()
            await asyncio.wait_for(_read_frame(reader), 1.0)  # EVENT_ACK still sent

            # The raising callback must not kill the session: a later POLL is
            # still answered.
            poll = Frame(
                src_id=PANEL_ID,
                dst_id=RECEIVER_ID,
                sequence=3,
                major=int(MajorCode.SESSION),
                minor=int(MinorCode.POLL),
                payload=b"abcdefgh",
                src_flag=0x00,
            )
            writer.write(poll.encode())
            await writer.drain()
            ack = await asyncio.wait_for(_read_frame(reader), 1.0)
            assert ack.minor == MinorCode.POLL_ACK

            await _wait_for(
                lambda: any("on_event callback raised" in r.message for r in caplog.records)
            )

        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.05)
