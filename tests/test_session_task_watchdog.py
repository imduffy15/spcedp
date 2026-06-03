"""Watchdog on the on_session task (H1 / roadmap M0.3).

A crashed ``on_session`` callback used to be invisible until teardown: the read
loop kept ACKing POLLs independently, so the link looked healthy while the
application logic (arming, event handling) was dead and events were being
enqueued-then-dropped. The fix attaches a done-callback to the session task
that logs the crash *immediately* and tears the session down, mirroring the
``on_event`` failure path.

These tests drive the real ``PanelServer._handle`` loop over a loopback socket
(the harness pattern from ``tests/test_session.py``) with an ``on_session`` that
raises right away, and assert the POST-FIX behaviour:

  * the exception is logged PROMPTLY - while the peer socket is still open and
    long before any idle timeout - not deferred to connection close;
  * teardown fires (the server-side handler closes the socket and fails any
    in-flight command future);
  * the session does NOT keep silently ACKing POLLs as if healthy.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

import pytest

from spcedp.client import PanelServer, Session
from spcedp.commands import BinaryOp
from spcedp.errors import SpcConnectionLost
from spcedp.wire import Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio

PANEL_ID = 1000
RECEIVER_ID = 1001

# Long enough that nothing here can pass by waiting it out: a prompt-teardown
# assertion that only succeeds because the idle timeout fired would be a false
# positive, so we keep this far above every wait_for budget below.
IDLE_TIMEOUT = 30.0

# The crash log line emitted by PanelServer._on_session_done.
CRASH_LOG_FRAGMENT = "on_session callback for"


def _session_frame(minor: MinorCode, *, sequence: int, payload: bytes) -> Frame:
    """A panel->receiver SESSION frame (src_flag 0x00 == from panel)."""
    return Frame(
        src_id=PANEL_ID,
        dst_id=RECEIVER_ID,
        sequence=sequence,
        major=int(MajorCode.SESSION),
        minor=int(minor),
        payload=payload,
        src_flag=0x00,
    )


async def _send_session_frame(
    writer: asyncio.StreamWriter, minor: MinorCode, *, sequence: int, payload: bytes
) -> None:
    writer.write(_session_frame(minor, sequence=sequence, payload=payload).encode())
    await writer.drain()


async def _read_frame(reader: asyncio.StreamReader) -> Frame:
    prefix = await reader.readexactly(2)
    rem = int.from_bytes(prefix, "little")
    rest = await reader.readexactly(rem)
    return Frame.decode(prefix + rest)


async def _wait_for(predicate, timeout: float = 1.0) -> None:
    async def _loop() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(_loop(), timeout)


async def test_crashed_on_session_is_logged_promptly_and_tears_down(caplog) -> None:
    """on_session raises immediately: the crash is logged and the session torn
    down PROMPTLY - while the panel socket is still open and far inside the idle
    timeout - never deferred to connection close."""
    entered: list[Session] = []

    async def on_session(sess: Session) -> None:
        entered.append(sess)
        raise RuntimeError("on_session boom")

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        on_session=on_session,
        idle_timeout=IDLE_TIMEOUT,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            with caplog.at_level(logging.ERROR, logger="spcedp"):
                # HELLO -> the receiver ACKs and starts on_session, which blows up.
                await _send_session_frame(writer, MinorCode.HELLO, sequence=1, payload=b"12345678")
                hello_ack = await asyncio.wait_for(_read_frame(reader), 1.0)
                assert hello_ack.minor == MinorCode.HELLO_ACK

                # on_session actually ran and raised...
                await _wait_for(lambda: bool(entered))

                # ...and the crash surfaces PROMPTLY in the log. The peer socket
                # is still open (we have not closed it) and the idle timeout is
                # 30s away, so a log appearing here cannot be the deferred
                # connection-close path or an idle-timeout disconnect.
                await _wait_for(
                    lambda: any(
                        CRASH_LOG_FRAGMENT in r.message and r.levelno >= logging.ERROR
                        for r in caplog.records
                    ),
                    timeout=2.0,
                )

            # Teardown fired: the server-side handler closed the socket from its
            # end, so our peer read hits EOF well within the idle timeout. This
            # confirms the read loop stopped on the teardown request rather than
            # waiting out idle_timeout.
            tail = await asyncio.wait_for(reader.read(), 5.0)
            assert tail == b""
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def test_crashed_on_session_does_not_keep_acking_polls(caplog) -> None:
    """After on_session crashes, the receiver must not behave as a mute-but-alive
    session that keeps ACKing POLLs as if healthy: teardown stops the read loop,
    so a POLL sent after the crash is never answered with an unbounded stream of
    POLL_ACKs - the connection is reclaimed instead."""
    crashed = asyncio.Event()

    async def on_session(sess: Session) -> None:
        try:
            raise RuntimeError("on_session boom")
        finally:
            crashed.set()

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        on_session=on_session,
        idle_timeout=IDLE_TIMEOUT,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            with caplog.at_level(logging.ERROR, logger="spcedp"):
                await _send_session_frame(writer, MinorCode.HELLO, sequence=1, payload=b"12345678")
                hello_ack = await asyncio.wait_for(_read_frame(reader), 1.0)
                assert hello_ack.minor == MinorCode.HELLO_ACK

                await asyncio.wait_for(crashed.wait(), 1.0)
                # The crash is observable promptly via the log hook.
                await _wait_for(
                    lambda: any(CRASH_LOG_FRAGMENT in r.message for r in caplog.records),
                    timeout=2.0,
                )

            # The panel keeps polling as if nothing happened. A mute-but-alive
            # session would answer every POLL forever; the torn-down session
            # answers none of them and the socket is reclaimed instead. We assert
            # the stream ends (EOF) rather than yielding an endless run of
            # POLL_ACKs - bounded, observable, never an indefinite healthy-looking
            # session.
            with contextlib.suppress(ConnectionResetError, BrokenPipeError):
                await _send_session_frame(writer, MinorCode.POLL, sequence=2, payload=b"abcdefgh")

            saw_eof = False
            poll_acks = 0
            for _ in range(64):
                try:
                    frame = await asyncio.wait_for(_read_frame(reader), 5.0)
                except asyncio.IncompleteReadError:
                    saw_eof = True
                    break
                if frame.minor == MinorCode.POLL_ACK:
                    poll_acks += 1
            # The session was reclaimed (EOF) rather than left answering POLLs.
            assert saw_eof
            # At most the pre-crash POLL_ACK could have been in flight; the
            # post-crash POLL is never met with a fresh stream of ACKs.
            assert poll_acks <= 1
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


async def test_crashed_on_session_fails_inflight_command(caplog) -> None:
    """A command already awaiting a panel reply when on_session crashes must fail
    fast with the typed SpcConnectionLost (teardown fails pending futures) rather
    than blocking until its own timeout - the session does not silently persist."""
    captured: list[Session] = []
    proceed = asyncio.Event()

    async def on_session(sess: Session) -> None:
        captured.append(sess)
        # Hold until the test has an in-flight command registered, then crash.
        await proceed.wait()
        raise RuntimeError("on_session boom")

    server = PanelServer(
        receiver_id=RECEIVER_ID,
        bind="127.0.0.1",
        port=0,
        on_session=on_session,
        idle_timeout=IDLE_TIMEOUT,
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await _send_session_frame(writer, MinorCode.HELLO, sequence=1, payload=b"12345678")
            hello_ack = await asyncio.wait_for(_read_frame(reader), 1.0)
            assert hello_ack.minor == MinorCode.HELLO_ACK
            await _wait_for(lambda: bool(captured))
            sess = captured[0]

            # An in-flight command with a generous timeout: if teardown did not
            # fail it, this would block on the long timeout, not on the crash.
            cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1, timeout=60))
            await _wait_for(lambda: bool(sess._pending_bin))

            with caplog.at_level(logging.ERROR, logger="spcedp"):
                proceed.set()  # on_session crashes now
                with pytest.raises(SpcConnectionLost):
                    await asyncio.wait_for(cmd, 5.0)
                assert any(CRASH_LOG_FRAGMENT in r.message for r in caplog.records)
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
