"""Write-backpressure tests: stalled-drain rising-edge WARN, a stuck writer
never blocking the read/dispatch path, and teardown flushing the queue
(campaign M5/M1.6, roadmap M4.6 "writer-backpressure/stalled-drain WARN +
teardown flush").

The writer task drains ``Session._write_queue`` to the socket on a dedicated
task so that ``writer.drain()`` backpressure stays off the read loop. These
tests model a peer that has stopped draining its socket: ``FakeWriter.drain()``
blocks forever on a never-set ``asyncio.Event``, so the writer task pops exactly
one frame and then parks. With nothing draining the queue, every assertion here
is about the *post-fix* hardened behaviour:

  * the rising-edge ``WRITE_QUEUE_WARN`` fires once when the queue first crosses
    the threshold even when an enqueue *steps over* (not lands exactly on) it;
  * the read/dispatch path can still enqueue a POLL_ACK while the writer is
    stalled - ``_send`` uses ``put_nowait`` and never awaits the stuck drain,
    so an inbound POLL is still acknowledged (never a mute-but-alive session);
  * ``PanelServer._teardown`` flushes the frames still queued behind the stalled
    writer to the socket *before* closing it, so no buffered ACK/alarm frame is
    silently dropped on shutdown.

Drives the real ``Session``/``PanelServer`` against a socket-free ``FakeWriter``,
reusing the helper shapes from ``tests/test_session.py``. Deterministic: no
wall-clock sleeps; progress is awaited on observable predicates only.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable

import pytest

from spcedp.client import (
    WRITE_QUEUE_MAXSIZE,
    WRITE_QUEUE_WARN,
    FrameDecoder,
    PanelServer,
    Session,
)
from spcedp.wire import FLAG_FROM_RECEIVER, Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio

PANEL_ID = 1000
RECEIVER_ID = 1001


class StalledWriter:
    """StreamWriter stand-in whose drain() blocks forever on a never-set Event.

    The writer task pops one frame, writes it (recorded in ``written``), then
    parks in ``drain()``; the queue can only grow from there. Mirrors the
    ``FakeWriter`` surface in ``tests/test_session.py`` so ``Session`` and
    ``PanelServer`` treat it as a real writer. ``release()`` lets a test
    unblock the single parked drain when it wants the queue to drain.
    """

    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False
        self._never = asyncio.Event()

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    async def drain(self) -> None:
        await self._never.wait()  # never set: drain stalls forever

    def release(self) -> None:
        self._never.set()

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, _name: str) -> tuple[str, int]:
        return ("test", 0)


def _make_session(writer: StalledWriter) -> tuple[Session, PanelServer, asyncio.Task]:
    """Build a Session over ``writer`` with the writer-task done-callback wired.

    Reproduces ``PanelServer._handle``'s setup so an unexpected writer exit
    would tear the session down (here the writer never exits; it stalls)."""
    sess = Session(
        panel_id=PANEL_ID,
        receiver_id=RECEIVER_ID,
        reader=None,  # type: ignore[arg-type]
        writer=writer,  # type: ignore[arg-type]
        key=None,
    )
    server = PanelServer(receiver_id=RECEIVER_ID)
    writer_task = asyncio.create_task(sess._writer_loop())
    writer_task.add_done_callback(lambda t: server._on_writer_done(t, sess, ("test", 0)))
    return sess, server, writer_task


async def _cancel(*tasks: asyncio.Task) -> None:
    for t in tasks:
        t.cancel()
    for t in tasks:
        with contextlib.suppress(asyncio.CancelledError):
            await t


async def _wait_for(predicate: Callable[[], bool], timeout: float = 1.0) -> None:
    async def _loop() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(_loop(), timeout)


def _outbound(seq: int) -> Frame:
    """An arbitrary outbound POLL_ACK-shaped frame to enqueue via _send."""
    return Frame(
        src_id=RECEIVER_ID,
        dst_id=PANEL_ID,
        sequence=seq,
        major=int(MajorCode.SESSION),
        minor=int(MinorCode.POLL_ACK),
        payload=b"12345678",
        src_flag=FLAG_FROM_RECEIVER,
    )


def _inbound_poll(seq: int, payload: bytes = b"abcdefgh") -> Frame:
    """A panel->receiver POLL frame (src_flag 0x00) for the dispatch path."""
    return Frame(
        src_id=PANEL_ID,
        dst_id=RECEIVER_ID,
        sequence=seq,
        major=int(MajorCode.SESSION),
        minor=int(MinorCode.POLL),
        payload=payload,
        src_flag=0x00,
    )


async def test_rising_edge_warn_fires_when_stepping_over_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Stepping the queue OVER (not onto) WRITE_QUEUE_WARN still warns exactly once.

    With a stalled drain the queue only grows. Enqueuing in steps of 3 jumps the
    queue from below the threshold to above it without ever landing on the exact
    value, which an ``== N`` one-shot check would miss. The rising-edge fix fires
    once on the crossing and does not re-fire while the queue stays above warn.
    """
    writer = StalledWriter()
    sess, server, wt = _make_session(writer)

    # Prime the stalled writer: the first enqueued frame is popped by the writer
    # task, written once, and then it parks forever in drain(). From here the
    # queue can only grow, so qsize accounting reflects a single stalled writer.
    sess._send(_outbound(0))
    await _wait_for(lambda: len(writer.written) >= 1)

    with caplog.at_level(logging.WARNING, logger="spcedp"):
        seq = 1
        # Step in 3s so we cross the exact WRITE_QUEUE_WARN boundary rather than
        # landing on it, but stop well short of the hard cap (no teardown here).
        while sess._write_queue.qsize() < WRITE_QUEUE_WARN + 30:
            for _ in range(3):
                sess._send(_outbound(seq & 0xFFFF))
                seq += 1

        warn_records = [r for r in caplog.records if "outbound queue at" in r.getMessage()]

    # Never landed exactly on the threshold yet the warning still fired - once.
    qsizes_at_warn = [WRITE_QUEUE_WARN in (sess._write_queue.qsize(),)]
    assert qsizes_at_warn == [False]  # current qsize is strictly above warn
    assert len(warn_records) == 1, [r.getMessage() for r in warn_records]
    assert sess._write_warned is True

    # Crossing the warn threshold is not a teardown trigger; the hard cap is.
    assert not sess._closed.is_set()
    assert sess._write_queue.qsize() < WRITE_QUEUE_MAXSIZE
    assert WRITE_QUEUE_WARN < WRITE_QUEUE_MAXSIZE

    await _cancel(wt)


async def test_warn_rearms_after_draining_below_threshold(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The rising-edge warning re-arms once the queue drains back below warn.

    A single one-shot would never warn a second time. After releasing the
    stalled drain so the queue empties, the next backlog must warn again.
    """
    writer = StalledWriter()
    sess, server, wt = _make_session(writer)
    # Prime the stalled writer (pops one, parks in drain) before backing up.
    sess._send(_outbound(0))
    await _wait_for(lambda: len(writer.written) >= 1)

    with caplog.at_level(logging.WARNING, logger="spcedp"):
        seq = 1
        # First backlog: cross the threshold (one warning).
        while sess._write_queue.qsize() < WRITE_QUEUE_WARN + 5:
            sess._send(_outbound(seq & 0xFFFF))
            seq += 1
        assert sess._write_warned is True
        first_warns = [r for r in caplog.records if "outbound queue at" in r.getMessage()]
        assert len(first_warns) == 1

        # Release the parked drain so the writer task empties the queue. Once it
        # is below the threshold, a fresh _send re-arms (clears _write_warned).
        writer.release()
        await _wait_for(lambda: sess._write_queue.qsize() < WRITE_QUEUE_WARN)
        sess._send(_outbound(seq & 0xFFFF))
        seq += 1
        await _wait_for(lambda: sess._write_warned is False)
        assert sess._write_warned is False

    await _cancel(wt)


async def test_dispatch_still_enqueues_poll_ack_while_writer_stalled() -> None:
    """A stalled writer must not block the read/dispatch path from ACKing a POLL.

    ``_send`` uses ``put_nowait`` and never awaits the stuck drain, so dispatch
    of an inbound POLL still enqueues its POLL_ACK (and bumps the poll count)
    even after the writer has parked behind a never-completing drain. This is
    the no-mute-but-alive guarantee: the receiver keeps acknowledging the panel.
    """
    writer = StalledWriter()
    sess, server, wt = _make_session(writer)

    # Pre-fill the queue with backlog the stalled writer cannot drain: the first
    # frame is popped and the writer parks in drain(); the rest sit queued, so
    # the writer task is genuinely stalled when the POLL arrives.
    for i in range(50):
        sess._send(_outbound(i & 0xFFFF))
    await _wait_for(lambda: len(writer.written) >= 1)
    backlog = sess._write_queue.qsize()
    assert backlog >= 1
    polls_before = sess._poll_count

    # Drive the real dispatch path with a panel-originated POLL. reply_echo ->
    # _send -> put_nowait must return immediately (not block on the stalled
    # drain) and enqueue a POLL_ACK behind the backlog.
    server._dispatch(sess, _inbound_poll(seq=0x1234))

    assert sess._poll_count == polls_before + 1
    assert sess._ready.is_set()
    # The POLL_ACK was enqueued (queue grew by exactly one), not dropped or
    # blocked: the dispatch call returned and the session is not torn down.
    assert sess._write_queue.qsize() == backlog + 1
    assert not sess._closed.is_set()
    assert not sess._teardown_requested.is_set()

    # The queued POLL_ACK echoes the request seq/payload (it is the last frame).
    last = Frame.decode(_drain_last(sess))
    assert last.minor == MinorCode.POLL_ACK
    assert last.sequence == 0x1234
    assert last.payload == b"abcdefgh"

    await _cancel(wt)


def _drain_last(sess: Session) -> bytes:
    """Pop every queued frame and return the last (the most recently enqueued)."""
    last = b""
    while not sess._write_queue.empty():
        last = sess._write_queue.get_nowait()
    return last


async def test_teardown_does_not_send_queued_commands() -> None:
    """A failed connection must not flush delayed control commands on shutdown."""
    writer = StalledWriter()
    sess, server, wt = _make_session(writer)
    for seq in range(10):
        sess._send(_outbound(seq))
    await _wait_for(lambda: len(writer.written) == 1)
    assert sess._write_queue.qsize() == 9

    await server._teardown(sess, FrameDecoder(), writer, (wt, None), ("test", 0))

    assert len(writer.written) == 1
    assert writer.closed
    assert sess._closed.is_set()
    assert wt.cancelled()
