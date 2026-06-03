"""Writer-fault and bounded-queue teardown tests (campaign B2 / roadmap M0.2).

The writer task drains ``Session._write_queue`` to the socket on a dedicated
task. The hardening fix (M0.2) guarantees that a writer death or a backed-up
queue can never leave a *mute-but-alive* receiver: any non-cancellation exit of
``_writer_loop`` is broadened to ``(OSError, ssl.SSLError)``, logged, and the
writer-task done-callback (``PanelServer._on_writer_done``) tears the session
down (``request_teardown`` -> ``_closed`` + ``_teardown_requested``). The queue
is bounded by ``WRITE_QUEUE_MAXSIZE`` and ``_send`` tears down on ``QueueFull``
rather than dropping an outbound ACK/alarm frame or growing without limit.

These tests assert the post-fix behaviour. They drive the real ``Session`` and
the real ``PanelServer._on_writer_done`` against a ``FakeWriter`` (no socket),
reusing the helpers and patterns from ``tests/test_session.py``. The
done-callback is attached here the same way ``PanelServer._handle`` attaches it,
because ``_make_session`` builds the writer task without one.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from collections.abc import Callable

import pytest

from spcedp.client import WRITE_QUEUE_MAXSIZE, WRITE_QUEUE_WARN, PanelServer, Session
from spcedp.wire import Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio

PANEL_ID = 1000
RECEIVER_ID = 1001


class FaultyWriter:
    """A StreamWriter stand-in whose drain() always fails after the first write.

    ``error`` is raised from ``drain()``; the first ``write`` is recorded so we
    can confirm the writer loop actually pulled a frame before dying. Mirrors the
    ``FakeWriter`` surface in ``tests/test_session.py`` so ``Session`` and
    ``PanelServer`` treat it as a real writer.
    """

    def __init__(self, error: BaseException) -> None:
        self.written: list[bytes] = []
        self.closed = False
        self._error = error

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    async def drain(self) -> None:
        raise self._error

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, _name: str) -> tuple[str, int]:
        return ("test", 0)


class _StalledWriter:
    """Records writes; its drain() never returns (queue can only grow)."""

    def __init__(self) -> None:
        self.written: list[bytes] = []
        self.closed = False
        self._never = asyncio.Event()

    def write(self, data: bytes) -> None:
        self.written.append(bytes(data))

    async def drain(self) -> None:
        await self._never.wait()  # never set: drain stalls forever

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, _name: str) -> tuple[str, int]:
        return ("test", 0)


def _make_faulty_session(
    writer: FaultyWriter | _StalledWriter,
) -> tuple[Session, PanelServer, asyncio.Task]:
    """Build a Session over ``writer`` with the writer-task done-callback wired.

    Reproduces ``PanelServer._handle``'s setup: create the writer loop task and
    attach ``_on_writer_done`` so an unexpected writer exit tears the session
    down (the bit ``_make_session`` in test_session.py omits)."""
    sess = Session(
        panel_id=PANEL_ID,
        receiver_id=RECEIVER_ID,
        reader=None,  # type: ignore[arg-type]
        writer=writer,  # type: ignore[arg-type]
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


def _frame(seq: int) -> Frame:
    """An arbitrary outbound POLL_ACK-shaped frame to enqueue via _send."""
    return Frame(
        src_id=RECEIVER_ID,
        dst_id=PANEL_ID,
        sequence=seq,
        major=int(MajorCode.SESSION),
        minor=int(MinorCode.POLL_ACK),
        payload=b"12345678",
    )


@pytest.mark.parametrize(
    ("error", "log_needle"),
    [
        (OSError(105, "No buffer space available"), "socket error"),
        (ssl.SSLError("decryption failed or bad record mac"), "socket error"),
    ],
)
async def test_writer_drain_failure_tears_session_down(
    error: BaseException, log_needle: str, caplog: pytest.LogCaptureFixture
) -> None:
    """drain() raising OSError(105) or ssl.SSLError must not go mute-alive.

    Post-fix: the broadened ``except (OSError, ssl.SSLError)`` in
    ``_writer_loop`` logs and returns; the writer-task done-callback fires and
    calls ``request_teardown`` -> ``_closed`` and ``_teardown_requested`` set.
    """
    writer = FaultyWriter(error)
    sess, server, wt = _make_faulty_session(writer)

    with caplog.at_level(logging.WARNING, logger="spcedp"):
        # Push a frame: the writer loop pops it, write() records it, drain()
        # raises -> loop exits -> done-callback tears the session down.
        sess._send(_frame(1))

        # Teardown must happen promptly without any wall-clock wait.
        await _wait_for(lambda: sess._closed.is_set())
        await _wait_for(lambda: wt.done())

    # The writer task exited (it did not get stuck swallowing the error).
    assert wt.done()
    assert not wt.cancelled()
    assert wt.exception() is None  # the loop caught it and returned cleanly

    # Done-callback fired: both teardown events are set.
    assert sess._closed.is_set()
    assert sess._teardown_requested.is_set()

    # The writer actually attempted the failing write before dying.
    assert writer.written == [_frame(1).encode()]

    # Both the loop's own log and the done-callback's log surfaced the fault.
    messages = [r.getMessage() for r in caplog.records]
    assert any(log_needle in m for m in messages), messages
    assert any("tearing session down" in m for m in messages), messages

    await _cancel(wt)


async def test_write_queue_stays_bounded_after_writer_death() -> None:
    """After the writer dies, _send must never grow the queue without limit.

    Pushing far more frames than ``WRITE_QUEUE_MAXSIZE`` (the historical bug
    left this at ~100000) keeps the queue bounded by the cap and re-confirms the
    session stays torn down.
    """
    writer = FaultyWriter(OSError(105, "No buffer space available"))
    sess, server, wt = _make_faulty_session(writer)

    sess._send(_frame(0))  # triggers the drain failure / teardown
    # Wait on _closed (set by the done-callback), which is strictly later than
    # wt.done(): the callback is scheduled after the task finishes.
    await _wait_for(lambda: sess._closed.is_set())
    assert wt.done()

    # The writer task is dead and nothing drains the queue. Push 10k frames.
    for i in range(1, 10_001):
        sess._send(_frame(i & 0xFFFF))

    # CURRENT (buggy) behaviour would be qsize ~= 10000 with _closed unset.
    # POST-FIX: the queue is hard-capped and the session stays torn down.
    assert sess._write_queue.qsize() <= WRITE_QUEUE_MAXSIZE
    assert sess._closed.is_set()
    assert sess._teardown_requested.is_set()

    await _cancel(wt)


async def test_send_queue_full_triggers_teardown(caplog: pytest.LogCaptureFixture) -> None:
    """The bounded-queue QueueFull path tears the session down (not drops).

    With a writer whose drain() never returns, the queue can only fill. Once
    ``_send`` hits ``QueueFull`` it must log and call ``request_teardown``
    rather than block the caller or silently drop the frame.
    """
    writer = _StalledWriter()
    sess, server, wt = _make_faulty_session(writer)

    with caplog.at_level(logging.WARNING, logger="spcedp"):
        # Push enough frames to overflow the bounded queue. The writer loop
        # pops at most one (then stalls forever in drain), so the queue fills
        # to WRITE_QUEUE_MAXSIZE and the next _send hits QueueFull.
        for i in range(WRITE_QUEUE_MAXSIZE + 50):
            sess._send(_frame(i & 0xFFFF))
            if sess._closed.is_set():
                break

    # QueueFull -> request_teardown(): both events set, queue at the cap.
    assert sess._closed.is_set()
    assert sess._teardown_requested.is_set()
    assert sess._write_queue.qsize() <= WRITE_QUEUE_MAXSIZE

    messages = [r.getMessage() for r in caplog.records]
    assert any("outbound queue full" in m for m in messages), messages
    # _send never blocks the caller: control returned for every call above.

    await _cancel(wt)


async def test_write_queue_warn_rising_edge(caplog: pytest.LogCaptureFixture) -> None:
    """The rising-edge WRITE_QUEUE_WARN fires once when the queue crosses warn.

    With a stalled writer the queue backs up; stepping over (not landing on)
    the warn threshold must still emit exactly one warning, and not re-fire
    while it stays above the threshold (it re-arms only after draining below).
    """
    writer = _StalledWriter()
    sess, server, wt = _make_faulty_session(writer)

    with caplog.at_level(logging.WARNING, logger="spcedp"):
        # Step in 3s so we jump over the exact WRITE_QUEUE_WARN boundary, then
        # stop short of the hard cap so teardown does not fire here.
        i = 0
        while sess._write_queue.qsize() < WRITE_QUEUE_WARN + 30:
            sess._send(_frame(i & 0xFFFF))
            sess._send(_frame((i + 1) & 0xFFFF))
            sess._send(_frame((i + 2) & 0xFFFF))
            i += 3

        warn_records = [r for r in caplog.records if "outbound queue at" in r.getMessage()]

    # Rising edge: fired exactly once despite many sends above the threshold.
    assert len(warn_records) == 1, [r.getMessage() for r in warn_records]
    assert sess._write_warned is True
    # Did not reach the hard cap, so no teardown from this path.
    assert not sess._closed.is_set()
    assert sess._write_queue.qsize() < WRITE_QUEUE_MAXSIZE
    assert WRITE_QUEUE_WARN < WRITE_QUEUE_MAXSIZE

    await _cancel(wt)


async def test_read_loop_stops_without_idle_timeout() -> None:
    """request_teardown stops the read loop even when idle_timeout is None.

    M0.2 acceptance: the default 120s idle timeout otherwise masks a runaway, so
    prove teardown does not depend on it. ``_read_chunk`` races the socket read
    against ``_teardown_requested``; with ``idle_timeout=None`` the wait is
    unbounded, yet a teardown request must still return None promptly (the read
    loop then stops) rather than blocking forever on a silent socket.
    """
    server = PanelServer(receiver_id=RECEIVER_ID, idle_timeout=None)
    reader = asyncio.StreamReader()  # no data, no EOF fed -> read() blocks forever
    sess = Session(
        panel_id=PANEL_ID,
        receiver_id=RECEIVER_ID,
        reader=reader,
        writer=FaultyWriter(OSError()),  # type: ignore[arg-type]  # unused by _read_chunk
    )

    chunk_task = asyncio.ensure_future(server._read_chunk(reader, sess))
    await asyncio.sleep(0)  # let it block on the read/teardown race
    # With idle_timeout=None there is no timer to fall back on: the read is
    # genuinely blocked, so the chunk task must still be pending here.
    assert not chunk_task.done()

    sess.request_teardown()
    chunk = await asyncio.wait_for(chunk_task, timeout=1.0)

    assert chunk is None
    assert sess._teardown_requested.is_set()
