"""Event delivery survives cancellation without replaying consumed events."""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from test_session import FakeWriter, _cancel, _make_session

from spcedp.client import PanelServer, Session
from spcedp.events import SiaEvent

pytestmark = pytest.mark.asyncio


def _event(spc_id: int = 1) -> SiaEvent:
    return SiaEvent(
        spc_id=spc_id,
        timestamp=None,
        timestamp_raw="08521203062026",
        sia_code="BA",
        address="1",
        description="Burglar",
        verification_id="0",
    )


async def test_cancel_in_wait_window_does_not_lose_event() -> None:
    """Cancel __anext__ while the inner get() has completed but the event has
    not yet been yielded; the event must be re-queued and delivered next."""
    sess, writer, server, wt = _make_session()
    assert isinstance(writer, FakeWriter)  # reuse loopback-free helpers
    assert isinstance(sess, Session) and isinstance(server, PanelServer)

    ev = _event()
    sess.emit_event(ev)
    assert sess._events.qsize() == 1

    agen = sess.events()
    anext_task = asyncio.create_task(agen.__anext__())

    # Step the loop a few passes so events() can create its inner get_task and
    # let _events.get() complete (consuming the queued event) while the outer
    # __anext__ task is still parked inside asyncio.wait().
    for _ in range(5):
        await asyncio.sleep(0)
        if sess._events.empty():
            break
    # The event has been dequeued by the inner get_task but not yet yielded:
    # this is exactly the get-completed-but-not-yielded window.
    assert sess._events.empty()
    assert not anext_task.done()

    # Cancel inside that window. The except-CancelledError path must put the
    # consumed event back so it is not lost.
    anext_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await anext_task

    # The event was re-queued, not dropped.
    assert sess._events.qsize() == 1

    # A fresh iteration over the same stream still delivers the event.
    agen2 = sess.events()
    got = await asyncio.wait_for(agen2.__anext__(), 1.0)
    assert got is ev
    await agen2.aclose()
    await _cancel(wt)


async def test_closing_after_delivery_does_not_replay_event() -> None:
    sess, writer, server, wt = _make_session()
    ev = _event()
    sess.emit_event(ev)
    agen = sess.events()
    assert await anext(agen) is ev
    await agen.aclose()
    assert sess._events.empty()
    await _cancel(wt)


async def test_repeated_cancel_never_drops_the_event() -> None:
    """Repeatedly start-and-cancel __anext__ in the wait window; the single
    event must survive every cancellation and finally be delivered exactly
    once."""
    sess, writer, server, wt = _make_session()
    ev = _event()
    sess.emit_event(ev)

    for _ in range(10):
        agen = sess.events()
        anext_task = asyncio.create_task(agen.__anext__())
        for _ in range(5):
            await asyncio.sleep(0)
            if sess._events.empty():
                break
        # Either the get completed (event consumed) or it is still pending; in
        # both cases the event must not be lost across the cancel.
        anext_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await anext_task
        await agen.aclose()
        # After teardown of this iteration the event is back in the queue.
        assert sess._events.qsize() == 1, "event lost across cancel iteration"

    # And it is still deliverable, exactly once.
    agen = sess.events()
    got = await asyncio.wait_for(agen.__anext__(), 1.0)
    assert got is ev
    assert sess._events.empty()
    await agen.aclose()
    await _cancel(wt)


async def test_cancel_does_not_consume_a_second_event() -> None:
    """With two events queued, cancelling in the wait window after one was
    dequeued must restore that one (front of queue) so neither is lost and the
    second is not skipped."""
    sess, writer, server, wt = _make_session()
    first, second = _event(1), _event(2)
    sess.emit_event(first)
    sess.emit_event(second)
    assert sess._events.qsize() == 2

    agen = sess.events()
    anext_task = asyncio.create_task(agen.__anext__())
    for _ in range(5):
        await asyncio.sleep(0)
        # One event consumed by the inner get_task (qsize drops to 1).
        if sess._events.qsize() <= 1:
            break
    anext_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await anext_task

    # Both events are still present (the consumed one was re-queued).
    assert sess._events.qsize() == 2

    # Drain in order: the first event must still come out first.
    agen2 = sess.events()
    got1 = await asyncio.wait_for(agen2.__anext__(), 1.0)
    got2 = await asyncio.wait_for(agen2.__anext__(), 1.0)
    assert (got1.spc_id, got2.spc_id) == (1, 2)
    await agen2.aclose()
    await _cancel(wt)
