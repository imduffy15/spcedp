"""Reproduce SPC4300 command/event sequence collisions and serialize transactions."""

import asyncio

import pytest
from test_session import INFO_REPLY, _cancel, _make_session, _reply, _wait_for

from spcedp.client import COMMAND_QUIET_TIME
from spcedp.commands import BinaryOp
from spcedp.errors import SpcConnectionLost, SpcTimeout
from spcedp.wire import Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio


def event(sequence: int) -> Frame:
    return _reply(
        sequence,
        b"E2[#1000|12331920092026|NL|1|Home||0]",
        major=MajorCode.EVENT,
        minor=MinorCode.EVENT_PUSH,
    )


async def test_event_burst_is_acked_before_allocating_command_sequence() -> None:
    session, writer, server, writer_task = _make_session()
    query = None
    try:
        server._dispatch(session, event(40))
        query = asyncio.create_task(session.xml_command("area_status"))
        # The panel queues its next event after receiving the first ACK.
        await asyncio.sleep(COMMAND_QUIET_TIME / 2)
        server._dispatch(session, event(41))
        await _wait_for(lambda: len(writer.written) == 3)
        frames = [Frame.decode(data) for data in writer.written]
        assert [(f.major, f.minor, f.sequence) for f in frames] == [
            (MajorCode.EVENT, MinorCode.EVENT_ACK, 40),
            (MajorCode.EVENT, MinorCode.EVENT_ACK, 41),
            (MajorCode.XML_CMD, MinorCode.REQUEST, 42),
        ]
        server._dispatch(
            session, _reply(42, INFO_REPLY, major=MajorCode.XML_CMD, minor=MinorCode.REPLY)
        )
        await query
    finally:
        await _cancel(writer_task, *([query] if query else []))


async def test_fragmented_xml_finishes_before_next_control_command() -> None:
    session, writer, server, writer_task = _make_session()
    query = asyncio.create_task(session.xml_command("zone_status"))
    control = None
    try:
        await _wait_for(lambda: len(writer.written) == 1)
        first = Frame.decode(writer.written[0])
        control = asyncio.create_task(session.binary_command(BinaryOp.AREA_UNSET, 1))
        server._dispatch(
            session,
            _reply(
                first.sequence,
                b"\x01<COMMAND_REPLY>",
                major=MajorCode.XML_CMD,
                minor=MinorCode.REPLY,
            ),
        )
        await _wait_for(lambda: len(writer.written) == 2)
        continuation = Frame.decode(writer.written[1])
        assert continuation.major == MajorCode.XML_CMD
        assert continuation.payload.startswith(b"\x02")
        server._dispatch(
            session,
            _reply(
                continuation.sequence,
                b"\x02</COMMAND_REPLY>",
                major=MajorCode.XML_CMD,
                minor=MinorCode.REPLY,
            ),
        )
        assert await query == {}
        await _wait_for(lambda: len(writer.written) == 3)
        command = Frame.decode(writer.written[2])
        assert command.major == MajorCode.BINARY_CMD
        server._dispatch(
            session,
            _reply(
                command.sequence, b"\xf0", major=MajorCode.BINARY_CMD, minor=MinorCode.BINARY_REPLY
            ),
        )
        await control
    finally:
        await _cancel(writer_task, query, *([control] if control else []))


async def test_disconnect_during_quiet_period_never_sends_command() -> None:
    session, writer, server, writer_task = _make_session()
    server._dispatch(session, event(40))
    query = asyncio.create_task(session.xml_command("area_status"))
    try:
        await _wait_for(lambda: len(writer.written) == 1)
        session.request_teardown()
        with pytest.raises(SpcConnectionLost):
            await query
        assert len(writer.written) == 1  # Only the event ACK.
    finally:
        query.cancel()
        await asyncio.gather(query, return_exceptions=True)
        await _cancel(writer_task)


async def test_busy_panel_respects_command_timeout_without_disconnect() -> None:
    session, writer, server, writer_task = _make_session()
    server._dispatch(session, event(40))
    try:
        with pytest.raises(SpcTimeout, match="idle"):
            await session.xml_command("area_status", timeout=COMMAND_QUIET_TIME / 10)
        assert not session._closed.is_set()
        assert len(writer.written) == 1
    finally:
        await _cancel(writer_task)
