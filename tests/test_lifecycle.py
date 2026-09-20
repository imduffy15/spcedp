"""Connection ownership and cancellation regressions."""

import asyncio
from unittest.mock import MagicMock

import pytest

from spcedp import PanelServer, Session, SpcConnectionLost
from spcedp.commands import BinaryOp
from spcedp.wire import Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio


async def test_server_exit_closes_connected_and_pre_handshake_clients() -> None:
    entered = asyncio.Event()
    exited = asyncio.Event()

    async def connected(session):
        entered.set()
        try:
            await asyncio.Future()
        finally:
            exited.set()

    server = PanelServer(receiver_id=1, bind="127.0.0.1", port=0, on_session=connected)
    async with asyncio.timeout(2):
        async with server:
            port = server._server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            idle_reader, idle_writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(
                Frame(
                    src_id=2,
                    dst_id=1,
                    sequence=1,
                    major=MajorCode.SESSION,
                    minor=MinorCode.HELLO,
                    payload=b"12345678",
                ).encode()
            )
            await writer.drain()
            await entered.wait()
        assert exited.is_set()
        assert not server._handlers
        await reader.read()  # buffered HELLO_ACK followed by EOF
        assert await idle_reader.read() == b""
        writer.close()
        idle_writer.close()
        await asyncio.gather(writer.wait_closed(), idle_writer.wait_closed())


async def test_disconnected_session_fails_reads_controls_and_readiness_promptly() -> None:
    session = Session(1, 2, asyncio.StreamReader(), MagicMock())
    ready = asyncio.create_task(session.wait_ready())
    await asyncio.sleep(0)
    session.request_teardown()
    async with asyncio.timeout(1):
        for operation in (
            ready,
            session.xml_command("info"),
            session.binary_command(BinaryOp.AREA_SET, 1),
        ):
            with pytest.raises(SpcConnectionLost):
                await operation
    assert session._write_queue.empty()
    assert not session._pending_xml
    assert not session._pending_bin


async def test_cancelled_socket_read_leaves_no_reader_task() -> None:
    reader = asyncio.StreamReader()
    session = Session(1, 2, reader, MagicMock())
    server = PanelServer(receiver_id=2)
    task = asyncio.create_task(server._read_chunk(reader, session))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # A leaked read would make this fail with "another coroutine is already waiting".
    reader.feed_data(b"next")
    assert await reader.read(4) == b"next"
