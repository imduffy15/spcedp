"""Error-taxonomy guard (campaign H5 / M3.2).

Every public Session method must raise an ``SpcError`` subclass for each
failure mode - never let a bare ``asyncio.TimeoutError``, ``ConnectionResetError``
or ``ValueError`` escape. This pins the post-fix public hierarchy:

  * non-OK reply code         -> PanelRejected (.code)
  * no reply within timeout   -> SpcTimeout
  * mid-command disconnect    -> SpcConnectionLost
  * runaway fragmentation /   -> SpcProtocolError
    empty reply

The tests drive a real ``Session`` over a FakeWriter (reusing the helpers from
``test_session.py``) for the reply-shaped cases, and over a loopback
``PanelServer`` + ``MockPanel`` (``mockpanel.py``) for the disconnect case, so
the typed errors are asserted on the genuine code paths.
"""

from __future__ import annotations

import asyncio

import pytest
from mockpanel import MockPanel
from test_session import (
    PANEL_ID,
    RECEIVER_ID,
    FakeWriter,
    _cancel,
    _make_session,
    _reply,
    _wait_for,
)

from spcedp.client import MAX_XML_FRAGMENTS, PanelServer, Session
from spcedp.commands import BinaryOp
from spcedp.errors import (
    PanelRejected,
    SpcConnectionLost,
    SpcError,
    SpcProtocolError,
    SpcTimeout,
)
from spcedp.wire import Frame, MajorCode, MinorCode

pytestmark = pytest.mark.asyncio


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


async def _drive_binary_reply(
    sess: Session,
    writer: FakeWriter,
    server: PanelServer,
    *,
    op: BinaryOp,
    reply_payload: bytes,
    timeout: float = 1.0,
) -> asyncio.Task[None]:
    """Start a binary_command, wait for its request, then inject ``reply_payload``."""
    cmd = asyncio.create_task(sess.binary_command(op, 1, timeout=timeout))
    await _wait_for(lambda: len(writer.written) >= 1)
    req = Frame.decode(writer.written[-1])
    server._dispatch(
        sess,
        _reply(
            req.sequence,
            reply_payload,
            major=MajorCode.BINARY_CMD,
            minor=MinorCode.BINARY_REPLY,
        ),
    )
    return cmd


# --------------------------------------------------------------------------- #
# Non-OK reply code -> PanelRejected (with .code)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("code", [0xF2, 0xF3, 0xF4, 0xF5, 0xFB, 0xFC, 0xFD, 0xFF])
async def test_binary_non_ok_raises_panel_rejected(code: int) -> None:
    sess, writer, server, wt = _make_session()
    cmd = await _drive_binary_reply(
        sess, writer, server, op=BinaryOp.AREA_SET, reply_payload=bytes([code])
    )
    with pytest.raises(PanelRejected) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert isinstance(exc.value, SpcError)
    assert exc.value.code == code
    await _cancel(wt)


# --------------------------------------------------------------------------- #
# No reply within timeout -> SpcTimeout
# --------------------------------------------------------------------------- #


async def test_xml_command_timeout_raises_spctimeout() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.xml_command("info", timeout=0.05))
    with pytest.raises(SpcTimeout) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert isinstance(exc.value, SpcError)
    # No bare asyncio.TimeoutError leaked through.
    assert not isinstance(exc.value, asyncio.TimeoutError)
    await _cancel(wt)


async def test_binary_command_timeout_raises_spctimeout() -> None:
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1, timeout=0.05))
    with pytest.raises(SpcTimeout) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert isinstance(exc.value, SpcError)
    assert not isinstance(exc.value, asyncio.TimeoutError)
    await _cancel(wt)


# --------------------------------------------------------------------------- #
# Mid-command disconnect -> SpcConnectionLost
# --------------------------------------------------------------------------- #


async def test_disconnect_mid_command_raises_spcconnectionlost_in_process() -> None:
    """fail_pending(SpcConnectionLost) is what teardown delivers to in-flight futures."""
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1, timeout=10))
    await _wait_for(lambda: bool(sess._pending_bin))
    sess.fail_pending(SpcConnectionLost("panel disconnected"))
    with pytest.raises(SpcConnectionLost) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert isinstance(exc.value, SpcError)
    # No raw ConnectionResetError leaks to the caller.
    assert not isinstance(exc.value, ConnectionResetError)
    await _cancel(wt)


async def test_disconnect_mid_command_raises_spcconnectionlost_end_to_end() -> None:
    """A real loopback panel that drops the socket mid-command fails the future
    with SpcConnectionLost (not the panel's own command timeout, not a raw
    ConnectionResetError)."""
    captured: list[Session] = []

    async def on_session(sess: Session) -> None:
        captured.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=5.0
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID)
        await panel.connect()
        await panel.hello()
        await _wait_for(lambda: bool(captured))
        sess = captured[0]

        # An in-flight command with a long timeout: only the disconnect can
        # resolve it, and it must resolve as SpcConnectionLost.
        cmd = asyncio.create_task(sess.binary_command(BinaryOp.AREA_SET, 1, timeout=30))
        await _wait_for(lambda: bool(sess._pending_bin))

        await panel.disconnect(abortive=True)
        with pytest.raises(SpcConnectionLost) as exc:
            await asyncio.wait_for(cmd, 2.0)
        assert isinstance(exc.value, SpcError)
        assert not isinstance(exc.value, ConnectionResetError)


async def test_xml_command_disconnect_mid_command_raises_spcconnectionlost() -> None:
    """The XML path surfaces a mid-command disconnect as SpcConnectionLost too."""
    captured: list[Session] = []

    async def on_session(sess: Session) -> None:
        captured.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=5.0
    )
    async with server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID)
        await panel.connect()
        await panel.hello()
        await _wait_for(lambda: bool(captured))
        sess = captured[0]

        cmd = asyncio.create_task(sess.xml_command("info", timeout=30))
        await _wait_for(lambda: bool(sess._pending_xml))

        await panel.disconnect(abortive=True)
        with pytest.raises(SpcConnectionLost) as exc:
            await asyncio.wait_for(cmd, 2.0)
        assert isinstance(exc.value, SpcError)
        assert not isinstance(exc.value, ConnectionResetError)


# --------------------------------------------------------------------------- #
# Protocol violations -> SpcProtocolError
# --------------------------------------------------------------------------- #


async def test_empty_binary_reply_raises_spcprotocolerror() -> None:
    sess, writer, server, wt = _make_session()
    cmd = await _drive_binary_reply(sess, writer, server, op=BinaryOp.AREA_SET, reply_payload=b"")
    with pytest.raises(SpcProtocolError) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert isinstance(exc.value, SpcError)
    await _cancel(wt)


async def test_runaway_fragmentation_raises_spcprotocolerror() -> None:
    """A reply that never closes </COMMAND_REPLY> raises SpcProtocolError after
    MAX_XML_FRAGMENTS, not a bare ValueError and not an infinite loop."""
    sess, writer, server, wt = _make_session()
    cmd = asyncio.create_task(sess.xml_command("zone_status", timeout=1.0))
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
    with pytest.raises(SpcProtocolError) as exc:
        await asyncio.wait_for(cmd, 2.0)
    assert isinstance(exc.value, SpcError)
    assert not isinstance(exc.value, ValueError)
    await _cancel(wt)


# --------------------------------------------------------------------------- #
# Negative guard: no foreign exception type escapes any public method.
# --------------------------------------------------------------------------- #

# (major, minor) reply shape + the failure-mode payload sentinel, swept across
# every public command method so a regression that lets a builtin/asyncio
# exception leak is caught here regardless of which path introduced it.
_FOREIGN_TYPES = (asyncio.TimeoutError, ConnectionResetError, ValueError)


@pytest.mark.parametrize("scenario", ["timeout", "runaway"])
async def test_no_foreign_exception_from_xml_command(scenario: str) -> None:
    """Sweep XML failure modes; every one must be an SpcError, never a foreign type."""
    sess, writer, server, wt = _make_session()
    try:
        if scenario == "timeout":
            cmd = asyncio.create_task(sess.xml_command("info", timeout=0.05))
        else:  # runaway
            cmd = asyncio.create_task(sess.xml_command("zone_status", timeout=1.0))
            for i in range(MAX_XML_FRAGMENTS):
                await _wait_for(lambda i=i: len(writer.written) > i)
                req = Frame.decode(writer.written[i])
                server._dispatch(
                    sess,
                    _reply(
                        req.sequence,
                        b"\x02<COMMAND_REPLY>open",
                        major=MajorCode.XML_CMD,
                        minor=MinorCode.REPLY,
                    ),
                )
        with pytest.raises(SpcError) as exc:
            await asyncio.wait_for(cmd, 2.0)
        assert not isinstance(exc.value, _FOREIGN_TYPES), scenario
    finally:
        await _cancel(wt)


@pytest.mark.parametrize("payload", [b"", b"\xf2", b"\xfc"])
async def test_no_foreign_exception_from_binary_command(payload: bytes) -> None:
    sess, writer, server, wt = _make_session()
    cmd = await _drive_binary_reply(
        sess, writer, server, op=BinaryOp.AREA_SET, reply_payload=payload
    )
    with pytest.raises(SpcError) as exc:
        await asyncio.wait_for(cmd, 1.0)
    assert not isinstance(exc.value, _FOREIGN_TYPES)
    await _cancel(wt)
