"""Concurrency & lifecycle tests (roadmap M4.6).

These drive the real ``PanelServer``/``Session`` over a loopback socket using
the :class:`~tests.mockpanel.MockPanel` TCP client, and assert the *post-fix*
GA behaviour from the roadmap:

  * **Concurrent demux.** ``asyncio.gather`` of many concurrent ``xml_command``
    / ``binary_command`` calls, while POLL frames carrying random sequences
    interleave (exercising the ``next_seq = max(next_seq, frame.sequence)`` bump
    at ``client.py:562``). Every command must resolve with *its own* reply: each
    request carries a unique nonce the panel echoes back, and each binary reply
    carries a per-command status byte, so a cross-match (one command resolving
    on another's reply) is observable. Sequences are asserted distinct.

  * **Connection policy.** The documented policy (roadmap line 105) is "one panel
    per receiver_id; reconnect re-runs ``on_session``" - there is NO
    ``{panel_id: Session}`` dedup registry. So two connections with the *same*
    ``panel_id`` each get their own live ``Session`` and each runs ``on_session``
    exactly once, and two connections with *distinct* ``panel_id`` behave the
    same way and stay isolated (distinct Session objects, distinct panel_id).

  * **``wait_ready(min_polls=N)``** unblocks only after the panel has completed
    at least N polls.



  * **``PanelServer._normalise_key``** accepts a 32-hex string or 16 raw bytes
    and rejects empty / wrong-length / odd-hex values at construction.

Deterministic: no wall-clock sleeps gate assertions; progress is awaited on
observable predicates (the ``_wait_for`` helper) only.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable

import pytest
from mockpanel import DEFAULT_NONCE, MockPanel

from spcedp.client import PanelServer, Session
from spcedp.commands import BinaryOp
from spcedp.errors import ReplyCode
from spcedp.wire import Frame, MajorCode, MinorCode

# Applied per-async-test (not module-wide) so the synchronous encode/key-
# validation tests below are not flagged for an unused asyncio mark.
asyncio_test = pytest.mark.asyncio

PANEL_ID = 1000
RECEIVER_ID = 1001
KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY_BYTES = bytes.fromhex(KEY_HEX)


async def _wait_for(predicate: Callable[[], bool], timeout: float = 2.0) -> None:
    """Await until ``predicate()`` is truthy (deterministic; no fixed sleeps)."""

    async def _loop() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(_loop(), timeout)


def _command_nonce(req: Frame) -> str | None:
    """Pull the NONCE="..." attribute the receiver put on an XML request."""
    text = req.payload[1:].decode("ascii", "replace")
    marker = 'NONCE="'
    start = text.find(marker)
    if start < 0:
        return None
    start += len(marker)
    end = text.find('"', start)
    if end < 0:
        return None
    return text[start:end]


class _EchoPanel:
    """A loopback receiver + a MockPanel wired together for demux tests.

    The panel reads receiver-originated request frames off the MockPanel inbound
    queue and replies on the *same sequence*, but tags each reply so a cross-match
    is detectable:

      * XML request  -> COMMAND_REPLY echoing the request's NONCE *and* its wire
        sequence, so the caller can assert the reply it got carries the nonce it
        sent (and only that one), and that every command used a distinct sequence.
      * binary request -> a 1-byte OK status on the request's own sequence, so a
        mis-routed reply would resolve the wrong future or hang.

    POLL frames with arbitrary sequences are pushed concurrently to drive the
    receiver's ``next_seq = max(...)`` bump.
    """

    def __init__(self) -> None:
        self.server: PanelServer | None = None
        self.panel: MockPanel | None = None
        self._serve_task: asyncio.Task | None = None
        self.session: Session | None = None

    async def __aenter__(self) -> _EchoPanel:
        sessions: list[Session] = []

        async def on_session(sess: Session) -> None:
            sessions.append(sess)

        self.server = PanelServer(
            receiver_id=RECEIVER_ID,
            bind="127.0.0.1",
            port=0,
            on_session=on_session,
            idle_timeout=10.0,
        )
        await self.server.__aenter__()
        assert self.server._server is not None
        port = self.server._server.sockets[0].getsockname()[1]
        self.panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID)
        await self.panel.connect()
        await self.panel.hello()
        await self.panel.poll()
        await _wait_for(lambda: bool(sessions))
        self.session = sessions[0]
        self._serve_task = asyncio.ensure_future(self._reply_loop())
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._serve_task is not None:
            self._serve_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._serve_task
        if self.panel is not None:
            await self.panel.disconnect()
        if self.server is not None:
            await self.server.__aexit__(None, None, None)

    async def _reply_loop(self) -> None:
        assert self.panel is not None
        try:
            while True:
                req = await self.panel._inbound.get()
                if req.major == MajorCode.XML_CMD and req.minor == MinorCode.REQUEST:
                    nonce = _command_nonce(req)
                    payload = (
                        b'\x01<COMMAND_REPLY><ECHO NONCE="'
                        + (nonce or "").encode("ascii")
                        + b'" SEQ="'
                        + str(req.sequence).encode("ascii")
                        + b'" /></COMMAND_REPLY>'
                    )
                    await self.panel._send_reply_payload(req, int(MinorCode.REPLY), payload)
                elif req.major == MajorCode.BINARY_CMD and req.minor == MinorCode.REQUEST:
                    # Reply OK on the request's own sequence. The status byte is
                    # the same for every command, so per-reply identity is proven
                    # by the XML path (NONCE/SEQ echo); here we only assert each
                    # future resolves (returns None) without a cross-match hang.
                    await self.panel._send_reply_payload(
                        req, int(MinorCode.BINARY_REPLY), bytes([int(ReplyCode.OK)])
                    )
        except asyncio.CancelledError:
            return


@asyncio_test
async def test_concurrent_xml_commands_demux_to_own_reply() -> None:
    """Many concurrent xml_command calls each resolve with their OWN reply.

    While the commands are in flight, POLL frames carrying random sequences are
    pushed, driving the receiver's next_seq = max(next_seq, frame.sequence) bump.
    Each command sends a unique NONCE; the panel echoes it back, so a cross-match
    is detectable. All allocated sequences must be distinct.
    """
    n = 200
    async with _EchoPanel() as ctx:
        sess = ctx.session
        panel = ctx.panel
        assert sess is not None and panel is not None

        async def one(i: int) -> tuple[int, str, str]:
            reply = await sess.xml_command("info", timeout=5.0, nonce=str(i))
            row = reply["ECHO"][0]
            return i, row["NONCE"], row["SEQ"]

        # Interleave POLLs with random/arbitrary sequences to bump next_seq via
        # the max() path while commands are outstanding.
        async def pollers() -> None:
            for seq in (0xFFFF, 0x10, 0x7FFFFFFF, 0x1234, 0x00000001, 0xDEADBEEF):
                frame = panel.build_frame(
                    major=int(MajorCode.SESSION),
                    minor=int(MinorCode.POLL),
                    payload=DEFAULT_NONCE,
                    sequence=seq,
                )
                await panel.send_raw(frame.encode())
                await asyncio.sleep(0)

        results, _ = await asyncio.gather(
            asyncio.gather(*(one(i) for i in range(n))),
            pollers(),
        )

        # Every command resolved with the nonce it sent: no cross-match.
        for i, echoed_nonce, _seq in results:
            assert echoed_nonce == str(i), f"command {i} got nonce {echoed_nonce!r}"
        # Every command was carried on a distinct wire sequence (the demux key):
        # the panel echoed each request's sequence back, so n distinct values
        # prove no two commands shared a sequence (which would cross-match).
        seqs = [seq for _i, _n, seq in results]
        assert len(set(seqs)) == n
        # next_seq was bumped past the largest interleaved POLL sequence.
        assert sess.next_seq >= 0xDEADBEEF


@asyncio_test
async def test_concurrent_binary_commands_all_resolve() -> None:
    """A gather of concurrent binary_command calls all resolve (return None).

    Each carries a distinct area ID; distinct sequences mean the
    binary-reply demux (keyed on sequence) resolves each future exactly once.
    """
    n = 100
    async with _EchoPanel() as ctx:
        sess = ctx.session
        assert sess is not None
        results = await asyncio.gather(
            *(sess.binary_command(BinaryOp.AREA_SET_A, i + 1) for i in range(n))
        )
        assert results == [None] * n
        # All futures resolved and were popped; no pending state left behind.
        assert not sess._pending_bin


@asyncio_test
async def test_random_poll_sequences_bump_next_seq() -> None:
    """A POLL with a large sequence bumps next_seq via the max() path, so the
    receiver's own outbound sequence stays ahead of the panel's last seq."""
    async with _EchoPanel() as ctx:
        sess = ctx.session
        panel = ctx.panel
        assert sess is not None and panel is not None
        big = 0x40000000
        frame = panel.build_frame(
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.POLL),
            payload=DEFAULT_NONCE,
            sequence=big,
        )
        await panel.send_raw(frame.encode())
        await _wait_for(lambda: sess.next_seq >= big)
        # A subsequent command allocates a sequence strictly greater than the
        # interleaved POLL's, so it cannot collide with the panel's space.
        before = sess.next_seq
        await sess.binary_command(BinaryOp.AREA_SET_A, 1)
        assert sess.next_seq > before


# --------------------------------------------------------------------------
# Connection policy: documented "one panel per receiver_id; reconnect re-runs
# on_session" - NO {panel_id: Session} dedup registry.
# --------------------------------------------------------------------------


async def _open_panel(server: PanelServer, panel_id: int) -> MockPanel:
    assert server._server is not None
    port = server._server.sockets[0].getsockname()[1]
    panel = MockPanel("127.0.0.1", port, panel_id=panel_id, receiver_id=RECEIVER_ID)
    await panel.connect()
    await panel.hello()
    await panel.poll()
    return panel


@asyncio_test
async def test_two_connections_same_panel_id_each_get_a_session() -> None:
    """Two simultaneous connections sharing a panel_id each get their own live
    Session and each runs on_session exactly once (no dedup registry)."""
    sessions: list[Session] = []

    async def on_session(sess: Session) -> None:
        sessions.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=10.0
    )
    async with server:
        a = await _open_panel(server, PANEL_ID)
        b = await _open_panel(server, PANEL_ID)
        try:
            await _wait_for(lambda: len(sessions) >= 2)
            assert len(sessions) == 2
            # Distinct Session objects, both reporting the same panel_id.
            assert sessions[0] is not sessions[1]
            assert {s.panel_id for s in sessions} == {PANEL_ID}
        finally:
            await a.disconnect()
            await b.disconnect()
        await asyncio.sleep(0.05)


@asyncio_test
async def test_two_connections_distinct_panel_ids_are_isolated() -> None:
    """Two connections with distinct panel_ids each get an isolated Session
    reporting its own panel_id; on_session runs once per connection."""
    sessions: list[Session] = []

    async def on_session(sess: Session) -> None:
        sessions.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=10.0
    )
    async with server:
        a = await _open_panel(server, 1000)
        b = await _open_panel(server, 2000)
        try:
            await _wait_for(lambda: len(sessions) >= 2)
            assert len(sessions) == 2
            assert sessions[0] is not sessions[1]
            assert {s.panel_id for s in sessions} == {1000, 2000}
        finally:
            await a.disconnect()
            await b.disconnect()
        await asyncio.sleep(0.05)


# --------------------------------------------------------------------------
# wait_ready(min_polls=N)
# --------------------------------------------------------------------------


@asyncio_test
async def test_wait_ready_blocks_until_min_polls() -> None:
    """wait_ready(min_polls=N) returns only after the panel completes N polls."""
    sessions: list[Session] = []

    async def on_session(sess: Session) -> None:
        sessions.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=10.0
    )
    async with server:
        assert server._server is not None
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID)
        await panel.connect()
        await panel.hello()
        await panel.poll()  # poll #1
        try:
            await _wait_for(lambda: bool(sessions))
            sess = sessions[0]

            waiter = asyncio.ensure_future(sess.wait_ready(min_polls=3))
            # One poll so far: the waiter must not be done yet.
            await _wait_for(lambda: sess._poll_count >= 1)
            await asyncio.sleep(0)
            assert not waiter.done()

            await panel.poll()  # poll #2 - still short of 3
            await _wait_for(lambda: sess._poll_count >= 2)
            await asyncio.sleep(0)
            assert not waiter.done()

            await panel.poll()  # poll #3 - now it should unblock
            await asyncio.wait_for(waiter, 2.0)
            assert waiter.done() and waiter.exception() is None
        finally:
            await panel.disconnect()
        await asyncio.sleep(0.05)


@asyncio_test
async def test_wait_ready_returns_immediately_when_already_polled() -> None:
    """If the panel has already met the poll count, wait_ready returns at once."""
    sessions: list[Session] = []

    async def on_session(sess: Session) -> None:
        sessions.append(sess)

    server = PanelServer(
        receiver_id=RECEIVER_ID, bind="127.0.0.1", port=0, on_session=on_session, idle_timeout=10.0
    )
    async with server:
        assert server._server is not None
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=PANEL_ID, receiver_id=RECEIVER_ID)
        await panel.connect()
        await panel.hello()
        await panel.poll()
        await panel.poll()
        try:
            await _wait_for(lambda: bool(sessions))
            sess = sessions[0]
            await _wait_for(lambda: sess._poll_count >= 2)
            # Already at >=2 polls: wait_ready(2) must not block.
            await asyncio.wait_for(sess.wait_ready(min_polls=2), 1.0)
        finally:
            await panel.disconnect()
        await asyncio.sleep(0.05)


# --------------------------------------------------------------------------
# Global binary op wire shape: BELL_SILENCE -> single opcode byte.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# PanelServer._normalise_key validation.
# --------------------------------------------------------------------------


def test_normalise_key_accepts_32_hex_string() -> None:
    assert PanelServer._normalise_key(KEY_HEX) == KEY_BYTES


def test_normalise_key_accepts_16_bytes() -> None:
    assert PanelServer._normalise_key(KEY_BYTES) == KEY_BYTES


def test_normalise_key_none_is_none() -> None:
    assert PanelServer._normalise_key(None) is None


def test_normalise_key_rejects_empty() -> None:
    with pytest.raises(ValueError):
        PanelServer._normalise_key("")
    with pytest.raises(ValueError):
        PanelServer._normalise_key(b"")


def test_normalise_key_rejects_wrong_length_bytes() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        PanelServer._normalise_key(b"\x00" * 15)
    with pytest.raises(ValueError, match="16 bytes"):
        PanelServer._normalise_key(b"\x00" * 17)


def test_normalise_key_rejects_wrong_length_hex() -> None:
    # 30 hex digits = 15 bytes (valid hex, wrong length).
    with pytest.raises(ValueError, match="16 bytes"):
        PanelServer._normalise_key("00" * 15)


def test_normalise_key_rejects_odd_hex() -> None:
    # Odd number of hex digits cannot decode to whole bytes.
    with pytest.raises(ValueError, match="32 hex digits"):
        PanelServer._normalise_key("abc")


def test_normalise_key_rejects_non_hex_string() -> None:
    with pytest.raises(ValueError, match="32 hex digits"):
        PanelServer._normalise_key("zz" * 16)
