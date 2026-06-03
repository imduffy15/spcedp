"""Programmable adversarial mock SPC panel (campaign A.1).

The real panel is the TCP *client*: it dials in to a listening ``PanelServer``
(the receiver under test). ``MockPanel`` plays that client role. It opens a
connection to a loopback ``PanelServer``, completes a real HELLO/POLL
handshake, and then either:

  * answers the receiver's XML/binary/panel requests from a scriptable table
    (:meth:`serve_requests`), or
  * injects deliberately malformed bytes via the raw injectors
    (``send_raw``, ``send_frame_with_bad_length``, ``send_truncated``,
    ``send_bad_checksum``, ``send_in_chunks``, ``drip``, ``half_open``,
    ``slow_drain``, ``disconnect``) to exercise the decoder/teardown paths.

The scriptable table maps ``(major, minor, command_id_or_opcode)`` to an
:class:`Action`. The key's third element is the XML ``COMMAND ID`` string for
``major=10`` requests and the leading opcode byte for ``major=4``/``major=5``
requests; ``None`` matches any third element for that ``(major, minor)`` pair.

This module is import-safe: importing it opens no sockets and starts no tasks.
Construct a :class:`MockPanel`, ``await connect()``, and drive it explicitly.

Usage sketch (against a loopback server, mirroring
``tests/test_session.py:297``)::

    async with PanelServer(receiver_id=1001, bind="127.0.0.1", port=0,
                           on_session=on_session) as server:
        port = server._server.sockets[0].getsockname()[1]
        panel = MockPanel("127.0.0.1", port, panel_id=1000, receiver_id=1001,
                          script={(MajorCode.XML_CMD, MinorCode.REQUEST, "info"):
                                  Action(payload=INFO_REPLY)})
        await panel.connect()
        await panel.hello()
        await panel.poll()
        serve = asyncio.create_task(panel.serve_requests())
        ...
        await panel.disconnect()
        serve.cancel()
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import struct
from collections.abc import Mapping
from dataclasses import dataclass

from spcedp.wire import (
    HEADER_LEN,
    Frame,
    FrameDecoder,
    MajorCode,
    MinorCode,
)
from spcedp.xmlcmd import FRAG_FIRST

log = logging.getLogger("spcedp.mockpanel")

# Default 8-byte HELLO/POLL nonce payload (the real panel sends random bytes;
# the receiver echoes them verbatim, so the exact value does not matter).
DEFAULT_NONCE = b"12345678"

# Sentinel: the script entry deliberately sends no reply (tests the receiver's
# timeout / idle path rather than the reply-correlation path).
NO_REPLY = object()

# A script key is (major, minor, command_id_or_opcode); the third element is
# the XML COMMAND ID (str) for major=10 or the opcode byte (int) for
# major=4/5, or None to match any request for that (major, minor) pair.
ScriptKey = tuple[int, int, str | int | None]


@dataclass(slots=True)
class Action:
    """One scripted response to a matched inbound request.

    Exactly one of ``payload``/``fragments``/``reply_code`` should be set
    (in that precedence order); if none is set the reply payload is empty.
    ``delay`` is applied before replying. If ``no_reply`` is true the request
    is consumed silently and nothing is sent back.

      * ``payload``     - full reply payload bytes sent as a single frame.
      * ``fragments``   - a list of payloads sent as successive reply frames,
                          all sharing the request's sequence (fragmented XML).
      * ``reply_code``  - a single status byte (binary/panel reply shape).
      * ``no_reply``    - consume the request, send nothing.
      * ``delay``       - seconds to sleep before replying.
    """

    payload: bytes | None = None
    fragments: list[bytes] | None = None
    reply_code: int | None = None
    no_reply: bool = False
    delay: float = 0.0


# Convenience: the NO_REPLY sentinel as a ready-made Action.
NO_REPLY_ACTION = Action(no_reply=True)


def _reply_minor(req: Frame) -> int:
    """Map a request frame to the minor code the panel uses for its reply."""
    if req.major == MajorCode.XML_CMD:
        return int(MinorCode.REPLY)
    if req.major == MajorCode.BINARY_CMD:
        return int(MinorCode.BINARY_REPLY)
    if req.major == MajorCode.PANEL_CMD:
        return int(MinorCode.PANEL_REPLY)
    # Fall back to a generic reply minor for unknown majors.
    return int(MinorCode.REPLY)


def _command_id(req: Frame) -> str | int | None:
    """Extract the script-key third element from a request frame.

    XML requests (major=10) carry ``<marker><COMMAND ID="..." .../>``; pull the
    COMMAND ID. Binary/panel requests carry the opcode as the first payload
    byte. Anything else has no third element (returns None).
    """
    if req.major == MajorCode.XML_CMD:
        try:
            text = req.payload[1:].decode("ascii", "replace")
        except Exception:  # pragma: no cover - defensive
            return None
        marker = 'ID="'
        start = text.find(marker)
        if start < 0:
            return None
        start += len(marker)
        end = text.find('"', start)
        if end < 0:
            return None
        return text[start:end]
    if req.major in (MajorCode.BINARY_CMD, MajorCode.PANEL_CMD):
        return req.payload[0] if req.payload else None
    return None


class MockPanel:
    """Adversarial EDP panel that dials in to a ``PanelServer`` (campaign A.1).

    The TCP client half of the protocol. Provides a real HELLO/POLL handshake,
    a scripted request/reply server loop, and a battery of raw injectors that
    bypass ``Frame.encode`` to feed the receiver malformed bytes.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        panel_id: int = 1000,
        receiver_id: int = 1001,
        key: bytes | None = None,
        script: Mapping[ScriptKey, Action] | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.panel_id = panel_id
        self.receiver_id = receiver_id
        self.key = key
        self.script: dict[ScriptKey, Action] = dict(script) if script else {}
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._decoder = FrameDecoder(key=key)
        self._seq = 0
        # Frames decoded from the receiver but not yet matched/handled. Lets a
        # caller (or serve_requests) pull receiver-originated frames in order.
        self._inbound: asyncio.Queue[Frame] = asyncio.Queue()
        # Set once half_open() asks the read pump to stop draining the socket.
        self._half_open = False
        self._read_pump: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------ wiring

    @property
    def writer(self) -> asyncio.StreamWriter:
        if self._writer is None:
            raise RuntimeError("MockPanel.connect() has not been called")
        return self._writer

    async def connect(self) -> None:
        """Open the TCP connection to the receiver and start the read pump."""
        self._reader, self._writer = await asyncio.open_connection(self.host, self.port)
        self._read_pump = asyncio.ensure_future(self._pump_inbound())

    def _next_seq(self) -> int:
        self._seq = (self._seq + 1) & 0xFFFFFFFF
        return self._seq

    def _panel_frame(self, *, major: int, minor: int, payload: bytes, sequence: int) -> Frame:
        """Build a frame addressed from this panel to the receiver (src_flag 0)."""
        return Frame(
            src_id=self.panel_id,
            dst_id=self.receiver_id,
            sequence=sequence,
            major=major,
            minor=minor,
            payload=payload,
            src_flag=0x00,  # 0x00 == from panel
        )

    async def _write(self, data: bytes) -> None:
        """Write raw bytes to the socket and drain (the only socket write path)."""
        self.writer.write(data)
        await self.writer.drain()

    async def _pump_inbound(self) -> None:
        """Continuously read the socket, decode frames, and queue them.

        Runs as a background task so ``hello``/``poll`` can await their ACKs and
        ``serve_requests`` can react to receiver-originated requests. Honours
        ``half_open`` by parking (stops reading, keeps the socket alive)."""
        assert self._reader is not None
        try:
            while True:
                if self._half_open:
                    await asyncio.sleep(0.05)
                    continue
                chunk = await self._reader.read(4096)
                if not chunk:
                    return  # receiver closed the connection
                for frame in self._decoder.feed(chunk):
                    self._inbound.put_nowait(frame)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            return
        except Exception:  # pragma: no cover - defensive, keep the pump quiet
            log.debug("mock panel read pump stopped on error", exc_info=True)
            return

    async def _expect(self, major: int, minor: int, *, timeout: float = 2.0) -> Frame:
        """Pull the next inbound frame matching (major, minor), skipping others."""
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for maj={major} min={minor} from receiver")
            frame = await asyncio.wait_for(self._inbound.get(), remaining)
            if frame.major == major and frame.minor == minor:
                return frame

    # ------------------------------------------------------------------ handshake

    async def hello(self, payload: bytes = DEFAULT_NONCE, *, timeout: float = 2.0) -> Frame:
        """Send a HELLO and return the receiver's HELLO_ACK frame."""
        frame = self._panel_frame(
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.HELLO),
            payload=payload,
            sequence=self._next_seq(),
        )
        await self._write(frame.encode(key=self.key))
        return await self._expect(int(MajorCode.SESSION), int(MinorCode.HELLO_ACK), timeout=timeout)

    async def poll(self, payload: bytes = DEFAULT_NONCE, *, timeout: float = 2.0) -> Frame:
        """Send a POLL and return the receiver's POLL_ACK frame."""
        frame = self._panel_frame(
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.POLL),
            payload=payload,
            sequence=self._next_seq(),
        )
        await self._write(frame.encode(key=self.key))
        return await self._expect(int(MajorCode.SESSION), int(MinorCode.POLL_ACK), timeout=timeout)

    async def push_event(self, sia_payload: bytes, *, timeout: float = 2.0) -> Frame:
        """Push a SIA event (major=2) and return the receiver's EVENT_ACK."""
        frame = self._panel_frame(
            major=int(MajorCode.EVENT),
            minor=int(MinorCode.EVENT_PUSH),
            payload=sia_payload,
            sequence=self._next_seq(),
        )
        await self._write(frame.encode(key=self.key))
        return await self._expect(int(MajorCode.EVENT), int(MinorCode.EVENT_ACK), timeout=timeout)

    # ------------------------------------------------------------------ scripted server

    async def serve_requests(self) -> None:
        """Answer the receiver's requests from ``self.script`` until disconnect.

        Reads receiver-originated request frames (XML/binary/panel) off the
        inbound queue and replies per the matched :class:`Action`. A POLL/HELLO
        the receiver might send is ACK-irrelevant here (the panel drives those),
        and replies the receiver does not expect are ignored. Unmatched requests
        get an empty reply payload so the receiver's future still resolves rather
        than hanging - a mute receiver is never the harness's fault."""
        while True:
            try:
                frame = await self._inbound.get()
            except asyncio.CancelledError:
                return
            action = self._match(frame)
            if action is None:
                # No script entry: reply with an empty payload so the receiver's
                # pending future resolves instead of timing out (tests that want
                # a timeout should script NO_REPLY explicitly).
                await self._reply(frame, Action(payload=b""))
                continue
            await self._reply(frame, action)

    def _match(self, req: Frame) -> Action | None:
        """Find the scripted Action for a request frame, or None."""
        cid = _command_id(req)
        # Exact (major, minor, id) first, then a wildcard id for that pair.
        for key in ((req.major, req.minor, cid), (req.major, req.minor, None)):
            action = self.script.get(key)
            if action is not None:
                return action
        return None

    async def _reply(self, req: Frame, action: Action) -> None:
        """Send the scripted reply (or fragments / status byte) for a request."""
        if action.delay:
            await asyncio.sleep(action.delay)
        if action.no_reply:
            return
        minor = _reply_minor(req)
        if action.fragments is not None:
            for chunk in action.fragments:
                await self._send_reply_payload(req, minor, chunk)
            return
        if action.reply_code is not None:
            await self._send_reply_payload(req, minor, bytes([action.reply_code & 0xFF]))
            return
        await self._send_reply_payload(req, minor, action.payload or b"")

    async def _send_reply_payload(self, req: Frame, minor: int, payload: bytes) -> None:
        """Emit one reply frame echoing the request's sequence."""
        reply = self._panel_frame(
            major=req.major,
            minor=minor,
            payload=payload,
            sequence=req.sequence,
        )
        await self._write(reply.encode(key=self.key))

    # ------------------------------------------------------------------ raw injectors

    async def send_raw(self, data: bytes) -> None:
        """Write arbitrary bytes straight to the socket (bypasses Frame.encode)."""
        await self._write(data)

    async def send_frame_with_bad_length(self, frame: Frame, rem_override: int) -> None:
        """Encode ``frame`` then overwrite its 2-byte length prefix with
        ``rem_override`` (little-endian). Used to drive the false-large-length
        wedge (B1): the receiver sees a valid-magic header claiming more bytes
        than will ever arrive."""
        encoded = bytearray(frame.encode(key=self.key))
        encoded[0:2] = struct.pack("<H", rem_override & 0xFFFF)
        await self._write(bytes(encoded))

    async def send_truncated(self, frame: Frame, keep: int) -> None:
        """Encode ``frame`` and send only its first ``keep`` bytes, then stop.

        The receiver should never deliver a frame from an incomplete buffer; the
        idle timeout must eventually reclaim the session."""
        encoded = frame.encode(key=self.key)
        await self._write(encoded[:keep])

    async def send_bad_checksum(self, frame: Frame) -> None:
        """Encode ``frame`` then corrupt its checksum slot (cleartext only).

        Flips the two checksum bytes at wire offsets 0x13/0x14 (struct offset
        0x11/0x12 plus the 2-byte length prefix) so the receiver's cleartext
        checksum validation (M1) rejects it. Raises if a key is configured, as
        the checksum sits inside the encrypted region and cannot be flipped on
        the wire without re-encrypting."""
        if self.key is not None:
            raise ValueError("send_bad_checksum cannot target an encrypted frame")
        encoded = bytearray(frame.encode(key=None))
        # Wire offsets: 2-byte length prefix + struct checksum slot 0x11/0x12.
        lo = 2 + 0x11
        hi = 2 + 0x12
        encoded[lo] ^= 0xFF
        encoded[hi] ^= 0xFF
        await self._write(bytes(encoded))

    async def send_in_chunks(self, data: bytes, sizes: list[int]) -> None:
        """Write ``data`` split into segments of the given ``sizes``.

        Exercises the decoder's TCP-reassembly path (a frame split across
        reads). Any bytes left over after consuming ``sizes`` are sent as a
        final segment so the full buffer is always transmitted."""
        offset = 0
        for size in sizes:
            if offset >= len(data):
                break
            await self._write(data[offset : offset + size])
            offset += size
        if offset < len(data):
            await self._write(data[offset:])

    async def drip(self, data: bytes, delay: float) -> None:
        """Send ``data`` one byte at a time, sleeping ``delay`` between bytes.

        Models a peer trickling bytes; combined with ``send_frame_with_bad_length``
        it reproduces the wedge scenario where bytes keep arriving but never
        complete the (phantom) claimed frame."""
        for i in range(len(data)):
            await self._write(data[i : i + 1])
            if delay:
                await asyncio.sleep(delay)

    async def half_open(self) -> None:
        """Stop reading the socket while keeping it open and writable.

        Parks the inbound read pump so the receiver's outbound queue backs up
        (its peer is not draining). The connection stays alive, so this drives
        the write-backpressure / bounded-queue teardown path (B2/M5) rather than
        an EOF."""
        self._half_open = True

    async def slow_drain(self) -> None:
        """Advertise a tiny receive window by reading at most one byte per pass.

        A softer form of ``half_open``: the socket is still drained, but so
        slowly that the receiver's writer.drain() backpressure engages. Toggles
        the read pump into a one-byte-at-a-time mode."""
        # Re-route the pump through a slow reader by parking the fast pump and
        # starting a deliberately starved one.
        self._half_open = True
        if self._read_pump is not None:
            self._read_pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._read_pump
        self._read_pump = asyncio.ensure_future(self._pump_inbound_slow())

    async def _pump_inbound_slow(self) -> None:
        """Read at most one byte per loop pass to throttle the receiver."""
        assert self._reader is not None
        try:
            while True:
                chunk = await self._reader.read(1)
                if not chunk:
                    return
                for frame in self._decoder.feed(chunk):
                    self._inbound.put_nowait(frame)
                await asyncio.sleep(0.01)
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            return

    async def disconnect(self, *, abortive: bool = False) -> None:
        """Close the connection.

        ``abortive=True`` sends a TCP RST (transport.abort) to simulate a hard
        drop with no clean FIN - the flapping-reconnect path (M2). Otherwise a
        normal close (FIN) is performed. Always stops the read pump first."""
        if self._read_pump is not None:
            self._read_pump.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._read_pump
            self._read_pump = None
        if self._writer is None:
            return
        if abortive:
            transport = self._writer.transport
            with contextlib.suppress(Exception):
                transport.abort()
        else:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._writer = None
        self._reader = None

    # ------------------------------------------------------------------ helpers

    def build_frame(
        self, *, major: int, minor: int, payload: bytes = b"", sequence: int | None = None
    ) -> Frame:
        """Construct (but do not send) a panel->receiver frame for an injector.

        Convenience for the raw injectors, which take a ``Frame`` and corrupt
        its encoding. Uses the next sequence if ``sequence`` is None."""
        return self._panel_frame(
            major=major,
            minor=minor,
            payload=payload,
            sequence=self._next_seq() if sequence is None else sequence,
        )

    def poll_frame(self, payload: bytes = DEFAULT_NONCE, sequence: int | None = None) -> Frame:
        """Build a POLL frame for use with the raw injectors."""
        return self.build_frame(
            major=int(MajorCode.SESSION),
            minor=int(MinorCode.POLL),
            payload=payload,
            sequence=sequence,
        )

    @staticmethod
    def junk(n: int) -> bytes:
        """Return ``n`` random bytes (for malformed-stream injection)."""
        return os.urandom(n)


def valid_magic_prefix(rem: int) -> bytes:
    """Return a 4-byte header start with a valid EDP magic and a chosen ``rem``.

    ``rem`` is the little-endian remaining-length field; the next two bytes are
    the protocol byte (0x45 'E') and version (0x02). Used to hand-craft a
    valid-looking-but-incomplete header for the wedge tests without a full
    ``Frame``."""
    return struct.pack("<H", rem & 0xFFFF) + bytes([0x45, 0x02])


# Re-export the FRAG marker and header length so test modules building raw
# fragment payloads / truncations do not have to import from two places.
__all__ = [
    "Action",
    "MockPanel",
    "NO_REPLY",
    "NO_REPLY_ACTION",
    "ScriptKey",
    "DEFAULT_NONCE",
    "FRAG_FIRST",
    "HEADER_LEN",
    "valid_magic_prefix",
]
