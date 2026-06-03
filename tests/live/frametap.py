"""Raw frame capture shim for the live campaign (campaign B.2).

Records every raw inbound and outbound frame (direction, monotonic timestamp,
bytes) to a length-prefixed binary capture file so a real session can later be
replayed byte-for-byte into pytest fixtures and mock-panel scripts
(``replay_to_fixture.py``).

The tap monkeypatches the session's two socket boundaries:

  * ``Session._send`` - records the encoded outbound frame (receiver -> panel),
    including ACKs and command requests, before it is queued.
  * ``FrameDecoder.feed`` - records each raw inbound chunk (panel -> receiver)
    as it is fed to the decoder.

Because ``_send`` encodes (and optionally encrypts) the frame itself, the
recorded outbound bytes are exactly what hits the wire. Inbound is recorded as
raw chunks (still encrypted if the link is encrypted), which is what a replay
must feed back through a ``FrameDecoder``.

Capture file format (repeated records, little-endian):

    1 byte   direction   'I' (0x49) inbound, 'O' (0x4F) outbound
    8 bytes  timestamp   double, time.monotonic()
    4 bytes  length      uint32, number of frame bytes that follow
    N bytes  frame       raw bytes

Use as a context manager around a live run::

    with FrameTap("captures/step1.bin") as tap:
        async with PanelServer(...):
            ...   # all frames for this run are appended to the file
"""

from __future__ import annotations

import contextlib
import struct
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import BinaryIO

from spcedp import wire
from spcedp.client import Session

DIR_INBOUND = b"I"
DIR_OUTBOUND = b"O"

# Record header: direction char, monotonic ts (double), payload length (uint32).
_RECORD_HEADER = struct.Struct("<cdI")


@dataclass(slots=True)
class FrameRecord:
    """One captured frame: direction, monotonic timestamp, raw bytes."""

    direction: str  # "I" or "O"
    ts: float
    data: bytes


class FrameTap:
    """Records all raw inbound/outbound frames during a live run to a file.

    Installs monkeypatches on import-time module objects (``Session._send`` and
    ``FrameDecoder.feed``) on ``__enter__`` and restores them on ``__exit__``,
    so capture is fully transparent to the SDK and the live runner."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._fh: BinaryIO | None = None
        self._orig_send: object | None = None
        self._orig_feed: object | None = None
        self.records_written = 0

    def __enter__(self) -> FrameTap:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("ab")
        self._install()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._restore()
        if self._fh is not None:
            self._fh.flush()
            self._fh.close()
            self._fh = None

    # ------------------------------------------------------------------ patching

    def _install(self) -> None:
        """Wrap Session._send and FrameDecoder.feed to record frames."""
        tap = self

        orig_send = Session._send
        self._orig_send = orig_send

        def _send(self: Session, frame: wire.Frame) -> None:
            # Never let capture break a real send.
            with contextlib.suppress(Exception):  # pragma: no cover - defensive
                tap._write(DIR_OUTBOUND, frame.encode(key=self.key))
            return orig_send(self, frame)

        Session._send = _send  # type: ignore[method-assign]

        orig_feed = wire.FrameDecoder.feed
        self._orig_feed = orig_feed

        def _feed(self: wire.FrameDecoder, data: bytes) -> list[wire.Frame]:
            tap._write(DIR_INBOUND, bytes(data))
            return orig_feed(self, data)

        wire.FrameDecoder.feed = _feed  # type: ignore[method-assign]

    def _restore(self) -> None:
        if self._orig_send is not None:
            Session._send = self._orig_send  # type: ignore[method-assign,assignment]
            self._orig_send = None
        if self._orig_feed is not None:
            wire.FrameDecoder.feed = self._orig_feed  # type: ignore[method-assign,assignment]
            self._orig_feed = None

    # ------------------------------------------------------------------ writing

    def _write(self, direction: bytes, data: bytes) -> None:
        if self._fh is None:
            return
        self._fh.write(_RECORD_HEADER.pack(direction, time.monotonic(), len(data)))
        self._fh.write(data)
        self.records_written += 1


def read_capture(path: str | Path) -> Iterator[FrameRecord]:
    """Yield :class:`FrameRecord` entries from a capture file in order.

    The complement of ``FrameTap``'s writer; used by ``replay_to_fixture.py``.
    Stops cleanly at EOF and on a truncated trailing record."""
    p = Path(path)
    with p.open("rb") as fh:
        while True:
            header = fh.read(_RECORD_HEADER.size)
            if len(header) < _RECORD_HEADER.size:
                return
            direction_b, ts, length = _RECORD_HEADER.unpack(header)
            data = fh.read(length)
            if len(data) < length:
                return  # truncated trailing record
            yield FrameRecord(
                direction=direction_b.decode("ascii", "replace"),
                ts=ts,
                data=data,
            )
