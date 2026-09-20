"""Parse SIA events without losing alarm data to clock or description quirks.

Descriptions may contain field delimiters; trailing fields are right-anchored.
See PROTOCOL.md for the payload format.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from dataclasses import dataclass

log = logging.getLogger("spcedp")

# Match only the fixed structure: the E2[#...] envelope, the spc_id, and the
# 14-digit timestamp. Everything after the timestamp is captured raw and split
# by a right-anchored rsplit so an interior '|' in the free-text description
# cannot shift the trailing fixed fields (extra, verification_id).
_ENVELOPE = re.compile(r"^E2\[#(?P<spc>\d+)\|(?P<ts>\d{14})\|(?P<rest>.*)\]$", re.DOTALL)


@dataclass(slots=True)
class SiaEvent:
    spc_id: int
    timestamp: dt.datetime | None  # None if the panel sent an out-of-range clock value
    timestamp_raw: str  # the raw 14-char HHMMSSDDMMYYYY string, always preserved
    sia_code: str
    address: str
    description: str
    verification_id: str
    extra: str = ""

    @classmethod
    def parse(cls, payload: bytes | str) -> SiaEvent:
        """Parse an ``E2[...]`` SIA event payload.

        Right-anchors the trailing fixed fields so an interior '|' in the
        free-text description cannot corrupt ``extra``/``verification_id``.

        Timestamps are naive panel-local wall time; the protocol carries no timezone.
        ``timestamp_raw`` preserves the original value even if the clock is invalid.

        Raises ``ValueError`` for genuinely non-matching payloads.
        """
        if isinstance(payload, bytes):
            # SPC firmware uses byte 0xA6 as a field separator inside the
            # human-readable description. It is Latin-1 "¦", not valid UTF-8;
            # normalise that one protocol byte before decoding the otherwise
            # ASCII/UTF-8 envelope so callers never receive U+FFFD glyphs.
            text = payload.replace(b"\xa6", "¦".encode()).decode("utf-8", "replace")
        else:
            text = payload
        m = _ENVELOPE.match(text.strip())
        if not m:
            raise ValueError(f"not an SIA event payload: {text!r}")

        # rest = "<code>|<addr>|<description...maybe with |...>|<extra>|<vid>"
        # Right-anchor: pull the two trailing fixed fields off the right, and the
        # two remaining leading fixed fields off the left; whatever is left in
        # the middle is the description (re-joined, interior pipes preserved).
        rest = m["rest"]
        leading = rest.split("|", 2)
        if len(leading) < 3:
            # Need at least code, addr, and one field for the trailing pair.
            raise ValueError(f"not an SIA event payload: {text!r}")
        code, addr, tail = leading
        trailing = tail.rsplit("|", 2)
        if len(trailing) < 3:
            # tail must still split into description + extra + vid.
            raise ValueError(f"not an SIA event payload: {text!r}")
        desc, extra, vid = trailing

        ts_raw = m["ts"]
        ts = cls._parse_timestamp(ts_raw)

        return cls(
            spc_id=int(m["spc"]),
            timestamp=ts,
            timestamp_raw=ts_raw,
            sia_code=code,
            address=addr,
            description=desc,
            extra=extra,
            verification_id=vid,
        )

    @staticmethod
    def _parse_timestamp(ts_raw: str) -> dt.datetime | None:
        """Build a datetime from the 14-char HHMMSSDDMMYYYY layout.

        Returns ``None`` (and logs) for an out-of-range clock value so the event
        is kept, never dropped.
        """
        try:
            ts = dt.datetime(
                year=int(ts_raw[10:14]),
                month=int(ts_raw[8:10]),
                day=int(ts_raw[6:8]),
                hour=int(ts_raw[0:2]),
                minute=int(ts_raw[2:4]),
                second=int(ts_raw[4:6]),
            )
        except ValueError:
            log.warning("SIA event has an out-of-range timestamp %r; keeping event", ts_raw)
            return None
        return ts
