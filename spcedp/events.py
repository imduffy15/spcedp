"""SIA event payload parsing.

Panel-pushed events arrive as major=2 (EVENT) frames with an ASCII payload
in this shape:

    E2[#<spc_id>|<HHMMSSDDMMYYYY>|<sia_code>|<address>|<description>|<extra>|<verification_id>]

There are four leading fixed fields (spc_id, timestamp, sia_code, address),
two trailing fixed fields (extra, verification_id), and <description> in the
middle. The free-text description may itself contain '|', so we right-anchor
the trailing fields rather than splitting left-to-right.

Examples seen on the wire:

    E2[#1000|08521203062026|NT|0|IP Link Fail||0]
    E2[#1000|08521703062026|NR|0|IP Link Restore||0]
    E2[#1000|09153403062026|NR|0|IP Link Restore||0]

We tolerate trailing whitespace, missing fields, and unknown SIA codes.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from dataclasses import dataclass
from zoneinfo import ZoneInfo

log = logging.getLogger("spcedp")

# Match only the fixed structure: the E2[#...] envelope, the spc_id, and the
# 14-digit timestamp. Everything after the timestamp is captured raw and split
# by a right-anchored rsplit so an interior '|' in the free-text description
# cannot shift the trailing fixed fields (extra, verification_id). H3.
_ENVELOPE = re.compile(r"^E2\[#(?P<spc>\d+)\|(?P<ts>\d{14})\|(?P<rest>.*)\]$", re.DOTALL)

# A SMALL, deliberately PARTIAL SIA code -> category map. The full catalogue is
# a documented live task (provoke-and-catalogue); this covers the codes already
# seen plus the obvious self-restoring families. Unknown codes -> "unknown".
_SIA_CATEGORY: dict[str, str] = {
    # alarm
    "BA": "alarm",  # burglary alarm
    "FA": "alarm",  # fire alarm
    "PA": "alarm",  # panic alarm
    "HA": "alarm",  # holdup alarm
    "TA": "alarm",  # tamper alarm
    # restore
    "BR": "restore",  # burglary restore
    "FR": "restore",  # fire restore
    "TR": "restore",  # tamper restore
    "NR": "restore",  # network/IP link restore (seen on the wire)
    # trouble
    "NT": "trouble",  # network/IP link fail (seen on the wire)
    "YT": "trouble",  # battery trouble
    "AT": "trouble",  # AC/mains fail
    "AR": "restore",  # AC/mains restore
    "YR": "restore",  # battery restore
    "ZO": "trouble",  # zone open (non-alarm)
    "ZC": "restore",  # zone close (non-alarm)
    # access (arm/disarm/login)
    "OP": "access",  # opening / disarm
    "CL": "access",  # closing / arm
    "OG": "access",  # operator login
    "OL": "access",  # operator logout
    # test
    "RP": "test",  # automatic test
    "RX": "test",  # manual test
}


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

    @property
    def category(self) -> str:
        """Coarse SIA category for ``sia_code``.

        Backed by a small, partial map (see ``_SIA_CATEGORY``); returns
        "unknown" for codes not yet catalogued. ``sia_code`` stays the source
        of truth.
        """
        return _SIA_CATEGORY.get(self.sia_code.upper(), "unknown")

    @classmethod
    def parse(cls, payload: bytes | str, *, panel_tz: ZoneInfo | None = None) -> SiaEvent:
        """Parse an ``E2[...]`` SIA event payload.

        Right-anchors the trailing fixed fields so an interior '|' in the
        free-text description cannot corrupt ``extra``/``verification_id`` (H3).

        If ``panel_tz`` is given, ``timestamp`` is returned timezone-aware in
        that zone (with ``fold`` handling for ambiguous wall-clock times during
        a DST fall-back); when ``None`` (the default), ``timestamp`` stays naive
        to preserve backward call compatibility. The host timezone is never
        guessed. ``timestamp_raw`` always holds the original 14-char string.

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
        ts = cls._parse_timestamp(ts_raw, panel_tz)

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
    def _parse_timestamp(ts_raw: str, panel_tz: ZoneInfo | None) -> dt.datetime | None:
        """Build a datetime from the 14-char HHMMSSDDMMYYYY layout.

        Returns ``None`` (and logs) for an out-of-range clock value so the event
        is kept, never dropped. When ``panel_tz`` is given the result is
        timezone-aware with ``fold`` handling.
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
        if panel_tz is not None:
            # Attach the panel zone. fold=0 picks the first (pre-transition)
            # occurrence of an ambiguous wall-clock time during a DST fall-back;
            # callers comparing two such events get distinct aware instants.
            ts = ts.replace(tzinfo=panel_tz, fold=0)
        return ts
