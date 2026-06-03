"""XML command request builder and reply parser.

The XML command channel (major=10) has two quirks worth handling here
rather than in the client:

  1. Each payload is prefixed with a 1-byte fragment marker:
        0x01 = first / only chunk
        0x02 = continuation chunk
     The marker bytes are NOT part of the XML and must be stripped
     before parsing.

  2. Large replies are fragmented at the EDP layer.  The receiver pulls
     the next chunk by re-sending the same <COMMAND ID="..."/> with the
     leading marker switched to 0x02.  The final chunk closes the
     </COMMAND_REPLY> tag.

This module assembles a complete COMMAND_REPLY from one or more frame
payloads and parses it into a dict-of-lists structure (the panel's XML
is shallow - one outer wrapper, one or more child rows with attributes).
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr

FRAG_FIRST = 0x01
FRAG_CONT = 0x02

# Backstop on a single reassembled reply, in case a panel never closes
# </COMMAND_REPLY> (a real status dump is a few KB across a handful of frames).
MAX_REPLY_BYTES = 1 << 20  # 1 MiB

# Attribute values realistically carried on the XML command channel.
AttrValue = str | int | None

# One parsed row: an element's attributes (all values are strings).
Row = dict[str, str]
# A parsed COMMAND_REPLY: keyed by section tag, each value a list of rows. A
# leaf section (e.g. <INFO .../>) is normalised to a single-row list so every
# section has a uniform shape.
XmlReply = dict[str, list[Row]]


def build_request(command_id: str, *, continuation: bool = False, **attrs: AttrValue) -> bytes:
    """Build the payload bytes for an XML COMMAND request frame.

    Attribute values are XML-escaped (`quoteattr`), so a value containing
    quotes or angle brackets cannot break out of its attribute and inject
    markup into the request.
    """
    marker = FRAG_CONT if continuation else FRAG_FIRST
    extra = "".join(f" {k.upper()}={quoteattr(str(v))}" for k, v in attrs.items() if v is not None)
    xml = f"<COMMAND ID={quoteattr(command_id)}{extra} />"
    return bytes([marker]) + xml.encode("ascii")


class ReplyAssembler:
    """Concatenate fragmented XML reply payloads into one XML string."""

    def __init__(self, max_bytes: int = MAX_REPLY_BYTES) -> None:
        self._buf = bytearray()
        self._max_bytes = max_bytes

    def feed(self, payload: bytes) -> bytes | None:
        """Add one frame's payload; return assembled XML once </COMMAND_REPLY>
        is seen, otherwise None to signal 'more frames needed'."""
        if not payload:
            return None
        # Drop the leading fragment marker byte and accumulate.
        self._buf += payload[1:]
        if len(self._buf) > self._max_bytes:
            raise ValueError(
                f"XML reply exceeded {self._max_bytes} bytes without closing </COMMAND_REPLY>"
            )
        if b"</COMMAND_REPLY>" in self._buf:
            assembled = bytes(self._buf)
            self._buf.clear()
            return assembled
        return None


def parse_reply(xml_bytes: bytes) -> XmlReply:
    """Parse a COMMAND_REPLY into a nested dict.

    Strategy: the panel's XML is always one outer <COMMAND_REPLY>
    containing one or more sections, each containing one or more rows
    with attributes only (no nested elements, no text content).  We
    return a dict keyed by section, each value a list of attribute rows
    (a leaf section like <INFO .../> becomes a single-row list).

    Example -
        <COMMAND_REPLY>
          <AREA_STATUS>
            <AREA ID="1" NAME="Home" MODE="0" />
          </AREA_STATUS>
        </COMMAND_REPLY>
    yields
        {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "0"}]}
    """
    # Reply bytes are untrusted (plain TCP, no MAC). ElementTree blocks
    # external entities but still expands internal ones (billion-laughs), and
    # the panel never sends a DTD, so reject any frame carrying one.
    if b"<!DOCTYPE" in xml_bytes or b"<!ENTITY" in xml_bytes:
        raise ValueError("XML reply contains a DTD/entity declaration; rejected")
    root = ET.fromstring(xml_bytes)
    if root.tag != "COMMAND_REPLY":
        raise ValueError(f"expected COMMAND_REPLY, got <{root.tag}>")
    out: XmlReply = {}
    for section in root:
        rows = [dict(child.attrib) for child in section]
        # A leaf section (e.g. <INFO .../>) carries its attributes directly;
        # normalise it to a single-row list so every section is uniform.
        out[section.tag] = rows if rows else [dict(section.attrib)]
    return out
