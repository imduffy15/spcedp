"""Tests for the XML command channel."""

from __future__ import annotations

import pytest

from spcedp.xmlcmd import FRAG_CONT, FRAG_FIRST, ReplyAssembler, build_request, parse_reply


def test_build_request_info() -> None:
    req = build_request("info")
    assert req[0] == FRAG_FIRST
    assert req[1:].decode() == '<COMMAND ID="info" />'


def test_build_request_continuation_with_attrs() -> None:
    req = build_request("zone_log", continuation=True, zone=3)
    assert req[0] == FRAG_CONT
    assert req[1:].decode() == '<COMMAND ID="zone_log" ZONE="3" />'


# Real INFO reply captured from the SPC4300:
# A representative INFO reply.  Identifying fields (serial, license key,
# config time) are anonymised placeholders; the rest mirrors a real reply.
INFO_REPLY_PAYLOAD = (
    b'\x01<COMMAND_REPLY><INFO TYPE="SPC4000" VARIANT="4300" '
    b'VERSION="3.15.0 - R.42751" DEVICE-ID="1" SN="0A1B2C3D" '
    b'CFGTIME="00000001012025" HW_VER_MAJOR="1" HW_VER_MINOR="4" '
    b'HW_VER_VDS="0" LICENSE_KEY="XXXXXXXXXXXXXXX" /></COMMAND_REPLY>'
)


def test_assemble_and_parse_single_chunk() -> None:
    asm = ReplyAssembler()
    body = asm.feed(INFO_REPLY_PAYLOAD)
    assert body is not None
    parsed = parse_reply(body)
    info = parsed["INFO"][0]
    assert info["TYPE"] == "SPC4000"
    assert info["VARIANT"] == "4300"
    assert info["VERSION"] == "3.15.0 - R.42751"


def test_assemble_two_fragment_reply() -> None:
    # Simulate a split reply.  Markers: first chunk 0x01, continuation 0x02.
    chunk1 = b'\x01<COMMAND_REPLY><AREA_STATUS><AREA ID="1" NAME="Home" '
    chunk2 = b'\x02MODE="0" /></AREA_STATUS></COMMAND_REPLY>'
    asm = ReplyAssembler()
    assert asm.feed(chunk1) is None
    body = asm.feed(chunk2)
    assert body is not None
    parsed = parse_reply(body)
    assert parsed["AREA_STATUS"][0]["NAME"] == "Home"


def test_assemble_three_fragment_reply() -> None:
    asm = ReplyAssembler()
    assert asm.feed(b"\x01<COMMAND_REPLY><ZONE_STATUS>") is None
    assert asm.feed(b'\x02<ZONE ID="1" ZONE_NAME="Hall" />') is None
    body = asm.feed(b"\x02</ZONE_STATUS></COMMAND_REPLY>")
    assert body is not None
    assert parse_reply(body)["ZONE_STATUS"][0]["ZONE_NAME"] == "Hall"


def test_assembler_empty_and_marker_only_return_none() -> None:
    asm = ReplyAssembler()
    assert asm.feed(b"") is None
    assert asm.feed(b"\x02") is None  # marker byte only -> empty body


def test_assembler_resets_between_replies() -> None:
    asm = ReplyAssembler()
    first = asm.feed(b'\x01<COMMAND_REPLY><A X="1" /></COMMAND_REPLY>')
    second = asm.feed(b'\x01<COMMAND_REPLY><A X="2" /></COMMAND_REPLY>')
    assert first is not None and second is not None
    assert b'X="2"' in second and b'X="1"' not in second


def test_assembler_rejects_oversized_reply() -> None:
    asm = ReplyAssembler(max_bytes=32)
    with pytest.raises(ValueError, match="exceeded"):
        asm.feed(b"\x01" + b"<NEVER_CLOSES>" * 8)


def test_build_request_escapes_attribute_injection() -> None:
    req = build_request("zone_log", zone='1" /><EVIL ATTR="x')
    xml = req[1:].decode()
    # The injected markup must be neutralised: still exactly one element.
    assert "<EVIL" not in xml
    assert xml.count("<COMMAND") == 1
    assert xml.rstrip().endswith("/>")


def test_parse_reply_rejects_dtd() -> None:
    payload = b'<!DOCTYPE x [<!ENTITY a "b">]><COMMAND_REPLY><A X="1" /></COMMAND_REPLY>'
    with pytest.raises(ValueError, match=r"DTD|entity"):
        parse_reply(payload)


def test_parse_reply_rejects_utf16_dtd_bypass() -> None:
    # A DTD/entity declaration encoded as UTF-16 carries no ASCII "<!DOCTYPE"
    # bytes, so a raw-byte substring guard would miss it. The parser must still
    # reject the DTD (and so never expand the entity).
    bomb = (
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<!DOCTYPE COMMAND_REPLY [<!ENTITY a "AAAAAAAAAA">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
        '<COMMAND_REPLY><INFO X="&b;" /></COMMAND_REPLY>'
    ).encode("utf-16")
    assert b"<!DOCTYPE" not in bomb  # precondition: not visible to a byte scan
    with pytest.raises(ValueError, match=r"DTD|entity"):
        parse_reply(bomb)


def test_parse_reply_rejects_malformed_xml() -> None:
    # A malformed reply surfaces as ValueError (not a bare ExpatError) so the
    # session maps it to SpcProtocolError.
    with pytest.raises(ValueError):
        parse_reply(b"<COMMAND_REPLY><UNCLOSED>")


def test_parse_reply_rejects_non_command_reply_root() -> None:
    with pytest.raises(ValueError, match="COMMAND_REPLY"):
        parse_reply(b"<NOPE />")


def test_parse_reply_multi_row_section_is_a_list() -> None:
    xml = (
        b"<COMMAND_REPLY><AREA_STATUS>"
        b'<AREA ID="1" NAME="A" /><AREA ID="2" NAME="B" />'
        b"</AREA_STATUS></COMMAND_REPLY>"
    )
    parsed = parse_reply(xml)
    assert isinstance(parsed["AREA_STATUS"], list)
    assert [r["NAME"] for r in parsed["AREA_STATUS"]] == ["A", "B"]
