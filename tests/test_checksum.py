"""Verify the EDP frame checksum against captured frames + spot samples."""

from __future__ import annotations

import struct

from spcedp.wire import Frame, edp_checksum


def _struct_bytes_and_dlen(wire_hex: str):
    wire = bytes.fromhex(wire_hex.replace(" ", ""))
    struct_bytes = wire[2:]  # strip length prefix
    dlen = struct.unpack_from("<H", struct_bytes, 0x13)[0]
    expected = struct.unpack_from("<H", struct_bytes, 0x11)[0]
    return struct_bytes, dlen, expected


# Three captured frames - HELLO (panel->gw), HELLO_ACK (gw->panel),
# and a 71-byte SIA_EVENT (panel->gw).  Real bytes pulled live from
# an SPC4300 panel.
HELLO = (
    "1d 00  45 02 00  10 15 58 0f  e8 03 00 00  e9 03 00 00  01 02  38 9d  08 00"
    "  24 cf 64 45 66 0c a4 3d"
)
HELLO_ACK = (
    "1d 00  45 02 08  10 15 58 0f  e9 03 00 00  e8 03 00 00  01 03  8c cb  08 00"
    "  24 cf 64 45 66 0c a4 3d"
)
SIA_EVENT = (
    # length prefix = 0x0045 (=69), total wire = 71B with 48-byte payload
    "45 00  45 02 00  12 15 58 0f  e8 03 00 00  e9 03 00 00  02 00  74 7a  30 00"
    "  45 32 5b 23 31 30 30 30 7c 30 39 31 35 33 34 30 33 30 36 32 30 32 36"
    "  7c 4e 52 7c 30 7c 49 50 20 4c 69 6e 6b 20 52 65 73 74 6f 72 65 7c 7c 30 5d"
)


def test_checksum_hello() -> None:
    body, dlen, expected = _struct_bytes_and_dlen(HELLO)
    assert edp_checksum(body, dlen) == expected


def test_checksum_hello_ack() -> None:
    body, dlen, expected = _struct_bytes_and_dlen(HELLO_ACK)
    assert edp_checksum(body, dlen) == expected


def test_checksum_sia_event() -> None:
    body, dlen, expected = _struct_bytes_and_dlen(SIA_EVENT)
    assert edp_checksum(body, dlen) == expected


def test_frame_encode_roundtrip_matches_capture() -> None:
    """Frame.encode() should reproduce captured wire bytes exactly."""
    wire = bytes.fromhex(HELLO.replace(" ", ""))
    f = Frame.decode(wire)
    assert f.encode() == wire


def test_frame_encode_roundtrip_hello_ack() -> None:
    wire = bytes.fromhex(HELLO_ACK.replace(" ", ""))
    f = Frame.decode(wire)
    assert f.encode() == wire


def test_frame_encode_roundtrip_event() -> None:
    wire = bytes.fromhex(SIA_EVENT.replace(" ", ""))
    f = Frame.decode(wire)
    assert f.encode() == wire
