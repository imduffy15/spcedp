"""Tests for the EDP wire format - round-trips and real captures."""

from __future__ import annotations

import struct

import pytest

from spcedp.wire import Frame, FrameDecoder, MajorCode, MinorCode, edp_checksum

# Frames captured live from an SPC4300 panel.


def _h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


# bytes 0-1 length(LE)=29  proto=45 ver=02 src_flag=00
# bytes 5-8  seq=a1e92aab    bytes 9-12 src=1000  bytes 13-16 dst=1001
# byte  17    maj=1 POLL     byte  18  min=0
# bytes 19-20 csum=ca11      bytes 21-22 dlen=0008
# bytes 23-30 payload
POLL_PANEL_TO_RX = _h(
    "1d 00  45 02  00  ab 2a e9 a1  e8 03 00 00  e9 03 00 00  01 00  11 ca  08 00"
    "  c5 b7 92 fc 53 4b 57 a3"
)
POLL_RX_TO_PANEL = _h(
    "1d 00  45 02  08  ab 2a e9 a1  e9 03 00 00  e8 03 00 00  01 01  40 8f  08 00"
    "  c5 b7 92 fc 53 4b 57 a3"
)
# SIA event - 68B total, dlen=48
SIA_EVENT = _h(
    "42 00  45 02  00  ac 2a e9 a1  e8 03 00 00  e9 03 00 00  02 00  86 19  2d 00"
    "  45 32 5b 23 31 30 30 30 7c 30 38 35 32 31 32 30 33 30 36 32 30 32 36"
    "  7c 4e 54 7c 30 7c 49 50 20 4c 69 6e 6b 20 46 61 69 6c 7c 7c 30 5d"
)


def test_decode_poll() -> None:
    f = Frame.decode(POLL_PANEL_TO_RX)
    assert f.major == MajorCode.SESSION
    assert f.minor == MinorCode.POLL
    assert f.src_id == 1000
    assert f.dst_id == 1001
    assert f.src_flag == 0x00
    assert f.payload.hex() == "c5b792fc534b57a3"
    assert f.sequence == 0xA1E92AAB


def test_decode_poll_ack() -> None:
    f = Frame.decode(POLL_RX_TO_PANEL)
    assert f.major == MajorCode.SESSION
    assert f.minor == MinorCode.POLL_ACK
    assert f.src_id == 1001
    assert f.dst_id == 1000
    assert f.src_flag == 0x08


def test_decode_sia_event() -> None:
    f = Frame.decode(SIA_EVENT)
    assert f.major == MajorCode.EVENT
    assert f.minor == MinorCode.EVENT_PUSH
    assert f.payload.startswith(b"E2[#1000|")
    assert b"IP Link Fail" in f.payload


def test_roundtrip_preserves_bytes_except_checksum() -> None:
    # The encoder leaves checksum at whatever's set on the Frame instance;
    # if we preserve it, encode/decode should be byte-for-byte identical.
    f = Frame.decode(POLL_PANEL_TO_RX)
    assert f.encode() == POLL_PANEL_TO_RX


def test_decoder_handles_split_reads() -> None:
    d = FrameDecoder()
    # Length prefix in one read, body in the next.
    assert d.feed(POLL_PANEL_TO_RX[:2]) == []
    out = d.feed(POLL_PANEL_TO_RX[2:])
    assert len(out) == 1
    assert out[0].minor == MinorCode.POLL


def test_decoder_handles_two_frames_in_one_read() -> None:
    d = FrameDecoder()
    out = d.feed(POLL_PANEL_TO_RX + POLL_RX_TO_PANEL)
    assert [f.minor for f in out] == [MinorCode.POLL, MinorCode.POLL_ACK]


def test_decoder_resyncs_on_garbage() -> None:
    d = FrameDecoder()
    # Prepend two bogus bytes; decoder should drop them and recover.
    out = d.feed(b"\x00\x00" + POLL_PANEL_TO_RX)
    assert len(out) == 1
    assert out[0].sequence == 0xA1E92AAB


# --- decode error guards -------------------------------------------------


def test_decode_rejects_short_buffer() -> None:
    with pytest.raises(ValueError, match="too short"):
        Frame.decode(b"\x00\x01\x02")


def test_decode_rejects_truncated_frame() -> None:
    with pytest.raises(ValueError, match="truncated"):
        Frame.decode(POLL_PANEL_TO_RX[:-4])


def test_decode_rejects_bad_magic() -> None:
    bad = bytearray(POLL_PANEL_TO_RX)
    bad[2] = 0x00  # corrupt the protocol byte
    with pytest.raises(ValueError, match="magic"):
        Frame.decode(bytes(bad))


def test_decode_rejects_dlen_overflow() -> None:
    # A dlen larger than the frame must be rejected, not silently truncated.
    bad = bytearray(POLL_PANEL_TO_RX)
    struct.pack_into("<H", bad, 21, 999)  # dlen field at wire offset 21-22
    with pytest.raises(ValueError, match="overflow"):
        Frame.decode(bytes(bad))


def test_decoder_resyncs_past_undecodable_frame() -> None:
    # A frame with valid magic + length prefix but a bad dlen fails to decode;
    # the stream decoder should drop it and still surface the following frame.
    bad = bytearray(POLL_PANEL_TO_RX)
    struct.pack_into("<H", bad, 21, 999)
    d = FrameDecoder()
    out = d.feed(bytes(bad) + POLL_PANEL_TO_RX)
    assert [f.minor for f in out] == [MinorCode.POLL]
    assert out[0].sequence == 0xA1E92AAB


def test_edp_checksum_rejects_short_input() -> None:
    with pytest.raises(ValueError, match="too short"):
        edp_checksum(b"\x00\x00\x00\x00", dlen=100)


def test_decoder_resync_limit_fails_fast_on_long_garbage() -> None:
    # A long run with no decodable frame must raise (fail fast) rather than
    # silently dropping everything to an eventual idle timeout.
    d = FrameDecoder()
    with pytest.raises(ValueError, match="resyncing"):
        d.feed(b"\x00" * 9000)


def test_encode_rejects_oversized_payload() -> None:
    huge = Frame(src_id=1, dst_id=2, sequence=0, major=10, minor=0, payload=b"x" * 0xFFFF)
    with pytest.raises(ValueError, match="too large"):
        huge.encode()
