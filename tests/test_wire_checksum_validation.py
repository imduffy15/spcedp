"""M1: cleartext frames must be checksum-validated (no phantom frames).

Before the fix the cleartext decode path trusted any buffer that carried valid
magic and a self-consistent length, so a 23-byte all-zero-but-valid-magic
header (csum=0, dlen=0) decoded into a phantom ``Frame`` and a frame with a
corrupted checksum byte was accepted verbatim. Post-fix the cleartext path
recomputes :func:`edp_checksum` and rejects any mismatch with
:class:`FrameDecodeError`, while the stream :class:`FrameDecoder` resyncs past
the bad bytes (it never tears the connection down for a recoverable decode
error). Genuine captured frames - whose checksum is correct - must still
decode unchanged.
"""

from __future__ import annotations

import struct

import pytest

from spcedp.wire import (
    HEADER_LEN,
    PROTOCOL_BYTE,
    PROTOCOL_VERSION,
    Frame,
    FrameDecodeError,
    FrameDecoder,
    MajorCode,
    MinorCode,
    edp_checksum,
)

# Frames captured live from an SPC4300 panel (must keep decoding byte-for-byte).
# Layout per wire.py: bytes 0-1 rem(LE), 2 proto=0x45, 3 ver=0x02, 4 src_flag,
# 5-8 seq, 9-12 src, 13-16 dst, 17 major, 18 minor, 19-20 csum, 21-22 dlen.


def _h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


POLL_PANEL_TO_RX = _h(
    "1d 00  45 02  00  ab 2a e9 a1  e8 03 00 00  e9 03 00 00  01 00  11 ca  08 00"
    "  c5 b7 92 fc 53 4b 57 a3"
)
POLL_RX_TO_PANEL = _h(
    "1d 00  45 02  08  ab 2a e9 a1  e9 03 00 00  e8 03 00 00  01 01  40 8f  08 00"
    "  c5 b7 92 fc 53 4b 57 a3"
)
SIA_EVENT = _h(
    "42 00  45 02  00  ac 2a e9 a1  e8 03 00 00  e9 03 00 00  02 00  86 19  2d 00"
    "  45 32 5b 23 31 30 30 30 7c 30 38 35 32 31 32 30 33 30 36 32 30 32 36"
    "  7c 4e 54 7c 30 7c 49 50 20 4c 69 6e 6b 20 46 61 69 6c 7c 7c 30 5d"
)

GENUINE_FRAMES = [
    ("POLL_PANEL_TO_RX", POLL_PANEL_TO_RX, MajorCode.SESSION, MinorCode.POLL),
    ("POLL_RX_TO_PANEL", POLL_RX_TO_PANEL, MajorCode.SESSION, MinorCode.POLL_ACK),
    ("SIA_EVENT", SIA_EVENT, MajorCode.EVENT, MinorCode.EVENT_PUSH),
]


def _zero_magic_header() -> bytes:
    """A 23-byte all-zero buffer carrying only valid magic: rem=21 (so total ==
    HEADER_LEN, dlen=0), proto=0x45, ver=0x02, csum=0, dlen=0. This is exactly
    the phantom-frame trap M1 closes: it passes the magic and length checks but
    its real checksum is non-zero, so the slot value of 0 must be rejected."""
    buf = bytearray(HEADER_LEN)
    struct.pack_into("<H", buf, 0, HEADER_LEN - 2)  # rem = 21 -> total = 23
    buf[2] = PROTOCOL_BYTE
    buf[3] = PROTOCOL_VERSION
    # csum (offset 19-20) and dlen (offset 21-22) are left zero.
    return bytes(buf)


# --- M1.1 the all-zero-but-valid-magic phantom header -----------------------


def test_zero_magic_header_is_not_a_valid_checksum() -> None:
    """Sanity check the fixture: the genuine checksum for this header is non-zero,
    so a csum-slot of 0 is genuinely wrong (the test below is not vacuous)."""
    buf = _zero_magic_header()
    real = edp_checksum(buf[2:], dlen=0)  # struct bytes = wire minus 2B prefix
    assert real != 0


def test_zero_magic_header_rejected_on_cleartext_decode() -> None:
    """Direct decode of the phantom header raises FrameDecodeError rather than
    returning a Frame(major=0, minor=0, payload=b"")."""
    with pytest.raises(FrameDecodeError, match="checksum"):
        Frame.decode(_zero_magic_header())


def test_zero_magic_header_resynced_by_decoder() -> None:
    """The stream decoder must not emit a phantom frame for the all-zero header;
    it resyncs past it and still surfaces a following genuine frame."""
    d = FrameDecoder()
    out = d.feed(_zero_magic_header() + POLL_PANEL_TO_RX)
    assert [f.minor for f in out] == [MinorCode.POLL]
    assert out[0].sequence == 0xA1E92AAB


# --- a single flipped checksum byte must be rejected / resynced -------------


@pytest.mark.parametrize("csum_off", [19, 20])
def test_flipped_checksum_byte_rejected_on_decode(csum_off: int) -> None:
    """A real frame with one checksum byte flipped no longer decodes; the
    payload and length are intact but the checksum no longer matches."""
    bad = bytearray(POLL_PANEL_TO_RX)
    bad[csum_off] ^= 0x01
    with pytest.raises(FrameDecodeError, match="checksum"):
        Frame.decode(bytes(bad))


@pytest.mark.parametrize("csum_off", [19, 20])
def test_flipped_checksum_byte_resynced_then_recover(csum_off: int) -> None:
    """The decoder drops the corrupted frame and still emits the genuine frame
    that follows it on the stream - the corruption never silences the session."""
    bad = bytearray(POLL_PANEL_TO_RX)
    bad[csum_off] ^= 0x01
    d = FrameDecoder()
    out = d.feed(bytes(bad) + POLL_RX_TO_PANEL)
    assert [f.minor for f in out] == [MinorCode.POLL_ACK]
    assert out[0].src_flag == 0x08


def test_flipped_payload_byte_rejected() -> None:
    """Mutating a payload byte (without recomputing the checksum) is also caught
    by the cleartext checksum validation, not silently accepted."""
    bad = bytearray(SIA_EVENT)
    bad[-2] ^= 0x01  # flip inside the SIA payload
    with pytest.raises(FrameDecodeError, match="checksum"):
        Frame.decode(bytes(bad))


# --- genuine captured frames must still decode (no regression) --------------


@pytest.mark.parametrize(
    ("name", "raw", "major", "minor"),
    GENUINE_FRAMES,
    ids=[f[0] for f in GENUINE_FRAMES],
)
def test_genuine_frames_still_decode(
    name: str, raw: bytes, major: MajorCode, minor: MinorCode
) -> None:
    """The captured-frame fixtures carry correct checksums and must decode
    unchanged now that the cleartext path validates them."""
    f = Frame.decode(raw)
    assert f.major == major
    assert f.minor == minor


def test_genuine_frame_checksum_recomputes_to_slot_value() -> None:
    """The captured POLL's stored checksum equals the recomputed value - this is
    why validation accepts it (and pins the slot-skip behaviour of edp_checksum)."""
    f = Frame.decode(POLL_PANEL_TO_RX)
    stored = struct.unpack_from("<H", POLL_PANEL_TO_RX, 19)[0]
    recomputed = edp_checksum(POLL_PANEL_TO_RX[2:], dlen=len(f.payload))
    assert f.checksum == stored == recomputed


def test_genuine_frames_decode_through_streaming_decoder() -> None:
    """Both genuine POLLs, fed back-to-back through the stream decoder, emerge
    intact - end-to-end confirmation the validation is not over-rejecting."""
    d = FrameDecoder()
    out = d.feed(POLL_PANEL_TO_RX + POLL_RX_TO_PANEL)
    assert [f.minor for f in out] == [MinorCode.POLL, MinorCode.POLL_ACK]
