"""Round-trip tests for EDP frame encryption.

We don't have a captured encrypted-mode frame to verify against (this
panel is in cleartext mode), but we can prove:

  - Frame.encode(key=KEY) → Frame.decode(KEY) round-trips perfectly.
  - The encrypted-flag bit at struct offset 2 is set.
  - The encrypted-payload byte range is at offsets 17+ on the wire.
  - The cleartext bytes 0-14 are identical to a non-encrypted frame.
  - The checksum, dlen, payload are recovered exactly after decrypt.
"""

from __future__ import annotations

import pytest

cryptography = pytest.importorskip("cryptography")

from spcedp.wire import (
    AES_BLOCK_SIZE,
    ENCRYPT_OFFSET_IN_WIRE,
    FLAG_ENCRYPTED,
    Frame,
    FrameDecoder,
    MajorCode,
    MinorCode,
)

KEY = bytes.fromhex("00112233445566778899AABBCCDDEEFF")


def _plain_hello() -> Frame:
    return Frame(
        src_id=1000,
        dst_id=1001,
        sequence=0xA1E92AAB,
        major=int(MajorCode.SESSION),
        minor=int(MinorCode.POLL),
        payload=b"abcdefgh",  # 8 bytes
        src_flag=0x00,
    )


def test_encrypt_sets_flag_and_pads_to_block_size() -> None:
    f = _plain_hello()
    wire = f.encode(key=KEY)
    # Wire bytes 0-1 = length-2; bytes 2-3 = proto/ver; byte 4 = flags
    assert wire[2] == 0x45
    assert wire[3] == 0x02
    assert wire[4] & FLAG_ENCRYPTED, "encrypted flag bit should be set"
    # Encrypted tail starts at wire offset 17, must be 16-byte aligned
    enc_tail_len = len(wire) - ENCRYPT_OFFSET_IN_WIRE
    assert enc_tail_len % AES_BLOCK_SIZE == 0
    assert enc_tail_len == AES_BLOCK_SIZE, "8-byte payload + 6-byte header tail rounds to 16"


def test_encrypt_decrypt_roundtrip_recovers_all_fields() -> None:
    f = _plain_hello()
    wire = f.encode(key=KEY)
    decoded = Frame.decode(wire, key=KEY)
    assert decoded.src_id == f.src_id
    assert decoded.dst_id == f.dst_id
    assert decoded.sequence == f.sequence
    assert decoded.major == f.major
    assert decoded.minor == f.minor
    assert decoded.payload == f.payload
    # Re-encoding the decoded frame should reproduce the same ciphertext
    assert decoded.encode(key=KEY) == wire


def test_cleartext_header_preserved_under_encryption() -> None:
    f = _plain_hello()
    plain_wire = f.encode()
    enc_wire = f.encode(key=KEY)
    # Bytes 0-3 are length prefix + proto + version. These will differ
    # only in the length byte (encrypted is longer).  Bytes 4-16 are the
    # cleartext part of the struct (flag/seq/src/dst); byte 4 (flags)
    # has the encrypt bit set in enc_wire so we mask that off.
    plain_struct_head = plain_wire[2:17]
    enc_struct_head = enc_wire[2:17]
    masked = bytearray(enc_struct_head)
    masked[2] &= ~FLAG_ENCRYPTED
    assert bytes(masked) == plain_struct_head


def test_decoder_streams_encrypted_frames() -> None:
    """FrameDecoder configured with a key should yield decrypted Frames."""
    f1 = _plain_hello()
    f2 = Frame(
        src_id=1001,
        dst_id=1000,
        sequence=0xA1E92AAC,
        major=int(MajorCode.SESSION),
        minor=int(MinorCode.POLL_ACK),
        payload=b"abcdefgh",
        src_flag=0x08,
    )
    stream = f1.encode(key=KEY) + f2.encode(key=KEY)
    decoder = FrameDecoder(key=KEY)
    frames = decoder.feed(stream)
    assert len(frames) == 2
    assert frames[0].payload == b"abcdefgh"
    assert frames[1].minor == int(MinorCode.POLL_ACK)


def test_decoder_without_key_rejects_encrypted_frame() -> None:
    enc_wire = _plain_hello().encode(key=KEY)
    decoder = FrameDecoder()  # no key
    with pytest.raises(ValueError, match="encrypted"):
        decoder.feed(enc_wire)


def test_bad_key_length_raises() -> None:
    f = _plain_hello()
    with pytest.raises(ValueError, match="16 bytes"):
        f.encode(key=b"too-short")


# --- ground-truth checks independent of the encode/decode round-trip -----


def test_encrypted_tail_decrypts_to_expected_layout() -> None:
    """Decrypt the tail with AES directly and assert the field layout +
    zero padding, so a wrong offset or PKCS#7 padding would be caught even
    though Frame.encode/decode round-trip cleanly."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    f = _plain_hello()
    wire = f.encode(key=KEY)
    plain = _plain_hello().encode()  # cleartext, for the non-encrypted fields
    # The cleartext region (seq/src/dst at wire 5..17) is untouched by encryption.
    assert wire[5:17] == plain[5:17]

    tail = wire[ENCRYPT_OFFSET_IN_WIRE:]
    assert len(tail) % AES_BLOCK_SIZE == 0
    dec = Cipher(algorithms.AES(KEY), modes.ECB()).decryptor()
    pt = dec.update(tail) + dec.finalize()
    # pt is struct offsets 15+: maj, min, csum(2), dlen(2), payload, padding.
    assert pt[0] == int(MajorCode.SESSION)
    assert pt[1] == int(MinorCode.POLL)
    assert int.from_bytes(pt[2:4], "little") == f.checksum
    assert int.from_bytes(pt[4:6], "little") == 8  # dlen
    assert pt[6:14] == b"abcdefgh"
    assert pt[14:] == b"\x00" * (len(pt) - 14)  # zero padding, not PKCS#7


def test_encrypted_frame_pinned_bytes() -> None:
    """Frozen encrypted wire bytes for a fixed key+frame.  Any change to the
    encryption offset, zero-padding, checksum, or AES handling is caught here
    (a regression fixture; see audit findings #14/#20)."""
    expected = bytes.fromhex("1f00450201ab2ae9a1e8030000e9030000289b213cf9f1d72805d90900cf744013")
    assert _plain_hello().encode(key=KEY) == expected


def test_wrong_key_is_rejected() -> None:
    # A wrong key is caught by the dlen bounds check or the post-decrypt
    # checksum gate; it must never silently decode to the real frame.
    wire = _plain_hello().encode(key=KEY)
    try:
        decoded = Frame.decode(wire, key=bytes(16))  # all-zero key != KEY
    except ValueError:
        return  # rejected, as expected
    assert decoded.payload != b"abcdefgh"


def test_corrupt_ciphertext_caught_by_checksum() -> None:
    # A larger payload spans multiple ECB blocks; corrupting the LAST block
    # leaves dlen intact (no length overflow) but fails the embedded checksum
    # after decrypt.  The "encrypt bit set" checksum convention is verified
    # live against a real SPC4300.
    f = Frame(
        src_id=1000,
        dst_id=1001,
        sequence=1,
        major=int(MajorCode.XML_CMD),
        minor=int(MinorCode.REQUEST),
        payload=b"X" * 40,
        src_flag=0x08,
    )
    wire = bytearray(f.encode(key=KEY))
    wire[-1] ^= 0xFF
    with pytest.raises(ValueError, match="checksum mismatch"):
        Frame.decode(bytes(wire), key=KEY)


def test_decoder_streams_encrypted_frame_across_single_byte_reads() -> None:
    wire = _plain_hello().encode(key=KEY)
    d = FrameDecoder(key=KEY)
    out = []
    for b in wire:
        out += d.feed(bytes([b]))
    assert len(out) == 1
    assert out[0].payload == b"abcdefgh"


def test_decoder_resyncs_past_garbage_before_encrypted_frame() -> None:
    wire = _plain_hello().encode(key=KEY)
    d = FrameDecoder(key=KEY)
    out = d.feed(b"\x00\x00" + wire)
    assert len(out) == 1
    assert out[0].payload == b"abcdefgh"
