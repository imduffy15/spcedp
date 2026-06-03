"""Property-based wire-format tests (campaign A.2).

These assert the post-fix wire contract from the GA roadmap (M0.1, M1.3,
M1.4) and the EDP checksum invariants:

* ``Frame.encode`` -> ``Frame.decode`` round-trips field-for-field for both
  cleartext (``key=None``) and encrypted (``key=KEY``) frames, and the
  encrypted flag is cleared on decode.
* ``edp_checksum`` is deterministic and independent of the two bytes that
  sit in the checksum slot (offsets 0x11/0x12).
* ``FrameDecoder.feed`` over arbitrary byte streams sliced into arbitrary
  chunks raises ONLY ``FrameDecodeError`` / ``EncryptionRequired``, always
  terminates, and never wedges: the buffer is bounded and the decoder is
  never left waiting on a frame whose claimed total exceeds
  ``MAX_PLAUSIBLE_FRAME`` (the M0.1 wedge that previously stalled forever).
* Boundary payload sizes near 0xFFFF round-trip via the unbounded
  ``Frame.decode`` path; a payload >= 0x10000 raises ``ValueError`` (typed,
  M1.4 — not a raw ``struct.error``); and any frame ``encode()`` emits whose
  ``total`` is plausible is accepted by a fresh ``FrameDecoder.feed``.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from spcedp.wire import (
    _CSUM_OFFSET_HIGH,
    _CSUM_OFFSET_LOW,
    FLAG_ENCRYPTED,
    HEADER_LEN,
    MAX_PLAUSIBLE_FRAME,
    RESYNC_LIMIT,
    EncryptionRequired,
    Frame,
    FrameDecodeError,
    FrameDecoder,
    MajorCode,
    edp_checksum,
)

pytestmark = []

# A fixed 16-byte test key; the AES layout is reverse-engineered and frozen,
# so this never changes a wire byte — it only exercises the encrypt/decrypt path.
KEY = bytes(range(16))

# rem (the 16-bit remaining-length field) == len(struct_bytes) == 21 + len(payload):
# the 23-byte header minus the 2-byte cleartext length prefix, plus the payload.
# So encode() accepts payloads up to 0xFFFF - 21 == 0xFFEA cleartext.
_HEADER_STRUCT_LEN = HEADER_LEN - 2  # 21
MAX_CLEARTEXT_PAYLOAD = 0xFFFF - _HEADER_STRUCT_LEN  # 0xFFEA

# Only frames whose total wire size is "plausible" are accepted by a live
# FrameDecoder; larger valid frames are intentionally rejected as a wedge guard
# (M0.1). Keep generated round-trip-via-feed payloads under that bound.
_MAX_FEED_PAYLOAD = MAX_PLAUSIBLE_FRAME - HEADER_LEN - 1

_u32 = st.integers(min_value=0, max_value=0xFFFFFFFF)
_u8 = st.integers(min_value=0, max_value=0xFF)


def _frames(*, max_payload: int) -> st.SearchStrategy[Frame]:
    return st.builds(
        Frame,
        src_id=_u32,
        dst_id=_u32,
        sequence=_u32,
        major=_u8,
        minor=_u8,
        payload=st.binary(max_size=max_payload),
    )


# --- 1. encode -> decode round-trip --------------------------------------


@settings(deadline=None, max_examples=300)
@given(frame=_frames(max_payload=512))
def test_roundtrip_cleartext(frame: Frame) -> None:
    decoded = Frame.decode(frame.encode())
    assert decoded.src_id == frame.src_id
    assert decoded.dst_id == frame.dst_id
    assert decoded.sequence == frame.sequence
    assert decoded.major == frame.major
    assert decoded.minor == frame.minor
    assert decoded.payload == frame.payload
    # Cleartext frame: encrypted flag never set on decode.
    assert decoded.src_flag & FLAG_ENCRYPTED == 0


@settings(deadline=None, max_examples=300)
@given(frame=_frames(max_payload=512))
def test_roundtrip_encrypted(frame: Frame) -> None:
    wire = frame.encode(KEY)
    decoded = Frame.decode(wire, KEY)
    assert decoded.src_id == frame.src_id
    assert decoded.dst_id == frame.dst_id
    assert decoded.sequence == frame.sequence
    assert decoded.major == frame.major
    assert decoded.minor == frame.minor
    assert decoded.payload == frame.payload
    # decode() clears the encrypted flag bit on the returned frame.
    assert decoded.src_flag & FLAG_ENCRYPTED == 0
    # The encrypted region (struct offsets 15+, == wire offsets 17+) is
    # AES-128-ECB and therefore a whole number of 16-byte blocks.
    assert (len(wire) - HEADER_LEN + (HEADER_LEN - 17)) % 16 == 0
    assert (len(wire) - 17) % 16 == 0


@settings(deadline=None, max_examples=200)
@given(frame=_frames(max_payload=_MAX_FEED_PAYLOAD))
def test_encode_output_accepted_by_fresh_decoder_cleartext(frame: Frame) -> None:
    """Any plausible-sized frame encode() emits is accepted by a fresh
    FrameDecoder.feed() and decodes back to the same fields (M1.3)."""
    out = FrameDecoder().feed(frame.encode())
    assert len(out) == 1
    assert out[0].payload == frame.payload
    assert out[0].sequence == frame.sequence
    assert out[0].major == frame.major


@settings(deadline=None, max_examples=200)
@given(frame=_frames(max_payload=_MAX_FEED_PAYLOAD - 16))
def test_encode_output_accepted_by_fresh_decoder_encrypted(frame: Frame) -> None:
    out = FrameDecoder(KEY).feed(frame.encode(KEY))
    assert len(out) == 1
    assert out[0].payload == frame.payload
    assert out[0].sequence == frame.sequence


# --- 2. boundary payload sizes near 0xFFFF (M1.3 / M1.4) ------------------


@pytest.mark.parametrize("payload_len", [0xFFE8, 0xFFE9, 0xFFEA])
def test_roundtrip_near_max_payload(payload_len: int) -> None:
    """rem in {0xFFFD..0xFFFF}: these encode and decode field-for-field via
    the (unbounded) Frame.decode path. They exceed MAX_PLAUSIBLE_FRAME, so a
    live FrameDecoder intentionally would not accept them — that is the wedge
    guard, tested separately."""
    frame = Frame(
        src_id=0x11223344,
        dst_id=0x55667788,
        sequence=0xDEADBEEF,
        major=int(MajorCode.XML_CMD),
        minor=0,
        payload=b"q" * payload_len,
    )
    wire = frame.encode()
    rem = struct.unpack_from("<H", wire, 0)[0]
    assert rem <= 0xFFFF
    assert rem == _HEADER_STRUCT_LEN + payload_len
    decoded = Frame.decode(wire)
    assert decoded.payload == frame.payload
    assert decoded.sequence == frame.sequence
    assert decoded.src_id == frame.src_id
    assert decoded.dst_id == frame.dst_id


def test_encode_just_over_frame_limit_raises_valueerror() -> None:
    # payload 0xFFEB pushes rem past 0xFFFF: typed ValueError, not struct.error.
    frame = Frame(src_id=1, dst_id=2, sequence=0, major=10, minor=0, payload=b"x" * 0xFFEB)
    with pytest.raises(ValueError, match="too large"):
        frame.encode()


def test_encode_payload_ge_0x10000_raises_valueerror_not_structerror() -> None:
    """M1.4: a >= 0x10000 payload raises a typed ValueError before struct.pack
    can raise a raw struct.error."""
    frame = Frame(src_id=1, dst_id=2, sequence=0, major=10, minor=0, payload=b"x" * 0x10000)
    with pytest.raises(ValueError, match="payload too large"):
        frame.encode()
    # struct.error subclasses Exception but NOT ValueError; assert the typed
    # contract holds rather than the raw struct overflow leaking out.
    assert not isinstance(struct.error(), ValueError)


# --- 3. edp_checksum invariants ------------------------------------------


def _struct_bytes(payload: bytes) -> bytes:
    """Build the in-memory frame struct (wire bytes minus the 2-byte prefix)
    with a zeroed checksum slot, mirroring Frame.encode()."""
    body = struct.pack(
        "<BBBIIIBBHH",
        0x45,  # PROTOCOL_BYTE
        0x02,  # PROTOCOL_VERSION
        0x00,  # src_flag
        0x01020304,  # sequence
        1000,  # src_id
        1001,  # dst_id
        0x0A,  # major
        0x00,  # minor
        0,  # checksum slot
        len(payload),  # dlen
    )
    return body + payload


@settings(deadline=None, max_examples=300)
@given(payload=st.binary(max_size=2048))
def test_checksum_deterministic(payload: bytes) -> None:
    sb = _struct_bytes(payload)
    dlen = len(payload)
    first = edp_checksum(sb, dlen)
    assert edp_checksum(sb, dlen) == first  # same input -> same output
    assert 0 <= first <= 0xFFFF


@settings(deadline=None, max_examples=300)
@given(payload=st.binary(max_size=2048), fill=_u8, fill2=_u8)
def test_checksum_ignores_csum_slot_bytes(payload: bytes, fill: int, fill2: int) -> None:
    """The two bytes in the checksum slot (struct offsets 0x11/0x12) are
    skipped during iteration, so mutating them does not change the result
    (pins the skip-the-slot loop in edp_checksum)."""
    sb = bytearray(_struct_bytes(payload))
    dlen = len(payload)
    baseline = edp_checksum(bytes(sb), dlen)
    sb[_CSUM_OFFSET_LOW] = fill
    sb[_CSUM_OFFSET_HIGH] = fill2
    assert edp_checksum(bytes(sb), dlen) == baseline


def test_checksum_rejects_short_input() -> None:
    with pytest.raises(ValueError, match="too short"):
        edp_checksum(b"\x00" * 4, dlen=100)


# --- 4. decoder fuzz: bounded, terminating, narrow exception set ----------

_TERMINATION_GUARD = 50_000  # any single feed() must settle well under this


@settings(deadline=None, max_examples=500)
@given(data=st.binary(max_size=8192), chunk=st.integers(min_value=1, max_value=512))
def test_feed_arbitrary_stream_keyless(data: bytes, chunk: int) -> None:
    _drive_decoder(data, chunk, key=None)


@settings(deadline=None, max_examples=500)
@given(data=st.binary(max_size=8192), chunk=st.integers(min_value=1, max_value=512))
def test_feed_arbitrary_stream_keyed(data: bytes, chunk: int) -> None:
    _drive_decoder(data, chunk, key=KEY)


def _drive_decoder(data: bytes, chunk: int, *, key: bytes | None) -> None:
    """Feed `data` to one FrameDecoder in `chunk`-sized slices.

    Asserts:
    * feed() only ever raises FrameDecodeError / EncryptionRequired (never
      IndexError, struct.error, or a cryptography error);
    * each feed() call terminates (bounded loop count guard);
    * the wedge invariant: the decoder is never left waiting on a frame whose
      claimed total exceeds MAX_PLAUSIBLE_FRAME, and the retained buffer stays
      bounded (< the unconsumed input it has seen + RESYNC_LIMIT).
    """
    dec = FrameDecoder(key)
    fed = 0
    for i in range(0, len(data), chunk):
        piece = data[i : i + chunk]
        fed += len(piece)
        try:
            dec.feed(piece)
        except FrameDecodeError, EncryptionRequired:
            # Recoverable/observable failure; the decoder may keep going or be
            # abandoned. Either way it did not hang or raise a foreign type.
            return
        # feed() returned: it terminated. Now assert the no-wedge invariant.
        _assert_not_wedged(dec, fed)


def _assert_not_wedged(dec: FrameDecoder, fed: int) -> None:
    buf = dec._buf
    # The retained buffer must be bounded: feed() consumes or resyncs past
    # everything except at most one in-progress frame, so it can never grow
    # beyond what has been fed plus the resync slack.
    assert len(buf) <= fed
    assert len(buf) < _TERMINATION_GUARD
    if len(buf) < HEADER_LEN:
        return
    rem = struct.unpack_from("<H", buf, 0)[0]
    total = rem + 2
    looks_valid = (
        total >= HEADER_LEN
        and rem <= 0xFFFF
        and buf[2] == 0x45  # PROTOCOL_BYTE
        and buf[3] == 0x02  # PROTOCOL_VERSION
    )
    # WEDGE DETECTOR (M0.1): if the head looks like a real frame and is being
    # waited on (not yet complete), its claimed total must be plausible. A
    # buffered, valid-looking, incomplete header claiming more than
    # MAX_PLAUSIBLE_FRAME is exactly the stall that wedged feed() forever.
    if looks_valid and len(buf) < total:
        assert total <= MAX_PLAUSIBLE_FRAME, (
            f"decoder wedged: waiting on a frame claiming {total} bytes "
            f"(> MAX_PLAUSIBLE_FRAME={MAX_PLAUSIBLE_FRAME})"
        )


def test_phantom_large_prefix_does_not_wedge() -> None:
    """Concrete M0.1 regression: a valid-magic header claiming a huge total,
    followed by trickling real POLLs, must NOT stall — the decoder resyncs
    and surfaces the embedded valid frames within a bounded byte budget."""
    # A real POLL captured from an SPC4300 (cleartext).
    poll = bytes.fromhex(
        "1d004502 00ab2ae9 a1e80300 00e90300 000100 11ca 0800c5b792fc534b57a3".replace(" ", "")
    )
    # Phantom prefix: valid magic, plausible-magic bytes, but a claimed rem of
    # 50000 (total 50002 > MAX_PLAUSIBLE_FRAME). Followed by real POLLs.
    phantom = struct.pack("<H", 50000) + bytes([0x45, 0x02]) + b"\x00" * 19
    stream = phantom + poll * 200

    dec = FrameDecoder()
    delivered: list[Frame] = []
    # Feed byte-by-byte to model the trickle; the wedge bug delivered zero
    # frames while bytes arrived. Post-fix the phantom prefix is rejected
    # immediately (total > MAX_PLAUSIBLE_FRAME) and real POLLs come through.
    for i in range(0, len(stream), 64):
        delivered.extend(dec.feed(stream[i : i + 64]))
        # Buffer must never blow past a bounded window.
        assert len(dec._buf) < MAX_PLAUSIBLE_FRAME + len(poll)
    assert len(delivered) >= 1
    assert all(f.minor == 0 for f in delivered)  # POLL


def test_interleaved_garbage_yields_every_embedded_frame() -> None:
    """Valid frames separated by garbage are each emitted exactly once."""
    poll = bytes.fromhex(
        "1d004502 00ab2ae9 a1e80300 00e90300 000100 11ca 0800c5b792fc534b57a3".replace(" ", "")
    )
    # Garbage that is short and resyncable (kept well under RESYNC_LIMIT).
    garbage = b"\x00\x01\x02\x03"
    stream = garbage + poll + garbage + poll + garbage + poll
    dec = FrameDecoder()
    out: list[Frame] = []
    for i in range(0, len(stream), 7):
        out.extend(dec.feed(stream[i : i + 7]))
    assert len(out) == 3
    assert all(f.sequence == 0xA1E92AAB for f in out)


def test_feed_resync_limit_raises_framedecodeerror() -> None:
    """A long unrecoverable run fails fast with FrameDecodeError (bounded by
    RESYNC_LIMIT) rather than silently dropping bytes to an idle timeout."""
    dec = FrameDecoder()
    with pytest.raises(FrameDecodeError, match="resyncing"):
        dec.feed(b"\x00" * (RESYNC_LIMIT + 1000))
