"""B1 / M0.1 - the false large length-prefix wedge.

A malformed (or maliciously crafted) 2-byte length prefix that carries valid
EDP magic but claims a frame far larger than will ever arrive must never wedge
the stream decoder.  The historical bug: ``feed()`` would buffer forever while
``_dropped`` stayed 0, so ``RESYNC_LIMIT`` never fired and the session went
mute-but-alive - real POLLs and events queued behind the phantom frame were
never delivered and the idle timeout never tripped (a silent, indefinite
stall).

These tests drive ``FrameDecoder`` directly (no socket) and assert the
*post-fix* behaviour from the roadmap: the decoder either resyncs and delivers
the real frames within a bounded byte budget, or fails fast with a
``FrameDecodeError`` - it never stalls and never silently drops a real frame.

Two distinct phantom-prefix regimes are exercised:

  * "large-but-plausible" (``total <= MAX_PLAUSIBLE_FRAME``): the header looks
    valid, so the decoder waits - but the wait is *bounded* by ``RESYNC_LIMIT``
    bytes-since-anchor, after which it resyncs past the suspect prefix.
  * "just-over-plausible" (``total > MAX_PLAUSIBLE_FRAME``): the header is
    rejected by ``looks_valid`` immediately, so the decoder resyncs at once
    without ever waiting on the phantom byte count.
"""

from __future__ import annotations

import struct

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from spcedp.wire import (
    HEADER_LEN,
    MAX_PLAUSIBLE_FRAME,
    PROTOCOL_BYTE,
    PROTOCOL_VERSION,
    RESYNC_LIMIT,
    Frame,
    FrameDecodeError,
    FrameDecoder,
    MajorCode,
    MinorCode,
)

# A real POLL frame captured live from an SPC4300 panel (see tests/test_wire.py).
# 31 bytes on the wire: 2-byte length prefix (rem=0x1d) + 23-byte header + 8-byte
# payload.  This is the genuine frame the decoder must keep delivering even after
# a phantom prefix has tried to wedge the stream.


def _h(s: str) -> bytes:
    return bytes.fromhex(s.replace(" ", ""))


POLL_PANEL_TO_RX = _h(
    "1d 00  45 02  00  ab 2a e9 a1  e8 03 00 00  e9 03 00 00  01 00  11 ca  08 00"
    "  c5 b7 92 fc 53 4b 57 a3"
)
REAL_POLL_SEQ = 0xA1E92AAB
REAL_POLL_LEN = len(POLL_PANEL_TO_RX)


def _phantom_prefix(rem: int) -> bytes:
    """A 4-byte stream start: a valid EDP magic header claiming ``rem`` bytes.

    Only the length prefix and the magic (protocol/version) bytes are present;
    the rest of the claimed frame never follows.  This is exactly what
    ``MockPanel.send_frame_with_bad_length`` / a corrupt-prefix MITM put on the
    wire, reduced to the minimum the decoder inspects."""
    return struct.pack("<H", rem & 0xFFFF) + bytes([PROTOCOL_BYTE, PROTOCOL_VERSION])


def _assert_real_poll(frame: Frame) -> None:
    assert frame.major == MajorCode.SESSION
    assert frame.minor == MinorCode.POLL
    assert frame.sequence == REAL_POLL_SEQ
    assert frame.payload.hex() == "c5b792fc534b57a3"


# --------------------------------------------------------------------------- #
# Scenario A: large-but-plausible phantom prefix, then a trickle of real POLLs #
# --------------------------------------------------------------------------- #


def test_plausible_phantom_prefix_then_polls_does_not_stall() -> None:
    """A phantom prefix claiming a large-but-plausible frame (total within
    MAX_PLAUSIBLE_FRAME) must not swallow the real POLLs that follow.

    The decoder waits while the header still looks valid, but the wait is
    bounded: once more than RESYNC_LIMIT bytes have piled up behind the phantom
    prefix it resyncs past it and delivers every real POLL.  Pre-fix this fed
    forever and delivered nothing."""
    # rem chosen so total == 16002, comfortably <= MAX_PLAUSIBLE_FRAME (16384):
    # the header looks valid, so the decoder enters the *bounded wait* path
    # rather than rejecting it outright (that is exercised in scenario B).
    rem = 16000
    assert rem + 2 <= MAX_PLAUSIBLE_FRAME

    d = FrameDecoder()
    # The 4-byte phantom prefix alone is below HEADER_LEN, so nothing decodes yet.
    assert d.feed(_phantom_prefix(rem)) == []

    # Feed enough real POLLs that the accumulated bytes exceed the wait budget,
    # forcing the resync. One POLL more than RESYNC_LIMIT/POLL_LEN guarantees it.
    n_polls = (RESYNC_LIMIT // REAL_POLL_LEN) + 5
    delivered = []
    for _ in range(n_polls):
        delivered.extend(d.feed(POLL_PANEL_TO_RX))

    # Every real POLL was surfaced (none silently dropped) and the buffer drained.
    assert len(delivered) == n_polls
    for f in delivered:
        _assert_real_poll(f)
    assert len(d._buf) == 0
    # Decoding a whole frame resets the resync budget, so it ends clean.
    assert d._dropped == 0


def test_plausible_phantom_prefix_byte_trickle_loses_no_real_frame() -> None:
    """The same wedge, but driven as a true byte-at-a-time trickle through
    ``feed`` (the pathological TCP segmentation the bug needed to hide).

    Asserts the safety-critical invariant directly: not a single real POLL is
    lost, the call always returns (never stalls), and the internal buffer stays
    bounded near RESYNC_LIMIT rather than growing without limit."""
    rem = 16000
    d = FrameDecoder()
    delivered = []
    delivered.extend(d.feed(_phantom_prefix(rem)))

    n_polls = 300
    stream = POLL_PANEL_TO_RX * n_polls
    max_buf = 0
    for byte in stream:
        delivered.extend(d.feed(bytes([byte])))
        max_buf = max(max_buf, len(d._buf))

    # No real frame lost despite the resync that walks past the phantom prefix.
    assert len(delivered) == n_polls
    for f in delivered:
        _assert_real_poll(f)
    # Bounded budget: the buffer never grew beyond the wait window plus one frame.
    assert max_buf <= RESYNC_LIMIT + REAL_POLL_LEN + HEADER_LEN
    assert len(d._buf) == 0


def test_plausible_phantom_prefix_with_no_data_does_not_raise() -> None:
    """A plausible-looking but never-completed header on its own must simply
    park (return ``[]``) - it is a legitimately incomplete frame until proven
    otherwise.  It must not raise and must not have dropped anything yet."""
    d = FrameDecoder()
    # A full header's worth of bytes claiming a plausible total that never arrives.
    header = _phantom_prefix(16000) + b"\x00" * (HEADER_LEN - 4)
    assert d.feed(header) == []
    assert d._dropped == 0  # still waiting, nothing dropped
    assert len(d._buf) == len(header)


# --------------------------------------------------------------------------- #
# Scenario B: prefix just over MAX_PLAUSIBLE_FRAME resyncs immediately         #
# --------------------------------------------------------------------------- #


def test_just_over_plausible_prefix_resyncs_immediately() -> None:
    """A prefix whose claimed total is just over MAX_PLAUSIBLE_FRAME is rejected
    by ``looks_valid`` at once - the decoder never waits on the phantom byte
    count, it resyncs straight past the bad prefix and delivers the following
    real POLL with no buffering delay."""
    # total = MAX_PLAUSIBLE_FRAME + 1: the smallest "just over" value.
    rem = MAX_PLAUSIBLE_FRAME - 1
    assert rem + 2 > MAX_PLAUSIBLE_FRAME

    d = FrameDecoder()
    out = d.feed(_phantom_prefix(rem) + POLL_PANEL_TO_RX)

    # The single real POLL is delivered straight away (no wait, no stall).
    assert len(out) == 1
    _assert_real_poll(out[0])
    assert len(d._buf) == 0
    # The 4 phantom bytes were resynced past, then the frame decoded cleanly.
    assert d._dropped == 0


def test_just_over_plausible_prefix_does_not_wait_for_phantom_bytes() -> None:
    """Once a full header is buffered, a just-over claim must be rejected by
    ``looks_valid`` and resynced immediately rather than parked to wait for the
    (16385-byte) frame it falsely claims.

    A sub-header buffer (<HEADER_LEN bytes) is genuinely undecidable - the magic
    region is not yet complete - so the decoder correctly parks there; the
    over-large rejection only applies once a whole header is in hand."""
    rem = MAX_PLAUSIBLE_FRAME - 1
    d = FrameDecoder()
    # A complete 23-byte header (over-large rem + valid magic + filler) but no
    # claimed body. ``looks_valid`` is False (total > MAX_PLAUSIBLE_FRAME), so
    # the decoder must resync (drop bytes) at once, not wait on phantom bytes.
    header = _phantom_prefix(rem) + b"\x00" * (HEADER_LEN - 4)
    out = d.feed(header)
    assert out == []
    # The bytes were resynced past (dropped), never stashed awaiting a frame
    # that will never complete. _dropped advanced; the wait anchor never armed.
    assert d._dropped > 0
    assert d._wait_total is None


# --------------------------------------------------------------------------- #
# Fail-fast guard: a sustained over-large garbage run raises, never stalls     #
# --------------------------------------------------------------------------- #


def test_sustained_oversized_garbage_fails_fast() -> None:
    """A phantom over-large prefix followed by a long garbage run that never
    yields a decodable frame must raise ``FrameDecodeError`` once the resync
    budget is exhausted - failing loud and bounded rather than dropping bytes
    forever into an idle timeout."""
    over_prefix = _phantom_prefix(MAX_PLAUSIBLE_FRAME)  # total > MAX_PLAUSIBLE_FRAME
    d = FrameDecoder()
    with pytest.raises(FrameDecodeError, match="resyncing"):
        d.feed(over_prefix + b"\x00" * (RESYNC_LIMIT + 50))


def test_plausible_phantom_then_garbage_fails_fast_not_stall() -> None:
    """A large-but-plausible phantom prefix followed only by undecodable garbage
    (no real frame ever arrives) must also terminate: the bounded wait trips the
    resync, and the resync budget then trips a ``FrameDecodeError``. The one
    outcome that must never happen is a silent indefinite stall."""
    d = FrameDecoder()
    d.feed(_phantom_prefix(16000))
    # Enough garbage to blow past both the wait window and the resync budget.
    with pytest.raises(FrameDecodeError, match="resyncing"):
        d.feed(b"\xee" * (RESYNC_LIMIT * 2 + HEADER_LEN))


# --------------------------------------------------------------------------- #
# Property: any phantom prefix + interleaved real POLLs delivers every POLL    #
# --------------------------------------------------------------------------- #


@settings(deadline=None, max_examples=150, suppress_health_check=[HealthCheck.too_slow])
@given(
    # rem from "just plausible enough to wait" up to well over the cap, so both
    # the bounded-wait and immediate-resync regimes are sampled.
    rem=st.integers(min_value=HEADER_LEN, max_value=0xFFFF),
    n_polls=st.integers(min_value=1, max_value=12),
    chunk=st.integers(min_value=1, max_value=64),
)
def test_phantom_prefix_never_swallows_real_polls(rem: int, n_polls: int, chunk: int) -> None:
    """For any phantom-prefix length and any number of trailing real POLLs fed in
    arbitrary chunk sizes, the decoder must surface every real POLL within a
    bounded byte budget (or raise FrameDecodeError) - never a stall, never a
    silently dropped real frame.

    To keep the byte budget bounded for *plausible* phantom prefixes we follow
    the prefix with enough real POLLs to cross the wait window so the resync is
    guaranteed to fire within this example."""
    # Pad the real-POLL run so plausible phantoms are guaranteed to resync within
    # the example (>RESYNC_LIMIT bytes behind the prefix). Over-cap phantoms
    # resync immediately regardless, so this only ever adds, never hides, frames.
    pad_to_cross = (RESYNC_LIMIT // REAL_POLL_LEN) + 2
    total_polls = n_polls + pad_to_cross

    stream = _phantom_prefix(rem) + POLL_PANEL_TO_RX * total_polls

    d = FrameDecoder()
    delivered = []
    max_buf = 0
    try:
        for i in range(0, len(stream), chunk):
            delivered.extend(d.feed(stream[i : i + chunk]))
            max_buf = max(max_buf, len(d._buf))
    except FrameDecodeError:
        # Failing fast is an acceptable, non-stalling outcome; the contract is
        # only that the decoder never wedges. Whatever it delivered before the
        # raise must still be genuine POLLs.
        for f in delivered:
            _assert_real_poll(f)
        return

    # No raise: every real POLL must have been delivered intact, and the buffer
    # must have stayed bounded (it never grows past the wait window + a frame).
    assert len(delivered) == total_polls
    for f in delivered:
        _assert_real_poll(f)
    assert max_buf <= RESYNC_LIMIT + REAL_POLL_LEN + HEADER_LEN + chunk
