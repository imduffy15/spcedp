"""Property-based tests for SIA event parsing (campaign H3 / M4).

These hammer :meth:`SiaEvent.parse` with near-valid ``E2[...]`` payloads built
from an adversarial free-text alphabet (``|``, ``]``, newline, CR, non-ASCII,
up to ~10k chars) and mutated timestamps (month 13, hour 25). They lock the
post-fix contract from the roadmap (M2.5):

  * ``parse`` returns a ``SiaEvent`` or raises ``ValueError`` - never any
    other exception type.
  * an interior ``|`` in the free-text description never corrupts
    ``verification_id``: the trailing fixed fields are right-anchored, so a
    pipe-bearing description is absorbed and ``vid`` is the true trailing field.
  * an out-of-range timestamp yields ``timestamp=None`` while keeping the event
    (no silent drop on the safety path), and ``timestamp_raw`` is preserved
    verbatim.
  * a 10k-char adversarial input parses well under a wall-clock budget (no
    catastrophic regex backtracking).

The parser is synchronous, so these are plain (non-asyncio) tests.
"""

from __future__ import annotations

import time

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from spcedp.events import SiaEvent

# Adversarial free-text alphabet: the structural delimiters the parser keys on
# (``|`` and the closing ``]``), line terminators that the DOTALL/strip handling
# must tolerate, ASCII control/space, and a spread of non-ASCII codepoints.
_FREETEXT_ALPHABET = (
    "|]\n\r\t #ABCxyz09"
    "é"  # e-acute
    "ü"  # u-umlaut
    "€"  # euro sign
    "中"  # CJK
    "\U0001f4a3"  # bomb emoji (astral plane)
)

# A field that is a fixed (non-description) trailing/leading slot must not itself
# contain a literal pipe, otherwise it would legitimately shift the split; the
# round-trip property therefore draws those from a pipe-free alphabet. They may
# still carry ``]``, newline and non-ASCII to keep the test adversarial.
_PIPELESS_ALPHABET = "]\n\r\t #ABCxyz09é€中\U0001f4a3"

_freetext = st.text(alphabet=_FREETEXT_ALPHABET, max_size=200)
_pipeless = st.text(alphabet=_PIPELESS_ALPHABET, max_size=50)


def _build_payload(
    *,
    spc: str,
    ts: str,
    code: str,
    addr: str,
    desc: str,
    extra: str,
    vid: str,
) -> str:
    """Assemble a structurally well-formed ``E2[...]`` payload string."""
    return f"E2[#{spc}|{ts}|{code}|{addr}|{desc}|{extra}|{vid}]"


# --------------------------------------------------------------------------- #
# 1. parse() returns a SiaEvent or raises ValueError - never anything else.
# --------------------------------------------------------------------------- #


@settings(deadline=None, max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(
    spc=st.integers(min_value=0, max_value=10**9).map(str),
    ts=st.text(alphabet="0123456789", min_size=0, max_size=16),
    code=_freetext,
    addr=_freetext,
    desc=_freetext,
    extra=_freetext,
    vid=_freetext,
    trailing_ws=st.sampled_from(["", " ", "\r\n", "\t \n"]),
)
def test_parse_returns_event_or_value_error_only(
    spc: str,
    ts: str,
    code: str,
    addr: str,
    desc: str,
    extra: str,
    vid: str,
    trailing_ws: str,
) -> None:
    payload = _build_payload(spc=spc, ts=ts, code=code, addr=addr, desc=desc, extra=extra, vid=vid)
    payload += trailing_ws
    try:
        ev = SiaEvent.parse(payload)
    except ValueError:
        # The only permitted failure mode.
        return
    # If it parsed, it must be a SiaEvent with the invariants intact.
    assert isinstance(ev, SiaEvent)
    assert isinstance(ev.timestamp_raw, str)
    # timestamp is either a datetime or None (out-of-range), nothing else.
    assert ev.timestamp is None or hasattr(ev.timestamp, "year")
    # The envelope only matches with exactly 14 timestamp digits, so a parsed
    # event must carry exactly those 14 digits as timestamp_raw.
    assert ev.timestamp_raw == ts
    assert len(ev.timestamp_raw) == 14


@settings(deadline=None, max_examples=300, suppress_health_check=[HealthCheck.too_slow])
@given(blob=st.text(max_size=300))
def test_parse_arbitrary_text_never_raises_unexpected(blob: str) -> None:
    """Wholly arbitrary text: only ValueError (or a clean parse) is allowed."""
    try:
        ev = SiaEvent.parse(blob)
    except ValueError:
        return
    assert isinstance(ev, SiaEvent)


@settings(deadline=None, max_examples=200, suppress_health_check=[HealthCheck.too_slow])
@given(blob=st.binary(max_size=300))
def test_parse_arbitrary_bytes_never_raises_unexpected(blob: bytes) -> None:
    """Arbitrary bytes (incl. invalid UTF-8): decode is lossy, never crashes."""
    try:
        ev = SiaEvent.parse(blob)
    except ValueError:
        return
    assert isinstance(ev, SiaEvent)


# --------------------------------------------------------------------------- #
# 2. H3 - an interior pipe in the description never corrupts verification_id.
# --------------------------------------------------------------------------- #


@settings(deadline=None, max_examples=400, suppress_health_check=[HealthCheck.too_slow])
@given(
    code=_pipeless,
    addr=_pipeless,
    # The description deliberately contains pipes (and other free text); it is
    # the one field allowed to carry interior '|'.
    desc_parts=st.lists(_freetext, min_size=2, max_size=6),
    extra=_pipeless,
    vid=_pipeless,
)
def test_pipe_in_description_does_not_corrupt_trailing_fields(
    code: str,
    addr: str,
    desc_parts: list[str],
    extra: str,
    vid: str,
) -> None:
    """A description CONTAINING pipes must not bleed into extra / vid.

    The trailing fixed fields are right-anchored, so the true ``extra`` and
    ``verification_id`` are recovered exactly and the whole pipe-bearing
    description is absorbed into ``description``.
    """
    desc = "|".join(desc_parts)  # guaranteed to contain at least one '|'
    assert "|" in desc
    payload = _build_payload(
        spc="1000",
        ts="08521203062026",
        code=code,
        addr=addr,
        desc=desc,
        extra=extra,
        vid=vid,
    )
    ev = SiaEvent.parse(payload)
    assert ev.sia_code == code
    assert ev.address == addr
    assert ev.description == desc
    assert ev.extra == extra
    # The crux: the trailing verification_id is the true last field, never a
    # fragment of the piped description.
    assert ev.verification_id == vid


def test_known_piped_description_vid_is_true_trailing_field() -> None:
    """A concrete, hand-built piped-description payload (H3 regression).

    ``vid`` must equal the literal trailing field, not the text that happens to
    sit after the first interior pipe of the description.
    """
    payload = "E2[#1000|08521203062026|BA|3|Zone 3 | Lobby | front door|metadata|99]"
    ev = SiaEvent.parse(payload)
    assert ev.sia_code == "BA"
    assert ev.address == "3"
    assert ev.description == "Zone 3 | Lobby | front door"
    assert ev.extra == "metadata"
    assert ev.verification_id == "99"
    # And it certainly did not collapse to one of the interior fragments.
    assert ev.verification_id != "Lobby "
    assert ev.verification_id != " front door"


def test_piped_description_with_minimal_trailing_fields() -> None:
    """Pipes in the description with empty extra/vid still right-anchor."""
    payload = "E2[#1000|08521203062026|FA|0|a|b|c|d||]"
    ev = SiaEvent.parse(payload)
    # desc absorbs "a|b|c|d"; extra and vid are the two empty trailing slots.
    assert ev.description == "a|b|c|d"
    assert ev.extra == ""
    assert ev.verification_id == ""


# --------------------------------------------------------------------------- #
# 3. M4 - out-of-range timestamps keep the event and preserve timestamp_raw.
# --------------------------------------------------------------------------- #

# 14-char HHMMSSDDMMYYYY strings that are syntactically valid (all digits) but
# semantically out of range, so dt.datetime() rejects them.
_OUT_OF_RANGE_TIMESTAMPS = [
    "08521203132026",  # month 13
    "25521203062026",  # hour 25
    "08991203062026",  # minute 99
    "08529903062026",  # second 99
    "08521299062026",  # day 99
    "00000000000000",  # year 0 / month 0 / day 0
    "99999999999999",  # everything maxed
    "08520003002026",  # month 00, day 00
]


@given(
    ts=st.sampled_from(_OUT_OF_RANGE_TIMESTAMPS),
    code=st.sampled_from(["BA", "FA", "PA", "NT", "ZO"]),
    desc=_freetext,
)
@settings(deadline=None, max_examples=120, suppress_health_check=[HealthCheck.too_slow])
def test_out_of_range_timestamp_keeps_event_and_preserves_raw(
    ts: str, code: str, desc: str
) -> None:
    payload = _build_payload(spc="1000", ts=ts, code=code, addr="0", desc=desc, extra="", vid="0")
    ev = SiaEvent.parse(payload)
    # The event is KEPT (never silently dropped) ...
    assert isinstance(ev, SiaEvent)
    assert ev.sia_code == code
    assert ev.description == desc
    # ... with no usable datetime ...
    assert ev.timestamp is None
    # ... and the raw 14-char string preserved verbatim for diagnostics.
    assert ev.timestamp_raw == ts


def test_in_range_timestamp_round_trips() -> None:
    """Sanity anchor: an in-range timestamp does produce a datetime."""
    ev = SiaEvent.parse("E2[#1000|08521203062026|BA|0|Burglar||0]")
    assert ev.timestamp is not None
    assert ev.timestamp.year == 2026
    assert ev.timestamp.month == 6
    assert ev.timestamp.day == 3
    assert ev.timestamp.hour == 8
    assert ev.timestamp_raw == "08521203062026"


# --------------------------------------------------------------------------- #
# 4. No catastrophic backtracking on a large adversarial input.
# --------------------------------------------------------------------------- #


def test_huge_adversarial_input_parses_within_budget() -> None:
    """A ~10k-char description full of pipes/brackets must parse fast.

    A linear right-anchored split has no pathological blow-up; a runaway regex
    would. Guard with a generous wall-clock budget that a quadratic/exponential
    path would blow through while a linear one finishes in microseconds. The
    budget is large enough to never flake on a slow CI box.
    """
    desc = ("Zone | " * 1400)[:10000]  # ~10k chars, dense with interior pipes
    assert len(desc) >= 9000
    assert "|" in desc
    payload = _build_payload(
        spc="1000",
        ts="08521203062026",
        code="BA",
        addr="0",
        desc=desc,
        extra="meta",
        vid="42",
    )
    start = time.perf_counter()
    ev = SiaEvent.parse(payload)
    elapsed = time.perf_counter() - start
    assert ev.verification_id == "42"
    assert ev.extra == "meta"
    assert ev.description == desc
    assert elapsed < 2.0, f"parse of 10k-char input took {elapsed:.3f}s (backtracking?)"


def test_huge_non_matching_input_fails_fast() -> None:
    """A 10k-char *non-matching* blob (no envelope) raises ValueError fast.

    A missing closing bracket on a long pipe-dense string is the classic
    backtracking trap for a greedy ``.*\\]$`` pattern; assert it still resolves
    well under budget.
    """
    blob = "E2[#1000|08521203062026|BA|0|" + ("x|" * 5000)  # no closing ']'
    start = time.perf_counter()
    try:
        SiaEvent.parse(blob)
        raised = False
    except ValueError:
        raised = True
    elapsed = time.perf_counter() - start
    assert raised
    assert elapsed < 2.0, f"non-matching parse took {elapsed:.3f}s (backtracking?)"


@settings(
    deadline=None,
    max_examples=80,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.large_base_example],
)
@given(
    # A hypothesis-grown adversarial seed, then deterministically inflated to
    # ~10k chars by repetition so every example exercises the long-input path
    # without overwhelming the data generator's entropy budget.
    seed=st.text(alphabet=_FREETEXT_ALPHABET, min_size=1, max_size=120),
    reps=st.integers(min_value=80, max_value=400),
)
def test_large_freetext_description_parses(seed: str, reps: int) -> None:
    """Large free-text descriptions (~up to 10k chars) parse to a SiaEvent or
    ValueError, never another exception, and within a wall-clock budget."""
    filler = (seed * reps)[:10000]
    payload = _build_payload(
        spc="1000",
        ts="08521203062026",
        code="BA",
        addr="0",
        desc=filler,
        extra="",
        vid="0",
    )
    start = time.perf_counter()
    try:
        ev = SiaEvent.parse(payload)
    except ValueError:
        ev = None
    elapsed = time.perf_counter() - start
    assert elapsed < 3.0, f"large freetext parse took {elapsed:.3f}s"
    if ev is not None:
        assert isinstance(ev, SiaEvent)
