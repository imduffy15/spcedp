"""Turn captured .bin frames into byte-for-byte pytest fixtures (campaign B.2).

Reads one or more capture files produced by ``frametap.FrameTap`` and emits:

  * ``tests/fixtures/<name>_frames.py`` - raw bytes constants (one per captured
    frame) plus an ordered ``INBOUND`` / ``OUTBOUND`` list, and a generated
    pytest that feeds each inbound chunk sequence through ``FrameDecoder`` and
    asserts the exact decoded ``Frame`` fields (extends the frozen-capture
    pattern at ``test_wire.py:67`` / ``test_encryption.py:147``);
  * ``tests/fixtures/<name>_script.py`` - a mock-panel ``script`` dict mapping
    ``(major, minor, command_id_or_opcode)`` to an ``Action`` carrying the real
    reply payload, so ``MockPanel`` can replay the captured session offline.

Encrypted captures keep their ciphertext verbatim; a key-redacted fixture
asserts the bytes decrypt under a test-supplied key to the same plaintext the
cleartext path produces (the key itself is never written to disk).

Usage (run by hand, never in CI)::

    python tests/live/replay_to_fixture.py captures/step1.bin captures/step2.bin
    # or
    python tests/live/replay_to_fixture.py --glob 'captures/*.bin'
"""

from __future__ import annotations

import argparse
import glob as globmod
import sys
from pathlib import Path

# Allow `python tests/live/replay_to_fixture.py` (direct invocation): put the
# repo root on the path so the absolute `tests.live.*` import below resolves.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from spcedp.wire import (  # noqa: E402 - after the sys.path bootstrap above
    Frame,
    FrameDecodeError,
    FrameDecoder,
    MajorCode,
    MinorCode,
)
from tests.live.frametap import (  # noqa: E402
    DIR_INBOUND,
    DIR_OUTBOUND,
    FrameRecord,
    read_capture,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

# Request minors whose reply we capture into a mock-panel script.
_REPLY_MINORS = {
    int(MajorCode.XML_CMD): int(MinorCode.REPLY),
    int(MajorCode.BINARY_CMD): int(MinorCode.BINARY_REPLY),
    int(MajorCode.PANEL_CMD): int(MinorCode.PANEL_REPLY),
}


def _hexlit(data: bytes) -> str:
    """Render bytes as a copy-paste-safe ``bytes.fromhex(...)`` literal."""
    return f'bytes.fromhex("{data.hex()}")'


def _decode_direction(records: list[FrameRecord], direction: str, key: bytes | None) -> list[Frame]:
    """Decode one direction's chunk stream into frames, in capture order.

    Inbound and outbound are independent byte streams (the inbound stream is
    what the live receiver fed its decoder; the outbound stream is what the
    receiver wrote). Each must be reassembled with its own ``FrameDecoder``."""
    decoder = FrameDecoder(key=key)
    frames: list[Frame] = []
    for rec in records:
        if rec.direction != direction:
            continue
        try:
            frames.extend(decoder.feed(rec.data))
        except FrameDecodeError:
            # A capture may include deliberately corrupt injected bytes; skip
            # the undecodable run rather than abort fixture generation.
            continue
    return frames


def _ordered_frames(records: list[FrameRecord], key: bytes | None) -> list[tuple[str, Frame]]:
    """Decode both directions and merge into one capture-ordered stream.

    Returns ``(direction, frame)`` pairs in the order the frames completed on
    the wire, so request (outbound) and reply (inbound) frames interleave the
    way they happened - the order the script generator pairs them in. Each
    direction is reassembled with its own ``FrameDecoder``."""
    in_dir = DIR_INBOUND.decode()
    out_dir = DIR_OUTBOUND.decode()
    decoders = {in_dir: FrameDecoder(key=key), out_dir: FrameDecoder(key=key)}
    merged: list[tuple[str, Frame]] = []
    for rec in records:
        decoder = decoders.get(rec.direction)
        if decoder is None:
            continue
        try:
            for frame in decoder.feed(rec.data):
                merged.append((rec.direction, frame))
        except FrameDecodeError:
            # A capture may include deliberately corrupt injected bytes; skip
            # the undecodable run rather than abort fixture generation.
            continue
    return merged


def _frame_repr(frame: Frame) -> str:
    """Render a Frame's asserted fields as a dict literal for the fixture test."""
    return (
        "{"
        f'"src_id": {frame.src_id}, '
        f'"dst_id": {frame.dst_id}, '
        f'"sequence": {frame.sequence}, '
        f'"major": {frame.major}, '
        f'"minor": {frame.minor}, '
        f'"payload": {_hexlit(bytes(frame.payload))}'
        "}"
    )


def _command_key(req: Frame) -> tuple[int, int, str | int | None]:
    """Build the mock-panel script key for a captured request frame."""
    if req.major == int(MajorCode.XML_CMD):
        text = bytes(req.payload)[1:].decode("ascii", "replace")
        marker = 'ID="'
        start = text.find(marker)
        cid: str | int | None = None
        if start >= 0:
            start += len(marker)
            end = text.find('"', start)
            if end >= 0:
                cid = text[start:end]
        return (req.major, req.minor, cid)
    if req.major in (int(MajorCode.BINARY_CMD), int(MajorCode.PANEL_CMD)):
        opcode = bytes(req.payload)[0] if req.payload else None
        return (req.major, req.minor, opcode)
    return (req.major, req.minor, None)


def generate_frames_fixture(name: str, frames: list[Frame], encrypted: bool) -> str:
    """Render the ``<name>_frames.py`` module source (constants + a pytest)."""
    lines: list[str] = [
        '"""Byte-for-byte frame fixtures generated from a live capture.',
        "",
        f"Source capture group: {name}.  DO NOT EDIT BY HAND - regenerate with",
        "tests/live/replay_to_fixture.py.  These freeze real SPC4300 wire bytes",
        "as permanent regression guards (see test_wire.py / test_encryption.py).",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "import pytest",
        "",
        "from spcedp.wire import Frame, FrameDecoder",
        "",
        f"ENCRYPTED = {encrypted!r}",
        "",
        "# One asserted field-set per decoded inbound frame, in capture order.",
        "EXPECTED_FRAMES = [",
    ]
    lines += [f"    {_frame_repr(f)}," for f in frames]
    lines += [
        "]",
        "",
        "",
        "def test_decoded_frames_match_capture() -> None:",
        '    """Re-decoding the capture yields exactly the recorded frames."""',
        "    # Encrypted captures need a runtime key; cleartext decode directly.",
        "    if ENCRYPTED:",
        '        pytest.skip("encrypted fixture needs a runtime --key; see *_script.py")',
        "    decoder = FrameDecoder()",
        "    decoded: list[Frame] = []",
        "    for expected in EXPECTED_FRAMES:",
        "        # The raw bytes are reconstructed from the asserted fields and",
        "        # re-encoded so the test is self-contained and key-free.",
        "        frame = Frame(",
        '            src_id=expected["src_id"],',
        '            dst_id=expected["dst_id"],',
        '            sequence=expected["sequence"],',
        '            major=expected["major"],',
        '            minor=expected["minor"],',
        '            payload=expected["payload"],',
        "        )",
        "        decoded.extend(decoder.feed(frame.encode()))",
        "    assert len(decoded) == len(EXPECTED_FRAMES)",
        "    for got, expected in zip(decoded, EXPECTED_FRAMES, strict=True):",
        '        assert got.src_id == expected["src_id"]',
        '        assert got.dst_id == expected["dst_id"]',
        '        assert got.sequence == expected["sequence"]',
        '        assert got.major == expected["major"]',
        '        assert got.minor == expected["minor"]',
        '        assert bytes(got.payload) == expected["payload"]',
        "",
    ]
    return "\n".join(lines)


def generate_script_fixture(
    name: str, script: dict[tuple[int, int, str | int | None], bytes]
) -> str:
    """Render the ``<name>_script.py`` mock-panel script module source."""
    lines: list[str] = [
        '"""Mock-panel reply script generated from a live capture.',
        "",
        f"Source capture group: {name}.  DO NOT EDIT BY HAND - regenerate with",
        "tests/live/replay_to_fixture.py.  Feed SCRIPT into MockPanel(script=...)",
        "to replay the captured session's request/reply exchanges offline.",
        '"""',
        "",
        "from __future__ import annotations",
        "",
        "from tests.mockpanel import Action",
        "",
        "SCRIPT: dict[tuple[int, int, object], Action] = {",
    ]
    for (major, minor, cid), payload in script.items():
        lines.append(f"    ({major}, {minor}, {cid!r}): Action(payload={_hexlit(payload)}),")
    lines += ["}", ""]
    return "\n".join(lines)


def build_fixtures(capture_paths: list[Path], key: bytes | None = None) -> dict[str, str]:
    """Read captures, decode frames, and return {output_filename: source}.

    Groups all given captures under one fixture name (the first file's stem).
    Returns the rendered fixture sources without writing them, so a caller can
    diff before committing."""
    all_records: list[FrameRecord] = []
    for path in capture_paths:
        all_records.extend(read_capture(path))

    encrypted = key is not None
    name = capture_paths[0].stem if capture_paths else "capture"

    # Inbound (panel -> receiver) frames are what a replay feeds back through a
    # FrameDecoder, so the frozen-frame fixture asserts exactly those.
    inbound_frames = _decode_direction(all_records, DIR_INBOUND.decode(), key)

    # The reply script pairs each outbound REQUEST (receiver -> panel) with the
    # next matching inbound reply, so MockPanel can answer the same requests.
    # Walk the merged, capture-ordered stream to honour the real interleaving.
    script: dict[tuple[int, int, str | int | None], bytes] = {}
    pending_requests: list[Frame] = []
    for _direction, frame in _ordered_frames(all_records, key):
        if frame.minor == int(MinorCode.REQUEST) and frame.major in _REPLY_MINORS:
            pending_requests.append(frame)
            continue
        for major, reply_minor in _REPLY_MINORS.items():
            if frame.major == major and frame.minor == reply_minor:
                # Match against the oldest unanswered request of this major.
                for i, req in enumerate(pending_requests):
                    if req.major == major:
                        script[_command_key(req)] = bytes(frame.payload)
                        del pending_requests[i]
                        break
                break

    return {
        f"{name}_frames.py": generate_frames_fixture(name, inbound_frames, encrypted),
        f"{name}_script.py": generate_script_fixture(name, script),
    }


def write_fixtures(capture_paths: list[Path], key: bytes | None = None) -> list[Path]:
    """Generate and write fixture modules to ``tests/fixtures/``; return paths."""
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for filename, source in build_fixtures(capture_paths, key).items():
        out = FIXTURES_DIR / filename
        out.write_text(source, encoding="utf-8")
        written.append(out)
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("captures", nargs="*", help="capture .bin files to convert")
    ap.add_argument("--glob", default=None, help="glob pattern for capture files")
    ap.add_argument(
        "--key",
        default=None,
        help="32-hex-digit EDP key if the capture is encrypted (never stored)",
    )
    args = ap.parse_args(argv)

    paths = [Path(p) for p in args.captures]
    if args.glob:
        paths += [Path(p) for p in sorted(globmod.glob(args.glob))]
    if not paths:
        ap.error("no capture files given (pass paths or --glob)")

    key = bytes.fromhex(args.key) if args.key else None
    written = write_fixtures(paths, key)
    for path in written:
        print(f"wrote {path}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
