# Changelog

## Unreleased

Additive, backward-compatible public-API additions (driven by the Home Assistant
integration):

- `ZoneType` enum (exported) plus `Zone.zone_type`, a typed view of the raw
  `Zone.type` token mirroring `Area.arm_mode`. It is the full SPC zone-input-type
  catalogue (`ALARM=0`, `ENTRY_EXIT=1`, `FIRE=3`, … `ENTRY_EXIT_2=30`);
  unrecognised or missing tokens return `None` rather than guessing.
- `Area.last_set_user_name` / `Area.last_set_user_id`, read from the
  `AREA_STATUS` reply alongside the existing `last_unset_user_*` fields, so a
  consumer can attribute a *set* (arm) to a user, not just an unset (disarm).
- `AreaControl` arm/disarm methods now document that the panel drops and
  re-establishes the EDP session on set/unset (PROTOCOL.md §2.4): the command
  can raise `SpcConnectionLost`/`SpcTimeout` even when applied; treat that as
  "applied, expect a re-dial" and resync from the new session.

## 1.0.0 - 2026-06-03

First stable release. Hardening pass toward a stable release. Behaviour changes plus a much larger
test suite; the public surface is now frozen behind `__all__`.

Safety-path fixes:

- The stream decoder can no longer stall indefinitely on a corrupt length
  prefix: a header claiming an implausibly large frame is rejected at once,
  and an incomplete-but-plausible header is bounded so recovery stays within
  a fixed byte budget (`wire.MAX_PLAUSIBLE_FRAME`).
- Cleartext frames are now checksum-validated on decode, like encrypted ones,
  so corruption resyncs instead of surfacing as a phantom frame.
- A writer task that dies on a socket error tears the session down instead of
  leaving a connected-but-mute receiver; the outbound queue is bounded.
- A crashed `on_session` callback is logged and torn down immediately rather
  than going unnoticed until the connection closes.
- `Frame.encode` raises `ValueError` (not `struct.error`) on an oversized
  payload.

Public API:

- Exception hierarchy rooted at `SpcError`: `PanelRejected` (carries the reply
  code; `.is_transient` flags retryable ones), `SpcTimeout`,
  `SpcConnectionLost`, `SpcProtocolError`. Public methods no longer leak
  `asyncio`/builtin exceptions. `FrameDecodeError` / `EncryptionRequired` are
  exported.
- Typed state accessors alongside the raw strings: `ArmMode` with
  `Area.arm_mode` / `Area.is_armed`, `Zone.is_open`, `Output.is_active`
  (unrecognised values read as `None`, never a wrong default).
- Read-only accessors for door/enet/verification/status and the system and
  zone logs; a `Door` snapshot type.
- `Panel.last_refresh` and a best-effort `Panel.apply_event` for reconciling
  the snapshot from the live event stream; the snapshot is otherwise
  point-in-time and stale after disconnect.
- `refresh()` rebuilds its dicts, so removed zones/areas/outputs no longer
  linger.
- Type aliases `XmlReply` / `Row` / `AttrValue` are exported.

SIA events:

- The parser right-anchors the trailing fields, so a `|` inside a free-text
  description no longer corrupts `verification_id`.
- The raw timestamp string is preserved, and `parse()` takes an optional
  `panel_tz` for timezone-aware timestamps; `SiaEvent.category` groups codes.

Protocol surface:

- Clock set (0x06) and pin set (0x07) are kept for identification only: their
  payload shape is unverified, so they are not exposed via `Panel`.
- Confirmed live against an SPC4300 (fw 3.15.0): the read commands, reversible
  zone ops, and arm/disarm all work. Arming makes the panel re-establish the
  EDP session, so a reconnect is expected after an arm/disarm; engineer mode
  makes operational commands return `0xFC`.

Packaging / CI:

- Requires Python 3.14 (provided by mise); CI tests on 3.14 only. Coverage
  reporting, `uv run --frozen`, and a lockfile-drift check in CI; `SECURITY.md`,
  `CONTRIBUTING.md` and Dependabot added; `cryptography>=43`.
- Live-verified end to end against an SPC4300 (firmware 3.15.0) before release.

## 0.1.0 - unreleased

First release. A pure-Python EDP v2 client for Vanderbilt SPC alarm
panels; the panel dials straight into your code over TCP.

What works (verified live against an SPC4300, firmware 3.15.0):

- Frame checksum: a 16-bit shift-register hash with byte-add mixing and
  poly 0xA097 (PROTOCOL.md §2.5).
- AES-128-ECB frame encryption, with the cleartext-prefix / encrypted-tail
  layout EDP uses (PROTOCOL.md §2.7). Pass `key=` (16 raw bytes or 32 hex
  digits) to `PanelServer` / `Frame.encode` / `Frame.decode`. Verified
  end to end with encryption on: the full panel/areas/zones/outputs read
  and the SIA event stream round-trip through encrypted HELLO, POLL and
  XCMD frames, including fragmented ~3 KB zone_status replies.
- TCP listener the panel dials into.
- HELLO plus a 10-second POLL ack loop, with one shared sequence space so
  the panel never sees a sequence collision when a command starts.
- SIA event parsing and an async event stream; live tests surface real
  ZO / ZC / NR / BB / BU events.
- XML command channel (`major=10`): info, status, area_status,
  zone_status, output_status, door_status and friends, with fragmented
  replies reassembled via the `\x02` continuation marker.
- Binary command channel (`major=4`): the opcode table is verified live
  for area set/set_a/set_b/unset, zone inhibit/deinhibit/isolate/deisolate,
  output set/reset, door inhibit/isolate/open/lock, alert restore, bell
  silence and audio play. Most opcodes take a 3-byte
  `<op> <target_id> <param>`; panel-wide ones take a 1-byte `<op>`.
  Clock set (0x06) and pin set (0x07) are kept for identification only:
  their payload shape is unverified and they are not exposed via `Panel`.
- Panel-wide command channel (`major=5`) for `panel/test` and
  `panel/reset`. SPC4300 firmware 3.15.0 answers `0xFF` (not implemented)
  to both, but the channel itself works.
- High-level `Panel` facade: `panel.info`, `panel.areas`, `panel.zones`,
  `panel.outputs`, `panel.zone(n).inhibit()`, `panel.area(n).set_a()`,
  `panel.output(n).set()`, `panel.events()`.
- `tests/integration_test.py` for a safe live run: it skips smoke
  detectors, refuses to run while any area is armed, and reverts every
  change it makes.

Robustness work (cleartext and encrypted paths re-checked live):

- A malformed or encrypted frame no longer drops the session. The stream
  decoder resyncs, bounded so a wrong key or a corrupt stream fails fast
  with a clear error instead of stalling.
- An out-of-bounds `dlen` is rejected rather than silently truncating the
  payload. On the encrypted path the embedded checksum is re-checked on
  decode to catch a wrong key or corruption (the encrypt-bit-set
  convention is confirmed live; PROTOCOL.md §2.7 was corrected to match).
- A dedicated writer task keeps a slow send from blocking reads, in-flight
  command futures fail fast on disconnect, `on_event` callbacks are kept,
  logged and cancelled cleanly, and `Panel.events()` receives events and
  stops cleanly when the panel disconnects.
- Reply bytes are treated as untrusted: XML attribute values are escaped,
  and a reply carrying a DTD or entity declaration is rejected.

Not yet implemented:

- Reply codes 0xF1, 0xF3, 0xF4, 0xF5 and 0xFB have not been seen on the
  wire. They map to meaningful errors if they show up (see
  `errors.ReplyCode`).
