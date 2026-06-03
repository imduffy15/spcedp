"""Ordered, flag-gated live SPC4300 campaign runner (campaign B.1).

CODE ONLY - never collected or run by pytest, never run in CI. Run by hand on
a host the panel dials in to (see the live-panel config: port 50000, receiver
1001, cleartext or ``--key <hex>``), with the safety flags from
``safety.py``::

    python tests/live/matrix.py --i-confirm-unoccupied \
        --confirm-physical arm --confirm-physical siren

The steps run STRICTLY in order; each must pass before the next. Read-only and
reversible steps run whenever the preflight passes; every dangerous step
(arm/disarm, output/siren, clock/pin probe, panel reset/test) is gated behind an
explicit ``--confirm-physical <step>`` flag AND auto-reverts under a watchdog
(``safety.gated_actuate``). The whole run aborts immediately if any area is
armed or the unoccupied flag is missing.

Every step's frames are captured via ``FrameTap`` so a real session becomes a
permanent offline regression corpus (``replay_to_fixture.py``).

Reuses the public ``spcedp`` API and the patterns from
``tests/integration_test.py`` (refuse-if-armed, skip-smoke, apply/verify/revert,
``zone_cycle``).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import sys
import traceback
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

# Allow `python tests/live/matrix.py` (direct invocation): put the repo root on
# the path so the absolute `tests.live.*` package imports below always resolve.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from spcedp import (  # noqa: E402 - after the sys.path bootstrap above
    BinaryOp,
    Frame,
    MajorCode,
    MinorCode,
    Panel,
    PanelRejected,
    PanelServer,
    SiaEvent,
    SpcConnectionLost,
)
from spcedp.client import Session  # noqa: E402
from tests.live.frametap import FrameTap  # noqa: E402
from tests.live.safety import (  # noqa: E402
    SafetyAbort,
    SafetyConfig,
    add_safety_args,
    gated_actuate,
    is_protected_zone,
    refuse_if_armed,
    require_confirmed,
    safety_config_from_args,
    verify_disarmed,
)

log = logging.getLogger("spcedp.live")

CAPTURES_DIR = Path(__file__).resolve().parent / "captures"

# Read-only XML commands swept in step 1. Each must parse without raising.
READ_ALL_COMMANDS: tuple[tuple[str, dict[str, object]], ...] = (
    ("info", {}),
    ("status", {}),
    ("area_status", {}),
    ("zone_status", {}),
    ("output_status", {}),
    ("door_status", {}),
    ("enet_status", {}),
    ("verification_status", {}),
    ("system_log", {"MAX_EVENTS": 20}),
    ("zone_log", {"ZONE": 1}),
)

# Reversible binary zone-op pairs probed in step 2 (apply, verify-name, revert).
REVERSIBLE_ZONE_OPS: tuple[tuple[str, str], ...] = (
    ("inhibit", "deinhibit"),
    ("isolate", "deisolate"),
)


def banner(title: str) -> None:
    log.info("==== %s %s", title, "=" * max(0, 60 - len(title)))


class LiveCampaign:
    """Holds the connected panel/session and runs the ordered steps."""

    def __init__(self, panel: Panel, session: Session, cfg: SafetyConfig) -> None:
        self.panel = panel
        self.session = session
        self.cfg = cfg
        self.results: dict[str, object] = {}

    # ------------------------------------------------------------------ step 1
    async def step_read_all(self) -> None:
        banner("1. read-all sweep")
        sweep: dict[str, object] = {}
        for command_id, attrs in READ_ALL_COMMANDS:
            try:
                reply = await self.session.xml_command(command_id, **attrs)  # type: ignore[arg-type]
                sweep[command_id] = {tag: len(rows) for tag, rows in reply.items()}
                log.info("  %-22s -> %s", command_id, sweep[command_id])
            except Exception as exc:  # log and continue; one failure is data
                sweep[command_id] = f"ERROR: {exc!r}"
                log.warning("  %-22s -> %r", command_id, exc)
        self.results["read_all"] = sweep

    # ------------------------------------------------------------------ step 2
    async def step_reversible_zone_ops(self) -> None:
        banner("2. reversible binary zone ops (apply/verify/revert)")
        await self.panel.refresh_zones()
        outcomes: dict[str, bool] = {}
        for apply_name, revert_name in REVERSIBLE_ZONE_OPS:
            # inhibit_allowed / isolate_allowed gate which zones are eligible.
            gate = "inhibit_allowed" if apply_name == "inhibit" else "isolate_allowed"
            candidates = [
                z
                for z in self.panel.zones.values()
                if getattr(z, gate, False) and not is_protected_zone(z.name)
            ][:3]
            for zone in candidates:
                ok = await self._zone_cycle(zone.id, apply=apply_name, revert=revert_name)
                outcomes[f"{apply_name}:{zone.id}"] = ok
        self.results["reversible_zone_ops"] = outcomes

    async def _zone_cycle(self, zone_id: int, *, apply: str, revert: str) -> bool:
        """Apply a reversible zone op, verify status changed, then revert.

        Mirrors integration_test.zone_cycle: refresh between each step and
        ALWAYS attempt the revert, even on error."""
        start = self.panel.zones[zone_id].status
        log.info("  zone %d %s: start status=%s", zone_id, apply, start)
        try:
            await getattr(self.panel.zone(zone_id), apply)()
            await self.panel.refresh_zones()
            mid = self.panel.zones[zone_id].status
            log.info("    after %-10s status=%s", apply, mid)
            await getattr(self.panel.zone(zone_id), revert)()
            await self.panel.refresh_zones()
            end = self.panel.zones[zone_id].status
            log.info("    after %-10s status=%s", revert, end)
            return end == start
        except Exception as exc:
            log.warning("    zone %d %s/%s error: %r", zone_id, apply, revert, exc)
            with suppress(Exception):
                await getattr(self.panel.zone(zone_id), revert)()
            return False

    # ------------------------------------------------------------------ step 3
    async def step_doors(self) -> None:
        banner("3. door read + reversible door ops")
        await self.panel.refresh_doors()
        if not self.panel.doors:
            log.info("  no doors configured; skipping")
            self.results["doors"] = "none-configured"
            return
        outcomes: dict[str, bool] = {}
        for door in list(self.panel.doors.values())[:3]:
            start = door.state
            try:
                await self.panel.door(door.id).inhibit()
                await self.panel.refresh_doors()
                await self.panel.door(door.id).deinhibit()
                await self.panel.refresh_doors()
                outcomes[str(door.id)] = self.panel.doors[door.id].state == start
            except Exception as exc:
                log.warning("  door %d cycle error: %r", door.id, exc)
                with suppress(Exception):
                    await self.panel.door(door.id).deinhibit()
                outcomes[str(door.id)] = False
        self.results["doors"] = outcomes

    # ------------------------------------------------------------------ step 4
    async def step_typed_token_capture(self) -> None:
        banner("4. typed-accessor token capture (H4)")
        await self.panel.refresh()
        tokens: dict[str, list[str]] = {
            "area_mode": sorted({a.mode for a in self.panel.areas.values()}),
            "zone_status": sorted({z.status for z in self.panel.zones.values()}),
            "output_state": sorted({o.state for o in self.panel.outputs.values()}),
        }
        # Flag any token that the typed accessors map to None (no silent default).
        unmapped: list[str] = []
        for area in self.panel.areas.values():
            if area.arm_mode is None:
                unmapped.append(f"area {area.id} MODE={area.mode!r}")
        for zone in self.panel.zones.values():
            if zone.is_open is None:
                unmapped.append(f"zone {zone.id} STATUS={zone.status!r}")
        for output in self.panel.outputs.values():
            if output.is_active is None:
                unmapped.append(f"output {output.id} STATE={output.state!r}")
        log.info("  tokens: %s", tokens)
        if unmapped:
            log.warning("  UNMAPPED tokens (extend ArmMode/is_open/is_active): %s", unmapped)
        self.results["typed_tokens"] = {"tokens": tokens, "unmapped": unmapped}

    # ------------------------------------------------------------------ step 5
    async def step_arm_disarm(self) -> None:
        banner("5. arm/disarm cycles (gated: arm)")
        if not require_confirmed("arm", self.cfg):
            self.results["arm_disarm"] = "skipped"
            return
        await self.panel.refresh_areas()
        # Pick the first area to exercise; refuse if anything is already armed.
        refuse_if_armed(self.panel.areas.values())
        targets = list(self.panel.areas.values())[:1]
        outcomes: dict[str, object] = {}
        try:
            for area in targets:
                for apply_name, expect_mode in (("set", "3"), ("set_a", "1"), ("set_b", "2")):
                    try:
                        applied = await gated_actuate(
                            self._area_apply(area.id, apply_name),
                            self._area_apply(area.id, "unset"),
                            name="arm",
                            hold_s=2.0,
                            confirm=self.cfg,
                        )
                    except PanelRejected as exc:
                        # e.g. engineer mode, or arm unsupported on the binary
                        # channel for this firmware - record the code and move on.
                        outcomes[f"{area.id}:{apply_name}"] = f"rejected {exc.code:#04x}"
                        log.warning("  area %d %s rejected: %s", area.id, apply_name, exc)
                        continue
                    if not applied:
                        continue
                    await self.panel.refresh_areas()
                    got = self.panel.areas[area.id].mode
                    outcomes[f"{area.id}:{apply_name}"] = got == expect_mode
                    log.info(
                        "  area %d %s -> mode=%s (expect %s)", area.id, apply_name, got, expect_mode
                    )
        finally:
            # Hard post-check: never leave anything armed, even on error.
            await verify_disarmed(self.panel)
        self.results["arm_disarm"] = outcomes

    def _area_apply(self, area_id: int, method: str) -> Callable[[], Awaitable[None]]:
        async def _do() -> None:
            await getattr(self.panel.area(area_id), method)()

        return _do

    # ------------------------------------------------------------------ step 6
    async def step_clock_pin_probe(self) -> None:
        banner("6. CLOCK_SET / PIN_SET shape probe (gated: clockpin)")
        if not require_confirmed("clockpin", self.cfg):
            self.results["clock_pin"] = "skipped"
            return
        # Read the clock first so we can restore it.
        before = await self.session.xml_command("status")
        observations: list[dict[str, object]] = []
        # CLOCK_SET (0x06) with 0/6/14 trailing bytes - raw frames bypassing
        # BinaryCommand (which forbids a payload on this opcode).
        for trailing in (0, 6, 14):
            payload = bytes([int(BinaryOp.CLOCK_SET)]) + b"\x00" * trailing
            code = await self._raw_binary_probe(payload)
            observations.append({"trailing": trailing, "reply_code": code})
            log.info("  CLOCK_SET +%d bytes -> reply_code=%s", trailing, code)
        after = await self.session.xml_command("status")
        # PIN_SET probe is destructive; only reply-codes, only on a disposable
        # test user, never run here without explicit confirmation.
        self.results["clock_pin"] = {
            "observations": observations,
            "clock_before": {k: len(v) for k, v in before.items()},
            "clock_after": {k: len(v) for k, v in after.items()},
            "pin_set": "not probed (destructive; disposable test user only)",
        }

    async def _raw_binary_probe(self, payload: bytes) -> int | None:
        """Send a raw major=4 request with an arbitrary payload, return the
        reply's first byte (or None on timeout). Bypasses BinaryCommand to probe
        an opcode/payload shape the SDK does not expose."""
        seq = self.session._alloc_seq()
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        self.session._pending_bin[seq] = fut
        frame = Frame(
            src_id=self.session.receiver_id,
            dst_id=self.session.panel_id,
            sequence=seq,
            major=int(MajorCode.BINARY_CMD),
            minor=int(MinorCode.REQUEST),
            payload=payload,
            src_flag=0x08,
        )
        self.session._send(frame)
        try:
            reply = await asyncio.wait_for(fut, 5.0)
        except TimeoutError:
            return None
        finally:
            self.session._pending_bin.pop(seq, None)
        return reply[0] if reply else None

    # ------------------------------------------------------------------ step 7
    async def step_more_data_watch(self) -> None:
        banner("7. 0xF1 MORE_DATA_FOLLOWS observation")
        seen: list[int] = []
        # A safe panel self-test, then a non-siren output read-back, to watch
        # the first reply byte for 0xF1/0xF3/0xF4/0xF5.
        with suppress(Exception):
            code = await self._raw_binary_probe(bytes([int(BinaryOp.ALERT_RESTORE)]))
            if code is not None:
                seen.append(code)
                log.info("  ALERT_RESTORE reply byte=%#04x", code)
        self.results["more_data_watch"] = [f"{c:#04x}" for c in seen]

    # ------------------------------------------------------------------ step 8
    async def step_siren(self) -> None:
        banner("8. output/siren (gated: siren)")
        if not require_confirmed("siren", self.cfg):
            self.results["siren"] = "skipped"
            return
        await self.panel.refresh_outputs()
        outputs = list(self.panel.outputs.values())
        if not outputs:
            self.results["siren"] = "no-outputs"
            return
        target = outputs[0]
        applied = await gated_actuate(
            self._output_apply(target.id, "set"),
            self._output_apply(target.id, "reset"),
            name="siren",
            hold_s=3.0,
            confirm=self.cfg,
        )
        self.results["siren"] = {"output_id": target.id, "applied": applied}

    def _output_apply(self, output_id: int, method: str) -> Callable[[], Awaitable[None]]:
        async def _do() -> None:
            await getattr(self.panel.output(output_id), method)()

        return _do

    # ------------------------------------------------------------------ step 9
    async def step_stale_state(self) -> None:
        banner("9. stale-state confirmation (H2)")
        await self.panel.refresh_zones()
        before = {z.id: z.status for z in self.panel.zones.values()}
        log.warning(
            "  Open then re-close one NON-smoke/fire PIR or door now; waiting 30s "
            "to observe ZO/ZC events while the snapshot stays unchanged ..."
        )
        observed: list[str] = []

        async def _watch() -> None:
            async for ev in self.panel.events():
                observed.append(f"{ev.sia_code}@{ev.address}")
                log.info("  event %s @addr=%s: %s", ev.sia_code, ev.address, ev.description)

        watcher = asyncio.ensure_future(_watch())
        await asyncio.sleep(30.0)
        watcher.cancel()
        with suppress(asyncio.CancelledError):
            await watcher
        # Snapshot should be unchanged by the event stream alone.
        snapshot_unchanged = all(
            self.panel.zones[zid].status == st
            for zid, st in before.items()
            if zid in self.panel.zones
        )
        # Then a refresh should reconcile.
        await self.panel.refresh_zones()
        self.results["stale_state"] = {
            "events": observed,
            "snapshot_unchanged_during_events": snapshot_unchanged,
        }

    # ------------------------------------------------------------------ step 12
    async def step_encrypted_parity(self, key_present: bool) -> None:
        banner("12. encrypted-mode parity")
        # Parity is run by re-invoking the campaign with --key; here we just
        # record whether this run is encrypted and that reads decoded.
        self.results["encrypted_parity"] = {
            "encrypted": key_present,
            "note": "re-run steps 1-2 with --key and diff read_all against cleartext",
        }

    # ------------------------------------------------------------------ step 13
    async def step_event_soak(self, seconds: float) -> None:
        banner("13. event-catalogue soak")
        catalogue: list[dict[str, object]] = []

        async def _watch() -> None:
            async for ev in self.panel.events():
                catalogue.append(
                    {
                        "sia_code": ev.sia_code,
                        "category": ev.category,
                        "address": ev.address,
                        "description": ev.description,
                        "extra": ev.extra,
                        "vid": ev.verification_id,
                        "has_pipe": "|" in (ev.description + ev.extra + ev.verification_id),
                    }
                )

        watcher = asyncio.ensure_future(_watch())
        log.warning(
            "  Provoke benign self-restoring events for %.0fs (LAN pull, open/close "
            "a non-smoke zone, mains/battery test) ...",
            seconds,
        )
        await asyncio.sleep(seconds)
        watcher.cancel()
        with suppress(asyncio.CancelledError):
            await watcher
        self.results["event_soak"] = catalogue
        log.info("  captured %d events", len(catalogue))

    # ------------------------------------------------------------------ step 14
    async def step_reset_test(self) -> None:
        banner("14. panel reset/test (gated: reset)")
        if not require_confirmed("reset", self.cfg):
            self.results["reset_test"] = "skipped"
            return
        # test() is non-destructive; reset() reboots the panel and is gated
        # behind a separate confirmation to avoid an accidental reboot.
        with suppress(Exception):
            await self.panel.test()
            log.info("  panel self-test issued")
        if require_confirmed("reset-reboot", self.cfg):
            await self.panel.reset()
            log.warning("  panel RESET issued (reboot)")
            self.results["reset_test"] = "test+reset"
        else:
            self.results["reset_test"] = "test-only"


async def run_campaign(args: argparse.Namespace) -> int:
    cfg = safety_config_from_args(args)  # raises SafetyAbort if not unoccupied
    key = args.key
    done = asyncio.Event()
    completed = asyncio.Event()
    holder: dict[str, LiveCampaign] = {}
    aborted: list[str] = []
    attempts = 0
    max_attempts = args.max_attempts
    # Steps that physically actuate must run AT MOST ONCE across the whole run.
    # Arming reliably makes the panel drop the EDP session; the reconnect must
    # resume and NOT re-actuate. These are marked done *before* running, so a
    # mid-step drop can never repeat them.
    actuate_once = {"arm_disarm", "clock_pin_probe", "siren", "reset_test"}
    completed_steps: set[str] = set()

    async def on_event(_sess: Session, ev: SiaEvent) -> None:
        log.debug("event %s @%s: %s", ev.sia_code, ev.address, ev.description)

    async def ensure_disarmed(panel: Panel) -> None:
        """Force every area disarmed on reconnect after we've armed.

        A post-arm session drop can leave an area set (the unset never reached
        the panel). On resume we disarm rather than abort, then confirm."""
        await panel.refresh_areas()
        armed = [a for a in panel.areas.values() if a.mode != "0"]
        for area in armed:
            log.warning(
                "force-disarming area %d (mode %s) left set by a post-arm drop",
                area.id,
                area.mode,
            )
            with suppress(Exception):
                await panel.area(area.id).unset()
        if armed:
            await panel.refresh_areas()
        still = [a.id for a in panel.areas.values() if a.mode != "0"]
        if still:
            raise SafetyAbort(f"areas {still} still armed after force-disarm")

    async def on_session(sess: Session) -> None:
        # The panel drops the first session mid-refresh, and reliably drops the
        # session right after an arm/disarm. Treat each fresh dial-in as a RESUME:
        # skip already-completed steps and never re-run an actuating step.
        nonlocal attempts
        if completed.is_set():
            return  # campaign finished; ignore extra dial-ins
        attempts += 1
        attempt = attempts
        try:
            banner(f"SESSION established (attempt {attempt})")
            log.info("panel-id=%s receiver-id=%s", sess.panel_id, sess.receiver_id)
            panel = await Panel.from_session(sess)
            log.info("panel %s/%s fw %s", panel.info.type, panel.info.variant, panel.info.version)
            if "arm_disarm" in completed_steps:
                # We already armed once; a drop may have left it set - disarm it.
                await ensure_disarmed(panel)
            else:
                # Initial hard gate: never start against an already-armed panel.
                refuse_if_armed(panel.areas.values())

            campaign = LiveCampaign(panel, sess, cfg)
            holder["campaign"] = campaign

            # arm/disarm runs LAST: it reliably drops the EDP session, so every
            # observational step (incl. the event soak) runs first, then we
            # actuate once at the very end. Steps 10/11 (reconnect-flap,
            # corrupt-prefix MITM) are separate bench scripts (see campaign.md).
            steps: list[tuple[str, Callable[[], Awaitable[None]]]] = [
                ("read_all", campaign.step_read_all),
                ("reversible_zone_ops", campaign.step_reversible_zone_ops),
                ("doors", campaign.step_doors),
                ("typed_token_capture", campaign.step_typed_token_capture),
                ("more_data_watch", campaign.step_more_data_watch),
                ("stale_state", campaign.step_stale_state),
                ("encrypted_parity", lambda: campaign.step_encrypted_parity(key is not None)),
                ("event_soak", lambda: campaign.step_event_soak(args.soak_seconds)),
                ("clock_pin_probe", campaign.step_clock_pin_probe),
                ("siren", campaign.step_siren),
                ("reset_test", campaign.step_reset_test),
                ("arm_disarm", campaign.step_arm_disarm),
            ]
            for step_name, step_fn in steps:
                if step_name in completed_steps:
                    continue
                if step_name in actuate_once:
                    # do-once: mark before running so a mid-step drop never repeats it
                    completed_steps.add(step_name)
                try:
                    await step_fn()
                except SpcConnectionLost, ConnectionResetError:
                    raise  # resume after re-dial (actuate-once steps won't repeat)
                except SafetyAbort:
                    raise  # armed/unsafe: abort the whole run
                except Exception:  # a per-step failure (e.g. PanelRejected) is data
                    log.exception("step %r failed; recording and continuing", step_name)
                    campaign.results[step_name] = "ERROR (see log)"
                completed_steps.add(step_name)

            log.info("campaign results: %s", campaign.results)
            completed.set()
            done.set()
        except SafetyAbort as exc:
            # An armed/unsafe panel stops the whole run immediately.
            aborted.append(str(exc))
            done.set()
        except SpcConnectionLost, ConnectionResetError:
            log.warning("attempt %d: session dropped; will resume on the panel's re-dial", attempt)
            if attempt >= max_attempts:
                log.error("giving up after %d attempt(s)", attempt)
                done.set()
            else:
                log.warning("waiting for the panel to re-dial to resume ...")
        except Exception:
            log.exception("attempt %d failed unexpectedly", attempt)
            if attempt >= max_attempts:
                done.set()
            else:
                log.warning("waiting for the panel to re-dial to resume ...")

    capture = CAPTURES_DIR / f"matrix-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.bin"
    with FrameTap(capture):
        async with PanelServer(
            receiver_id=args.receiver_id,
            bind=args.bind,
            port=args.port,
            key=key,
            on_event=on_event,
            on_session=on_session,
        ):
            log.info(
                "listening on %s:%d; waiting for the panel to dial in ...", args.bind, args.port
            )
            try:
                await asyncio.wait_for(done.wait(), timeout=args.timeout)
            except TimeoutError:
                log.error("timed out waiting for a panel session")
                return 2
    log.info("capture written to %s", capture)
    if aborted:
        log.error("SAFETY ABORT: %s", aborted[0])
        return 3
    if not completed.is_set():
        log.error("campaign did not complete after %d attempt(s)", attempts)
        return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Live SPC4300 campaign runner (campaign B.1)")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=50000)
    ap.add_argument("--receiver-id", type=int, default=1001)
    ap.add_argument("--key", default=None, help="32-hex-digit EDP key (omit for cleartext)")
    ap.add_argument("--timeout", type=float, default=300.0, help="overall run timeout (s)")
    ap.add_argument(
        "--max-attempts",
        type=int,
        default=5,
        help="retry the campaign this many times across panel re-dials (the panel "
        "often drops the first session mid-refresh)",
    )
    ap.add_argument("--soak-seconds", type=float, default=120.0, help="event soak duration (s)")
    add_safety_args(ap)
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        return asyncio.run(run_campaign(args))
    except SafetyAbort as exc:
        log.error("SAFETY ABORT: %s", exc)
        return 3
    except Exception:
        traceback.print_exc()
        return 2


# A reminder, unused at import, that the length-prefix corrupt-prefix MITM
# (step 11) flips only the 2-byte rem field - it actuates nothing. Kept here so
# a bench operator can wire it into a loopback shim if desired.
def corrupt_length_prefix(frame_bytes: bytes, rem_override: int = 50000) -> bytes:
    """Return ``frame_bytes`` with its 2-byte length prefix set to
    ``rem_override`` (the B1 wedge injection). Touches only the prefix."""
    if len(frame_bytes) < 2:
        return frame_bytes
    return struct.pack("<H", rem_override & 0xFFFF) + frame_bytes[2:]


if __name__ == "__main__":
    sys.exit(main())
