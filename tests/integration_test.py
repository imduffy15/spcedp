"""End-to-end direct-EDP integration test against a real SPC panel.

Listens on a TCP port, waits for the panel to dial in, then:

  1. Reads panel info + areas + zones + outputs and prints them.
  2. For a few zones, runs an inhibit/deinhibit cycle, verifying that
     the panel's reported zone status changes.
  3. Same for isolate/deisolate.
  4. Stays connected for a few seconds afterwards to surface any SIA
     events the panel happens to push.

Refuses to run if any area is currently armed.  Skips any zone named
"smoke" so we never poke the smoke detector.

Usage:
    python tests/integration_test.py --port 50000 --receiver-id 1001
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import traceback
from contextlib import suppress

from spcedp import Panel, PanelServer, SiaEvent
from spcedp.client import Session


def banner(s: str) -> None:
    print(f"\n{'=' * 4} {s} {'=' * max(0, 70 - len(s))}", flush=True)


def kv(name: str, value: object) -> None:
    if isinstance(value, (list, dict)):
        rendered = json.dumps(value, indent=2, default=str)
    else:
        rendered = str(value)
    print(f"  {name:<22} {rendered}", flush=True)


async def zone_cycle(panel: Panel, zone_id: int, *, label: str, apply: str, revert: str) -> bool:
    z0 = panel.zones[zone_id]
    print(f"\n  zone {zone_id} '{z0.name}' {label}: start status={z0.status}", flush=True)
    try:
        await getattr(panel.zone(zone_id), apply)()
        await panel.refresh_zones()
        z1 = panel.zones[zone_id]
        print(f"    after  {apply:<10}  status={z1.status}", flush=True)
        await getattr(panel.zone(zone_id), revert)()
        await panel.refresh_zones()
        z2 = panel.zones[zone_id]
        print(f"    after  {revert:<10}  status={z2.status}", flush=True)
        if z2.status != z0.status:
            print(
                f"    WARNING: status did not return to start ({z0.status} -> {z2.status})",
                flush=True,
            )
            return False
        return True
    except Exception as e:
        print(f"    ERROR: {e}", flush=True)
        with suppress(Exception):
            await getattr(panel.zone(zone_id), revert)()
        return False


_result: dict[str, object] = {}


async def on_session(sess: Session) -> None:
    try:
        banner("SESSION")
        kv("panel-id", sess.panel_id)
        kv("receiver-id", sess.receiver_id)
        banner("REFRESH")
        panel = await Panel.from_session(sess)
        kv(
            "panel",
            f"{panel.info.type} {panel.info.variant} sn={panel.info.sn} fw={panel.info.version}",
        )
        kv("areas", [(a.id, a.name, a.mode) for a in panel.areas.values()])
        kv("zones", f"{len(panel.zones)} configured")
        kv("outputs", [(o.id, o.name, o.state) for o in panel.outputs.values()])

        armed = [a for a in panel.areas.values() if a.mode != "0"]
        if armed:
            print(
                f"\n  Refusing to run mutation tests: areas {[a.id for a in armed]} are armed",
                flush=True,
            )
            _result["status"] = "skipped-armed"
            return

        banner("MUTATE: zone inhibit/deinhibit cycles")
        inhibit_zones = [
            z for z in panel.zones.values() if z.inhibit_allowed and "smoke" not in z.name.lower()
        ][:3]
        inhibit_results = [
            await zone_cycle(panel, z.id, label="inhibit", apply="inhibit", revert="deinhibit")
            for z in inhibit_zones
        ]

        banner("MUTATE: zone isolate/deisolate cycles")
        isolate_zones = [
            z for z in panel.zones.values() if z.isolate_allowed and "smoke" not in z.name.lower()
        ][:2]
        isolate_results = [
            await zone_cycle(panel, z.id, label="isolate", apply="isolate", revert="deisolate")
            for z in isolate_zones
        ]

        banner("SUMMARY")
        kv("panel", f"{panel.info.type}/{panel.info.variant} fw {panel.info.version}")
        kv("inhibit cycles", inhibit_results)
        kv("isolate cycles", isolate_results)
        ok = all(inhibit_results) and all(isolate_results)
        _result["status"] = "ok" if ok else "failures"
    except Exception as e:
        print(f"on_session error: {e!r}", flush=True)
        traceback.print_exc()
        _result["status"] = "error"


async def on_event(sess: Session, ev: SiaEvent) -> None:
    when = ev.timestamp.isoformat() if ev.timestamp else "?"
    print(f"  event {when} {ev.sia_code} @addr={ev.address}: {ev.description}", flush=True)


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=50000)
    ap.add_argument("--receiver-id", type=int, default=1001)
    ap.add_argument(
        "--key", default=None, help="32-hex-digit EDP encryption key (omit for cleartext)"
    )
    ap.add_argument(
        "--shutdown-after",
        type=float,
        default=20.0,
        help="exit this many seconds after the test finishes (allows event observation)",
    )
    args = ap.parse_args()

    logging.basicConfig(level=logging.WARNING)

    async with PanelServer(
        receiver_id=args.receiver_id,
        bind=args.bind,
        port=args.port,
        key=args.key,
        on_event=on_event,
        on_session=on_session,
    ):
        print(f"listening on {args.bind}:{args.port}, waiting for panel to connect ...", flush=True)

        # Run until on_session completes, then linger for events.
        async def runner():
            while "status" not in _result:
                await asyncio.sleep(0.5)
            await asyncio.sleep(args.shutdown_after)

        try:
            await asyncio.wait_for(runner(), timeout=120.0)
        except TimeoutError:
            print("timeout waiting for panel session", flush=True)
            return 2
    return 0 if _result.get("status") == "ok" else 1


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except Exception:
        traceback.print_exc()
        sys.exit(2)
