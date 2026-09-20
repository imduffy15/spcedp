"""Minimal example: accept connection from a panel and print everything.

Usage:
    python examples/listen.py --port 50000 --receiver-id 1001
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from spcedp import Panel
from spcedp.client import PanelServer, Session


async def on_session(sess: Session) -> None:
    panel = await Panel.from_session(sess)
    print(
        f"connected: {panel.info.type} {panel.info.variant} "
        f"sn={panel.info.sn} fw={panel.info.version}"
    )
    print(f"areas:   {[(a.id, a.name, a.mode) for a in panel.areas.values()]}")
    print(f"zones:   {len(panel.zones)} configured")

    async for event in panel.events():
        update = await panel.reconcile_event(event)
        for zone_id in update.zone_ids:
            zone = panel.zones[zone_id]
            print(f"zone {zone.name}: {zone.is_open}")
        for area_id in update.area_ids:
            area = panel.areas.get(area_id)
            if area is not None:
                print(f"area {area.name}: {area.arm_mode}")


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=50000)
    ap.add_argument("--receiver-id", type=int, required=True)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    async with PanelServer(
        receiver_id=args.receiver_id,
        bind=args.bind,
        port=args.port,
        on_session=on_session,
    ) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
