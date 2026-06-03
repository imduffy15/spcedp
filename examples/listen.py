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
from spcedp.events import SiaEvent


async def on_session(sess: Session) -> None:
    panel = await Panel.from_session(sess)
    print(
        f"connected: {panel.info.type} {panel.info.variant} "
        f"sn={panel.info.sn} fw={panel.info.version}"
    )
    print(f"areas:   {[(a.id, a.name, a.mode) for a in panel.areas.values()]}")
    print(f"zones:   {len(panel.zones)} configured")
    print(f"outputs: {[(o.id, o.name, o.state) for o in panel.outputs.values()]}")


async def on_event(sess: Session, ev: SiaEvent) -> None:
    when = ev.timestamp.isoformat() if ev.timestamp else "?"
    print(f"event {when} {ev.sia_code} @addr={ev.address}: {ev.description}")


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
        on_event=on_event,
        on_session=on_session,
    ) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
