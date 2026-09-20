# spcedp

Async Python library for Vanderbilt SPC zone sensors and alarm-area control
using the panel's native EDP v2 protocol. The panel connects to your TCP
listener. Requires Python 3.14+; tested with an SPC4300 running firmware 3.15.0.

```sh
uv add git+https://github.com/imduffy15/spcedp.git
```

## Connect and read sensors

```python
import asyncio
from spcedp import Panel, PanelServer

async def connected(session):
    panel = await Panel.from_session(session)
    print(panel.info.type, panel.info.version)
    for zone in panel.zones.values():
        print(zone.id, zone.name, zone.is_open)

    async def refresh():
        while True:
            await asyncio.sleep(30)
            await panel.refresh_areas()
            await panel.refresh_zones()

    refresh_task = asyncio.create_task(refresh())
    try:
        async for event in panel.events():
            update = await panel.reconcile_event(event)
            print(update.zone_ids, update.area_ids)
    finally:
        refresh_task.cancel()
        await asyncio.gather(refresh_task, return_exceptions=True)

async def main():
    async with PanelServer(receiver_id=1001, port=50000,
                           on_session=connected) as server:
        await server.serve_forever()

asyncio.run(main())
```

Follow the [panel setup instructions](https://github.com/imduffy15/hacs-spc-vanderbilt#panel-setup)
for global EDP settings, the TCP receiver and event filters. Use this
listener's host IP, `port` and `receiver_id` wherever the guide refers to
Home Assistant. The example uses panel ID `1000` and receiver ID `1001`;
`PanelServer` learns the panel ID from the connection. For encryption, pass
the receiver's matching 32-hex-digit key as `PanelServer(..., key=...)`.

`Panel.from_session()` waits for the first poll and reads identity, areas and
zones. `zones` and `areas` are snapshots; refresh replaces their contents.
`Zone.is_open` prefers physical `INPUT` over `STATUS` and returns `None` when
the physical input reports a fault or neither field gives a known state.
`STATUS` is only a fallback when `INPUT` is absent. `Area.arm_mode` is an `ArmMode` or
`None` for missing or unknown modes.

`reconcile_event()` applies zone events immediately and reads current area
state for ambiguous arm/disarm events. Refresh areas and zones periodically
to cover missed events. `Area.triggered` is event-derived and clears when a
refresh confirms disarm; it cannot reconstruct alarms missed while disconnected.

## Change alarm state

Use an area ID from `panel.areas`:

```python
await panel.area(1).set()    # full set / away
await panel.area(1).set_a()  # part set A / home
await panel.area(1).set_b()  # part set B / night
await panel.area(1).unset()  # disarm
await panel.refresh_areas() # read the confirmed state
```

Commands wait for the panel's reply. `PanelRejected` contains its rejection
code; `SpcTimeout`, `SpcConnectionLost` and `SpcProtocolError` report communication
failures. All inherit `SpcError`. A timeout does not prove a command failed:
read the state before retrying. The `on_session` callback runs for each new
connection; build a fresh `Panel` there. Leaving the server context closes
its accepted connections too.

Version 2 removes the high-level door/output/zone-maintenance and panel-reset
APIs. The supported facade is sensors and area arming; low-level `Session`
commands and [protocol notes](PROTOCOL.md) remain for protocol work.

## Development

```sh
mise install
uv run --extra test pytest -q
uv run --extra dev ruff check spcedp tests examples
uv run --extra dev ruff format --check spcedp tests examples
uv run --extra dev pylint spcedp
uv run --extra dev mypy
```

Tests include captured frames, malformed input, reconnect/shutdown behavior,
and encrypted loopback sessions. `examples/listen.py` prints live sensor and
area updates without changing alarm state.

Keep EDP on a trusted network: neither plaintext nor its AES-128-ECB mode
provides message authentication. Report vulnerabilities privately through the
repository's **Security → Report a vulnerability** page. MIT license.
