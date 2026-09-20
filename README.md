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
from spcedp import Panel, PanelServer, Session


async def connected(session: Session) -> None:
    panel = await Panel.from_session(session)
    print(panel.info.type, panel.info.version)
    for zone in panel.zones.values():
        print(zone.id, zone.name, zone.is_open)

    async def refresh() -> None:
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


async def main() -> None:
    async with PanelServer(receiver_id=1001, port=50000, on_session=connected) as server:
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
`Zone.is_open` reads physical `INPUT` and returns `None` for faults or missing
values. `Area.arm_mode` is an `ArmMode` or `None` for missing or unknown modes.

`reconcile_event()` applies zone events immediately and reads current area
state for ambiguous arm/disarm events. Refresh areas and zones periodically
to cover missed events. `Area.triggered` is event-derived and clears when a
refresh confirms disarm; it cannot reconstruct alarms missed while disconnected.

## Change alarm state

Use an area ID from `panel.areas`:

```python
await panel.area(1).set()  # full set / away
await panel.area(1).set_a()  # part set A / home
await panel.area(1).set_b()  # part set B / night
await panel.area(1).unset()  # disarm
await panel.refresh_areas()  # read the confirmed state
```

Commands are serialized and wait for a short pause in incoming traffic so
panel event bursts cannot collide with command sequence numbers.
Commands wait for the panel's reply. `PanelRejected` contains its rejection
code; `SpcTimeout`, `SpcConnectionLost` and `SpcProtocolError` report communication
failures. All inherit `SpcError`. A timeout does not prove a command failed:
read the state before retrying. The `on_session` callback runs for each new
connection; build a fresh `Panel` there. Leaving the server context closes
its accepted connections too.

## Development

```sh
mise install
mise run setup       # Locked dependencies and prek Git hooks
mise run format      # Apply Ruff formatting
mise run ci          # All checks, tests and release packaging
```

`mise run check` runs Ruff lint/format, strict mypy, Pylint, Bandit,
workflow checks and file hygiene. `mise run test` runs the tests separately.
Tool versions and dependencies are pinned in `mise.lock` and `uv.lock`.
GitHub Actions call these same tasks and cache tools, dependencies and check results.
Tag builds bypass caches before publishing their validated artifacts.

To release, update the version in `pyproject.toml` and push a matching `vX.Y.Z`
tag. CI publishes a wheel and source archive to GitHub Releases; it does not
publish to PyPI. `mise run build release-check` checks the artifacts locally.

Tests include captured frames, malformed input, reconnect/shutdown behavior,
and encrypted loopback sessions. `examples/listen.py` prints live sensor and
area updates without changing alarm state.

Keep EDP on a trusted network: neither plaintext nor its AES-128-ECB mode
provides message authentication. Report vulnerabilities privately through the
repository's **Security → Report a vulnerability** page. MIT license.
