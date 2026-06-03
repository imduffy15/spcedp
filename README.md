# spcedp

An async Python implementation of the Vanderbilt SPC EDP v2 wire protocol.

The SDK is the EDP receiver. A panel dials in over TCP, the SDK speaks EDP
back, and you get Python objects for the panel's areas, zones, outputs and
users, a live event stream, and control over zones, areas and outputs. The
panel talks straight to your code.

```python
import asyncio
from spcedp import PanelServer, Panel

async def on_session(session):
    panel = await Panel.from_session(session)
    print(panel.info)                  # PanelInfo(type='SPC4000', ...)
    for z in panel.zones.values():
        print(z.id, z.name, z.status)

    await panel.zone(1).inhibit()
    await panel.zone(1).deinhibit()

    async for ev in panel.events():
        print(ev.timestamp, ev.sia_code, ev.description)

async def main():
    async with PanelServer(receiver_id=1001, port=50000,
                           on_session=on_session) as server:
        await server.serve_forever()

asyncio.run(main())
```


## Status

Tested end to end against a Vanderbilt SPC4300 (firmware 3.15.0):

| Piece                                                   | Status |
|---------------------------------------------------------|--------|
| Frame encode / decode incl. checksum                    | ✅ matches captured frames byte-for-byte |
| TCP listener / panel-dial-in flow                       | ✅ panel holds the session indefinitely |
| Session loop (HELLO + POLL ack)                         | ✅ |
| SIA event stream                                        | ✅ live ZO / ZC / NR / BB / BU events surface via `Panel.events()` |
| XML command channel (info / status / area / zone / output / door / vzone / log) | ✅ encode + reply parsing + fragment reassembly |
| Zone control (inhibit/deinhibit/isolate/deisolate)      | ✅ verified live (apply→verify→revert cycles) |
| Area arm/disarm (`set` / `set_a` / `set_b` / `unset`)   | ✅ verified live |
| Output set/reset                                        | ✅ verified live |
| Door commands, alert restore, bell silence, audio play  | ✅ opcodes verified live; door ops on a doorless panel return INVALID_PARAMS as expected |
| Panel-wide commands (`panel.test()` / `panel.reset()`, `major=5`) | ✅ wire format verified live. The SPC4300 firmware replies `0xFF` (not implemented), but the channel works |
| EDP frame encryption (AES-128-ECB)                      | ✅ verified live end to end (HELLO, POLL, XCMD, fragmented zone_status and SIA events all round-trip encrypted) |

[`PROTOCOL.md`](PROTOCOL.md) has the full protocol:
header layout (§2.1), message families (§2.2), the XML channel (§2.3),
the binary opcode table (§2.4), the checksum (§2.5), the SIA event format
(§2.6), and AES encryption (§2.7).


## Install

Needs Python 3.10+. The only runtime dependency is `cryptography`, used for
the optional AES frame encryption.

Add it to a project with [`uv`](https://github.com/astral-sh/uv):

```bash
uv add git+https://github.com/imduffy15/spcedp.git
```

To work on spcedp itself, [`mise`](https://mise.jdx.dev) installs `uv` and
`uv` provisions Python:

```bash
git clone https://github.com/imduffy15/spcedp.git
cd spcedp
mise install                 # installs uv; uv provisions Python
uv run --extra test pytest -v
```


## Panel-side setup

On the panel, go to **Communications → Reporting → EDP** and add an EDP
entry pointing at the host running this SDK:

- **Receiver ID**: an integer; must match the SDK's `receiver_id`
- **Protocol version**: 2
- **Commands**: enabled (so the receiver can issue zone/area/output writes)
- **Live streaming**: always available (pushes SIA events as they happen)
- **Encryption**: optional. For AES-128-ECB, enable it and pass the
  32-hex-digit key as `PanelServer(..., key=...)`
- **Network**: enabled
- **Network protocol**: TCP/IP
- **Receiver IP address**: the host running the SDK
- **Port**: the SDK's port (default 50000)
- **Always connected**: true
- **Panel master**: true
- **Polling interval**: 10
- **Primary receiver**: true
- **Verification**: true

Leave everything else at its default.


## How the wire works

```
                  ┌──────────────┐
   panel  ───TCP/EDP v2 ───▶     │
       ◀──────────────────       │   spcedp
                  │ PanelServer  │   (EDP receiver role)
                  │ Session      │
                  │ Panel        │
                  └──────────────┘
```

An EDP v2 frame is a 23-byte little-endian header followed by a
variable-length payload. Two command families ride on it:

- XML commands (`major=10`) are readable structured queries. For example
  `<COMMAND ID="zone_status" />` returns
  `<COMMAND_REPLY><ZONE_STATUS>…</ZONE_STATUS></COMMAND_REPLY>`. Large
  replies arrive in fragments and the SDK reassembles them.
- Binary commands (`major=4`) are short writes: arm/disarm,
  inhibit/isolate, output set/reset, and so on.

The panel pushes SIA events on `major=2` as a plain ASCII payload.

The byte-level layout, the major/minor codes, the binary opcode table, the
fragment markers, the SIA event format, the checksum, and the AES layout
are all in [`PROTOCOL.md`](PROTOCOL.md).


## Examples

- [`examples/listen.py`](examples/listen.py): bind the receiver, accept the
  panel, and print what comes in.


## Tests

```bash
uv run --extra test pytest -v
```

The unit tests run against real frames captured from a live SPC4300, so a
regression in the decode logic fails right away.


## License

MIT. See [LICENSE](LICENSE).
