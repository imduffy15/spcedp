# EDP v2 protocol notes

The parts used by this library, observed on SPC4300 firmware 3.15.0.
The panel initiates the TCP connection to the receiver.

## Frames

All multibyte integers are little-endian. Offsets include the length prefix.

| Offset | Bytes | Field |
| --- | --- | --- |
| 0 | 2 | Remaining frame length |
| 2 | 1 | Protocol ID `0x45` |
| 3 | 1 | Version `0x02` |
| 4 | 1 | Flags: bit 0 encrypted, bit 3 from receiver |
| 5 | 4 | Sequence |
| 9 | 4 | Source ID |
| 13 | 4 | Destination ID |
| 17 | 1 | Major code |
| 18 | 1 | Minor code |
| 19 | 2 | Checksum |
| 21 | 2 | Payload length |
| 23 | variable | Payload |

| Major.minor | Direction | Meaning |
| --- | --- | --- |
| 1.0 / 1.1 | Panel / receiver | Poll / echo acknowledgement |
| 1.2 / 1.3 | Panel / receiver | Hello / echo acknowledgement |
| 2.0 / 2.1 | Panel / receiver | SIA event / echo acknowledgement |
| 4.0 / 4.2 | Receiver / panel | Area command / status reply |
| 10.0 / 10.1 | Receiver / panel | XML query / reply |

Acknowledgements echo the payload and sequence with source/destination reversed.
Commands use a new sequence; replies echo it. Serialize whole transactions,
including XML continuations. A panel may queue several events after a command
reply. Wait for 100 ms of quiet before allocating the next command sequence,
while acknowledging incoming frames immediately. Sending too early can collide
with an event's sequence and cause the panel to disconnect.

## Queries and alarm commands

XML request payloads start with `0x01`, followed by `<COMMAND ID="info" />`,
`<COMMAND ID="area_status" />` or `<COMMAND ID="zone_status" />`. Replies have
`<COMMAND_REPLY>` as their root. For a fragmented reply, pull subsequent
chunks with the same request prefixed by `0x02` until the closing tag arrives.
Strip the fragment marker from each reply before assembling its XML.

Area command payloads are three bytes: opcode, area ID, zero.

| Opcode | Action |
| --- | --- |
| `0x01` | Full set / away |
| `0x02` | Unset / disarm |
| `0x0F` | Part set A / home |
| `0x10` | Part set B / night |

A `0xF0` reply means success; other codes reject the command. This panel can
return `0xFC` while in engineer mode. `0xFD` was observed with an open zone;
its precise meaning is unconfirmed. Read `AREA_STATUS` to confirm the mode:
`0` unset, `1` part A, `2` part B, `3` full set.

## Events and sensor state

SIA payloads have this shape:

```text
E2[#<panel_id>|<HHMMSSDDMMYYYY>|<code>|<address>|<description>|<extra>|<verification_id>]
```

Descriptions can contain `|`, so parse the final two fields from the right.
Firmware also uses byte `0xA6` as a description separator. Timestamps are
panel-local wall time without a timezone. An invalid timestamp must not discard
an otherwise valid alarm event.

`ZO` opens a zone and `ZC` closes it. Alarm events `BA`, `FA`, `PA`, `HA` and
`TA` identify a zone and mark its area triggered. Arm/disarm events do not
reliably encode the arm mode or even an area ID: query `AREA_STATUS` for
`BV`, `CG`, `CL`, `NL`, `OG` and `OP`. `BV` marks its area triggered after that read.

Use `ZONE_STATUS.INPUT`: `0` closed, `1` open. Faults or missing input values
are unknown. `STATUS` can remain `0` while a physical input is open.

## Checksum and encryption

The checksum starts at `0xFFFF`. For each byte from protocol ID through payload,
skipping the checksum slot, shift the 16-bit state left, add the byte to its
low byte without carrying into the high byte, and XOR `0xA097` if the previous
high bit was set. See `wire.edp_checksum` and the captured-frame tests.

Encrypted frames use AES-128-ECB with a 16-byte key. Wire bytes 0–16 stay clear;
bytes 17 onward are encrypted, zero-padded to a 16-byte boundary. Set the
encrypted flag before computing the checksum, then encrypt and update the
length prefix. No PKCS#7 padding or message authentication is used.
