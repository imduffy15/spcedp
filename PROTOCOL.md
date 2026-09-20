# Vanderbilt SPC EDP v2 protocol reference

This document describes the Vanderbilt SPC EDP v2 wire protocol (Enhanced
Datagram Protocol). It was reverse-engineered black-box against an SPC4300
(firmware 3.15.0) with no vendor documentation; other models or firmware may
differ.


## 1. Overview

EDP runs over a single TCP connection that the **panel** initiates outbound to
a **receiver**. This SDK is that receiver: the panel connects directly to
your code.

```
                   ┌────────────────────┐
   SPC panel  ◀── TCP / EDP v2 ──▶       │  this SDK
   (dials in)      (optional AES-128-ECB)│  (EDP receiver role)
                   └────────────────────┘
```

Once connected, the panel sends a HELLO, then a POLL roughly every 10 s, plus
asynchronous SIA event frames. The receiver ACKs those and may issue XML
queries (`major=10`) and binary writes (`major=4`) / panel-wide commands
(`major=5`).


## 2. EDP wire format

### 2.1 Frame header (23 bytes, little-endian)

Confirmed against live captures from an SPC4300 v3.15.0 panel:

```
offset  size  field
 0-1    2     remaining-length (LE)   total frame size = 2 + this
 2      1     protocol family         constant 0x45 ('E')
 3      1     version                 0x02 on v2 panels
 4      1     source flag             0x00 from panel, 0x08 from the receiver
 5-8    4     sequence number (LE)    request and reply share the same seq
 9-12   4     source ID (LE)          panel ID or receiver ID
13-16   4     destination ID (LE)     receiver ID or panel ID
17      1     major code              message family (see §2.2)
18      1     minor code              sub-type (req/reply/ack)
19-20   2     checksum (LE)           see §2.5 for the algorithm
21-22   2     payload length (LE)
23..   var    payload
```

Byte 2 is the protocol ID (`0x45`, the character `'E'`); byte 4 is the source
flag. Sequence numbers and IDs are both 32-bit, not 16-bit.

### 2.2 Major / minor code map

In this table, `rx` = the receiver, i.e. this SDK:

| major.minor | direction | meaning |
|---|---|---|
| 1.0 | panel→rx | POLL (every 10s, keepalive with 8-byte random nonce) |
| 1.1 | rx→panel | POLL_ACK (echoes the nonce verbatim) |
| 1.2 | panel→rx | HELLO / session-establish |
| 1.3 | rx→panel | HELLO_ACK |
| 2.0 | panel→rx | SIA event (see §2.6) |
| 2.1 | rx→panel | SIA event ACK (echoes the SIA payload verbatim) |
| 4.0 | rx→panel | binary command request (3-byte or 1-byte payload) |
| 4.2 | panel→rx | binary command reply (1-byte status code) |
| 5.0 | rx→panel | panel-wide command request (1-byte opcode payload) |
| 5.1 | panel→rx | panel-wide command reply (1-byte status code) |
| 10.0 | rx→panel | XML command request (see §2.3) |
| 10.1 | panel→rx | XML command reply |

### 2.3 XML command channel (major=10)

The XML channel carries everything queryable: `info`, `status`, `area_status`,
`zone_status`, `output_status`, `door_status`, `verification_status`,
`enet_status`, plus log subsets. Observed request shapes:

```xml
<COMMAND ID="info" />
<COMMAND ID="zone_status" />
<COMMAND ID="system_log"  MAX_EVENTS="%d" />
<COMMAND ID="zone_log"    ZONE="%d" />
```

Replies are wrapped in `<COMMAND_REPLY> … </COMMAND_REPLY>`.

Wire format of the payload:

```
\x01 <COMMAND ID="zone_status" />               first/only request
\x02 <COMMAND ID="zone_status" />               "give me next chunk"
\x01 <COMMAND_REPLY>...</COMMAND_REPLY>         single-chunk reply
\x01 <COMMAND_REPLY>...partial...               first chunk of fragmented reply
\x02 ...middle of reply...                      continuation chunk
\x02 ...end</COMMAND_REPLY>                     final chunk
```

The leading byte `\x01`/`\x02` is a fragment marker. `\x02` ("more data will
follow") is sent by either side when a reply doesn't fit in a single ~1.4 KB
frame. The requester pulls subsequent chunks by re-sending the same
`<COMMAND>` prefixed with `\x02`.

### 2.4 Binary command channel (major=4)

Short writes (set/unset, inhibit, isolate, open door, etc.).

Request payload is 3 bytes for targeted writes (`<opcode> <target_id> <param>`)
or a single opcode byte for panel-wide actions. Opcodes:

| major | opcode | payload | action |
|-------|--------|---------|--------|
| 4 | 0x01 | 3 bytes | area set |
| 4 | 0x02 | 3 bytes | area unset |
| 4 | 0x03 | 3 bytes | zone inhibit |
| 4 | 0x04 | 3 bytes | zone deinhibit |
| 4 | 0x06 | 1 byte  | clock set |
| 4 | 0x07 | 1 byte  | pin set |
| 4 | 0x09 | 3 bytes | zone isolate |
| 4 | 0x0A | 3 bytes | zone deisolate |
| 4 | 0x0B | 1 byte  | alert restore |
| 4 | 0x0D | 3 bytes | output set |
| 4 | 0x0E | 3 bytes | output reset |
| 4 | 0x0F | 3 bytes | area set_a (part-set A) |
| 4 | 0x10 | 3 bytes | area set_b (part-set B) |
| 4 | 0x13 | 3 bytes | door inhibit |
| 4 | 0x14 | 3 bytes | door deinhibit |
| 4 | 0x15 | 3 bytes | door isolate |
| 4 | 0x16 | 3 bytes | door deisolate |
| 4 | 0x18 | 3 bytes | door open momentarily |
| 4 | 0x19 | 3 bytes | door open permanently |
| 4 | 0x1A | 3 bytes | door set normal mode |
| 4 | 0x1B | 3 bytes | door lock |
| 4 | 0x1C | 1 byte  | bell silence |
| 4 | 0x1D | 1 byte  | audio play |
| **5** | 0x04 | 1 byte | panel reset (panel-wide channel) |
| **5** | 0x07 | 1 byte | panel test (panel-wide channel) |

Reply payload (1 byte status):

| code | meaning | observed live |
|------|---------|---------------|
| 0xF0 | OK | ✅ (writes) |
| 0xF2 | Invalid parameters | ✅ (door cmds on a doorless panel) |
| 0xFC | Command is not implemented | ✅ (binary channel) |
| 0xFF | Command is not implemented | ✅ (panel channel; SPC4300 does not support panel/reset or panel/test) |

`0xFC` is also returned for operational commands such as area set/unset while
the panel is in engineer mode; the same command succeeds once the panel leaves
engineer mode.

Issuing an area set/unset (arm/disarm) makes the panel drop and re-establish
the EDP session, so a receiver should expect the connection to close and the
panel to re-dial shortly after an arm/disarm command.

### 2.5 Checksum (offset 19-20)

The 16-bit field at struct offsets 0x11-0x12 (== wire offsets 19-20) is a
**linear-shift register with byte-add (not XOR) mixing** into the low half.
Because the mixing uses byte-add rather than XOR, this is not a standard CRC
(CRCs are XOR-only and linear over GF(2)).

```python
def edp_checksum(struct_bytes: bytes, dlen: int) -> int:
    """`struct_bytes` is the in-memory frame (wire bytes minus the
    2-byte length prefix); `dlen` is the payload length."""
    end = dlen + 0x15
    state = 0xFFFF
    for i in range(end):
        if i == 0x11 or i == 0x12:  # skip the checksum slot itself
            continue
        carry = state & 0x8000
        state = (state << 1) & 0xFFFF
        state = (state & 0xFF00) | ((state + struct_bytes[i]) & 0xFF)
        if carry:
            state ^= 0xA097
    return state
```

**Parameters**: init = `0xFFFF`, poly = `0xA097`. Both halves of the 16-bit
state shift together, but only the low half is mixed with the input byte (via
add, truncated mod 256). The two bytes of the checksum slot itself (struct
offsets `0x11`, `0x12`) are skipped during the loop.

The SDK's `spcedp.wire.edp_checksum` implements this algorithm; the unit tests
pin it against captured HELLO / HELLO_ACK / SIA frames.

### 2.6 SIA event payload format (major=2)

ASCII, vertical-bar-delimited:

```
E2[#<spc_id>|<HHMMSSDDMMYYYY>|<sia_code>|<address>|<description>||<verification_id>]
```

Examples seen:

```
E2[#1000|08521203062026|NT|0|IP Link Fail||0]
E2[#1000|09153403062026|NR|0|IP Link Restore||0]
```

Note the timestamp layout is `HHMMSSDDMMYYYY`. Unknown SIA codes are passed
through rather than dropped.

### 2.7 Encryption

When the panel's EDP receiver is configured with a key, the tail of every
frame is replaced by AES-128-ECB ciphertext.

**Cipher and key:**
- Algorithm: AES-128-ECB.
- Key: 16 bytes, provisioned in the panel and supplied to the receiver as the
  same 16 raw bytes (or 32 hex digits).
- Padding: PKCS#7 is **disabled**. The plaintext is pre-padded with zeroes to
  the next 16-byte multiple, and the length prefix is bumped accordingly.

**Which bytes are encrypted:**

```
   wire offset    field                          encrypted?
   ───────────    ──────────────────────────     ───────────
   0-1            length prefix                  cleartext
   2              protocol byte (0x45)           cleartext
   3              version (0x02)                 cleartext
   4              flags                          cleartext  (bit 0 indicates
                                                              the rest is encrypted;
                                                              bit 3 still means
                                                              "from the receiver")
   5-8            sequence                       cleartext
   9-12           src ID                         cleartext
   13-16          dst ID                         cleartext
   17             major code                     ENCRYPTED
   18             minor code                     ENCRYPTED
   19-20          checksum                       ENCRYPTED
   21-22          dlen                           ENCRYPTED
   23..           payload                        ENCRYPTED + zero-padded
```

The cleartext region is exactly 15 bytes of struct (`pid` through `dst_id`).
Everything from `maj` onwards is encrypted as one AES-128-ECB block stream.

**Order of operations on encode:**

1. Build the frame as if cleartext.
2. Set the encrypted flag bit (`flags |= 0x01`).
3. Compute the checksum (over the pre-encryption struct, *with the encrypt bit
   already set*; see §2.5). The checksum is computed over the flag byte after
   the encrypt bit has been set (step 2), not before it.
4. Zero-pad the bytes from struct offset 15 onwards to a 16-byte boundary.
5. AES-128-ECB encrypt them.
6. Update the length prefix to reflect the new (possibly larger) size.

**Decode** is the same in reverse: read the length prefix, read the 17
cleartext bytes, AES-128-ECB-decrypt the rest, then proceed as cleartext.
