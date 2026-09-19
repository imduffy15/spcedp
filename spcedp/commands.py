"""High-level command catalogue.

Two command families coexist:

  XML commands (major=10) - structured queries that return XML replies
  Binary commands (major=4) - 3-byte writes with a 1-byte status reply
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# XML commands (major=10)
# ---------------------------------------------------------------------------

# These are the COMMAND IDs reverse-engineered from the XML command channel
# and verified against a live SPC4300 panel.

XML_INFO = "info"
XML_STATUS = "status"
XML_AREA_STATUS = "area_status"
XML_ENET_STATUS = "enet_status"
XML_ZONE_STATUS = "zone_status"
XML_DOOR_STATUS = "door_status"
XML_VERIFICATION_STATUS = "verification_status"
XML_OUTPUT_STATUS = "output_status"
XML_SYSTEM_LOG = "system_log"
XML_ACCESS_LOG = "access_log"
XML_ZONE_LOG = "zone_log"
XML_WIRELESS_LOG = "wireless_log"


# ---------------------------------------------------------------------------
# Binary commands (major=4)
# ---------------------------------------------------------------------------


class BinaryOp(enum.IntEnum):
    """Opcodes for the binary command family (major=4).

    Every opcode here has a verified wire shape EXCEPT ``CLOCK_SET`` (0x06)
    and ``PIN_SET`` (0x07); see the note on those members below.
    `GLOBAL_OPS` below lists the opcodes whose payload is a single byte
    (panel-wide, no target); every other opcode uses the 3-byte
    `<opcode> <target_id> <param>` shape.

    Replies are a 1-byte status code; see `spcedp.errors.ReplyCode`
    (e.g. 0xF0 = OK, 0xF2 = invalid params, 0xFC = not implemented).
    """

    # 3-byte payloads (with target id + param)
    AREA_SET = 0x01
    AREA_UNSET = 0x02
    ZONE_INHIBIT = 0x03
    ZONE_DEINHIBIT = 0x04
    ZONE_ISOLATE = 0x09
    ZONE_DEISOLATE = 0x0A
    OUTPUT_SET = 0x0D
    OUTPUT_RESET = 0x0E
    AREA_SET_A = 0x0F
    AREA_SET_B = 0x10
    DOOR_INHIBIT = 0x13
    DOOR_DEINHIBIT = 0x14
    DOOR_ISOLATE = 0x15
    DOOR_DEISOLATE = 0x16
    DOOR_OPEN_MOMENTARY = 0x18
    DOOR_OPEN_PERMANENT = 0x19
    DOOR_SET_NORMAL = 0x1A
    DOOR_LOCK = 0x1B

    # 1-byte payloads (panel-wide, no target)
    ALERT_RESTORE = 0x0B
    BELL_SILENCE = 0x1C
    AUDIO_PLAY = 0x1D

    # UNVERIFIED wire shape - kept for documentation/identification only.
    # CLOCK_SET sets the panel clock and PIN_SET changes a user PIN, so each
    # MUST carry a time/PIN payload; a bare 1-byte opcode cannot. The real
    # payload layout has never been observed on the wire, so these are
    # deliberately excluded from GLOBAL_OPS and are NOT exposed via the Panel
    # facade (no set_clock/set_pin). Do not encode either via BinaryCommand
    # until the payload shape is captured and verified against a live panel.
    CLOCK_SET = 0x06
    PIN_SET = 0x07


# Opcodes that take only a 1-byte payload (themselves), with no target/param.
# Note: CLOCK_SET/PIN_SET are intentionally absent - their payload shape is
# unverified (a 1-byte opcode cannot carry a time/PIN), so they are not
# encodable as global ops and not surfaced on the Panel facade.
GLOBAL_OPS = frozenset(
    {
        BinaryOp.ALERT_RESTORE,
        BinaryOp.BELL_SILENCE,
        BinaryOp.AUDIO_PLAY,
    }
)


class PanelOp(enum.IntEnum):
    """Opcodes for the panel-wide command family (major=5).

    Each request is a 1-byte payload (the opcode).  Reply is a 1-byte
    status code, same encoding as `BinaryOp` replies.

    Found by probing the major=5 channel and verified live:
        panel reset  ->  major=5, op=0x04
        panel test   ->  major=5, op=0x07
    """

    RESET = 0x04
    TEST = 0x07


@dataclass(slots=True)
class BinaryCommand:
    """A binary-channel (major=4) command, with its two wire shapes.

    The opcode selects the shape (see `GLOBAL_OPS`):
      - a global op (e.g. ``BELL_SILENCE``) encodes to a single opcode
        byte; ``target_id``/``param`` must stay 0 (a non-zero value raises).
      - any other op encodes to the 3-byte ``op target_id param`` payload.
    """

    op: BinaryOp | int
    target_id: int = 0
    param: int = 0

    def encode(self) -> bytes:
        op_val = int(self.op) & 0xFF
        # IntEnum members compare/hash equal to their int value, so a raw int
        # opcode is matched against GLOBAL_OPS directly - no enum coercion.
        if op_val in GLOBAL_OPS:
            if self.target_id or self.param:
                raise ValueError(
                    f"op {op_val:#04x} is a global command and takes no "
                    f"target_id/param (got target_id={self.target_id}, "
                    f"param={self.param})"
                )
            return bytes([op_val])
        return bytes([op_val, self.target_id & 0xFF, self.param & 0xFF])
