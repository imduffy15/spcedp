"""EDP queries and commands used for sensors and alarm control."""

from enum import IntEnum

XML_INFO = "info"
XML_AREA_STATUS = "area_status"
XML_ZONE_STATUS = "zone_status"


class BinaryOp(IntEnum):
    """Alarm-area commands (major 4, payload: opcode, area ID, zero)."""

    AREA_SET = 0x01
    AREA_UNSET = 0x02
    AREA_SET_A = 0x0F
    AREA_SET_B = 0x10
