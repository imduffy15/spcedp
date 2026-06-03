"""Smoke tests for the panel-wide command channel (major=5)."""

from __future__ import annotations

import struct

from spcedp import PanelOp
from spcedp.wire import Frame, MajorCode


def test_panel_op_values() -> None:
    assert PanelOp.RESET == 0x04
    assert PanelOp.TEST == 0x07


def test_panel_command_frame_shape() -> None:
    """A major=5 frame carries a 1-byte payload (the opcode)."""
    f = Frame(
        src_id=1001,
        dst_id=1000,
        sequence=0xA1E92AAB,
        major=int(MajorCode.PANEL_CMD),
        minor=0,
        payload=bytes([int(PanelOp.TEST)]),
        src_flag=0x08,
    )
    wire = f.encode()
    decoded = Frame.decode(wire)
    assert decoded.major == int(MajorCode.PANEL_CMD)
    assert decoded.minor == 0
    assert decoded.payload == b"\x07"
    # Length-prefix on the wire should reflect 1-byte payload (23 hdr + 1 = 24, -2 = 22)
    assert struct.unpack_from("<H", wire, 0)[0] == 22


def test_panel_reply_round_trips() -> None:
    """A simulated panel reply with code 0xFF survives encode/decode."""
    reply = Frame(
        src_id=1000,
        dst_id=1001,
        sequence=0xA1E92AAB,
        major=int(MajorCode.PANEL_CMD),
        minor=1,  # panel-channel reply minor
        payload=b"\xff",
        src_flag=0x00,
    )
    wire = reply.encode()
    back = Frame.decode(wire)
    assert back.minor == 1
    assert back.payload == b"\xff"
