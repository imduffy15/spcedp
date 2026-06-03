"""Tests for BinaryCommand encoding (1-byte global vs 3-byte op/target/param)."""

from __future__ import annotations

import pytest

from spcedp.commands import BinaryCommand, BinaryOp


def test_three_byte_payload() -> None:
    assert BinaryCommand(BinaryOp.AREA_SET, 3, 1).encode() == b"\x01\x03\x01"


def test_three_byte_payload_defaults_to_zero() -> None:
    assert BinaryCommand(BinaryOp.ZONE_INHIBIT, 7).encode() == b"\x03\x07\x00"


def test_one_byte_global_payload() -> None:
    assert BinaryCommand(BinaryOp.BELL_SILENCE).encode() == b"\x1c"


def test_raw_int_opcode_uses_three_byte_shape() -> None:
    # An opcode not in the enum falls through to the 3-byte form.
    assert BinaryCommand(0x99, 5, 2).encode() == b"\x99\x05\x02"


def test_global_op_rejects_target_or_param() -> None:
    with pytest.raises(ValueError, match="global command"):
        BinaryCommand(BinaryOp.BELL_SILENCE, target_id=5).encode()
    with pytest.raises(ValueError, match="global command"):
        BinaryCommand(BinaryOp.AUDIO_PLAY, param=1).encode()
