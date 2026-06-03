"""Tests for ReplyCode -> message mapping and the PanelRejected exception."""

from __future__ import annotations

from spcedp.errors import PanelRejected, ReplyCode, reply_message


def test_reply_message_known_codes() -> None:
    assert reply_message(ReplyCode.OK) == "ok"
    assert reply_message(0xF2) == "Invalid parameters"
    assert reply_message(ReplyCode.PANEL_WAITING) == "Panel is waiting for data"
    assert reply_message(0xFC) == "Command is not implemented"


def test_reply_message_unknown_code() -> None:
    msg = reply_message(0x42)
    assert "unknown reply code" in msg
    assert "0x42" in msg


def test_panel_rejected_exposes_code_and_command() -> None:
    err = PanelRejected(0xFC, command="op=3 target=1")
    assert err.code == 0xFC
    assert err.command == "op=3 target=1"
    text = str(err)
    assert "not implemented" in text.lower()
    assert "op=3 target=1" in text
    assert "0xfc" in text


def test_panel_rejected_without_command() -> None:
    err = PanelRejected(0xF2)
    assert err.command is None
    assert "Invalid parameters" in str(err)
