"""Reply-code mapping and exception types."""

from __future__ import annotations

import enum


class ReplyCode(enum.IntEnum):
    """Single-byte status code returned in a CMD_REPLY payload."""

    OK = 0xF0
    MORE_DATA_FOLLOWS = 0xF1  # not seen on the wire; not handled
    INVALID_PARAMS = 0xF2  # seen on the wire
    PANEL_WAITING = 0xF3  # not seen on the wire
    PANEL_ENGINEER = 0xF4  # not seen on the wire
    NOT_POSSIBLE_NOW = 0xF5  # not seen on the wire
    NOT_PERMITTED = 0xFB  # not seen on the wire
    NOT_IMPLEMENTED = 0xFC  # seen on the wire (binary; also engineer-mode-blocked)
    NOT_IMPLEMENTED_PANEL = 0xFF  # seen on the wire (panel channel, maj=5)


_REPLY_MESSAGES = {
    ReplyCode.OK: "ok",
    ReplyCode.MORE_DATA_FOLLOWS: "More data will follow",
    ReplyCode.INVALID_PARAMS: "Invalid parameters",
    ReplyCode.PANEL_WAITING: "Panel is waiting for data",
    ReplyCode.PANEL_ENGINEER: "Panel is in full engineer mode",
    ReplyCode.NOT_POSSIBLE_NOW: "Command is not possible now",
    ReplyCode.NOT_PERMITTED: "Command is not permitted",
    ReplyCode.NOT_IMPLEMENTED: "Command is not implemented",
    ReplyCode.NOT_IMPLEMENTED_PANEL: "Command is not implemented (panel channel)",
}


def reply_message(code: int) -> str:
    try:
        return _REPLY_MESSAGES[ReplyCode(code)]
    except ValueError:
        return f"unknown reply code {code:#04x}"


# Reply codes the panel may return transiently; the same command can succeed if
# retried later (panel busy / waiting / engineer mode).
_TRANSIENT_CODES = frozenset(
    {
        ReplyCode.PANEL_WAITING,
        ReplyCode.PANEL_ENGINEER,
        ReplyCode.NOT_POSSIBLE_NOW,
    }
)


class SpcError(Exception):
    """Root base for every error raised by this SDK."""


class PanelRejected(SpcError):
    """Raised when the panel returns a non-OK reply code to a command."""

    def __init__(self, code: int, *, command: str | None = None):
        self.code = code
        self.command = command
        super().__init__(
            f"{reply_message(code)} (code={code:#04x})" + (f" for {command!r}" if command else "")
        )

    @property
    def is_transient(self) -> bool:
        """True if the reply code is retryable (panel busy/waiting/engineer)."""
        return self.code in _TRANSIENT_CODES


class SpcTimeout(SpcError):
    """Raised when the panel does not reply within the expected time."""


class SpcConnectionLost(SpcError):
    """Raised when the panel connection is dropped mid-command."""


class SpcProtocolError(SpcError):
    """Raised when received data violates the EDP protocol."""
