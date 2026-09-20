"""spcedp - Async Python SDK for Vanderbilt SPC alarm panels.

Speaks the EDP v2 wire protocol directly to the panel: the panel
dials in over TCP, we play the role of EDP receiver, and
issue commands / read state / surface SIA events.

Entry point: PanelServer / Panel (see examples/listen.py).
"""

from importlib.metadata import PackageNotFoundError, version

from .client import PanelServer, Session
from .commands import (
    XML_ACCESS_LOG,
    XML_AREA_STATUS,
    XML_DOOR_STATUS,
    XML_ENET_STATUS,
    XML_INFO,
    XML_OUTPUT_STATUS,
    XML_STATUS,
    XML_SYSTEM_LOG,
    XML_VERIFICATION_STATUS,
    XML_WIRELESS_LOG,
    XML_ZONE_LOG,
    XML_ZONE_STATUS,
    BinaryCommand,
    BinaryOp,
    PanelOp,
)
from .errors import (
    PanelRejected,
    ReplyCode,
    SpcConnectionLost,
    SpcError,
    SpcProtocolError,
    SpcTimeout,
    reply_message,
)
from .events import SiaEvent
from .panel import (
    Area,
    ArmMode,
    EventStateUpdate,
    Panel,
    PanelInfo,
    Zone,
    ZoneInput,
    ZoneType,
)
from .wire import EncryptionRequired, Frame, FrameDecodeError, FrameDecoder, MajorCode, MinorCode
from .xmlcmd import AttrValue, Row, XmlReply

try:
    __version__ = version("spcedp")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0+unknown"

__all__ = [
    # High-level facade
    "Panel",
    "PanelServer",
    "PanelInfo",
    "Session",
    "Area",
    "ArmMode",
    "ZoneInput",
    "ZoneType",
    "EventStateUpdate",
    "Zone",
    "SiaEvent",
    # Wire layer
    "Frame",
    "FrameDecoder",
    "FrameDecodeError",
    "EncryptionRequired",
    "MajorCode",
    "MinorCode",
    # Commands & status codes
    "BinaryCommand",
    "BinaryOp",
    "PanelOp",
    "ReplyCode",
    "reply_message",
    # Exceptions
    "SpcError",
    "PanelRejected",
    "SpcTimeout",
    "SpcConnectionLost",
    "SpcProtocolError",
    # XML command IDs (arguments to Session.xml_command)
    "XML_INFO",
    "XML_STATUS",
    "XML_AREA_STATUS",
    "XML_ENET_STATUS",
    "XML_ZONE_STATUS",
    "XML_DOOR_STATUS",
    "XML_VERIFICATION_STATUS",
    "XML_OUTPUT_STATUS",
    "XML_SYSTEM_LOG",
    "XML_ACCESS_LOG",
    "XML_ZONE_LOG",
    "XML_WIRELESS_LOG",
    # Public type aliases (XML command layer)
    "XmlReply",
    "Row",
    "AttrValue",
]
