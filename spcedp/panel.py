"""High-level Panel facade.

Wraps a Session and a snapshot of the panel's static metadata + live state
behind ergonomic accessors:

    panel = await Panel.from_session(session)
    print(panel.info.type, panel.info.version)
    for zone in panel.zones.values():
        print(zone.id, zone.name, zone.status)
    await panel.zone(1).inhibit()
    await panel.zone(1).deinhibit()
    async for event in panel.events():
        print(event.timestamp, event.sia_code, event.description)
"""

from __future__ import annotations

import enum
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

from .client import Session
from .commands import (
    XML_AREA_STATUS,
    XML_DOOR_STATUS,
    XML_ENET_STATUS,
    XML_INFO,
    XML_OUTPUT_STATUS,
    XML_STATUS,
    XML_VERIFICATION_STATUS,
    XML_ZONE_STATUS,
    BinaryOp,
    PanelOp,
)
from .events import SiaEvent
from .xmlcmd import Row, XmlReply

log = logging.getLogger("spcedp")


class ArmMode(enum.Enum):
    """Decoded arm state of an :class:`Area`.

    Keyed off the panel's raw ``MODE`` token: "0"=UNSET, "1"=PART_A,
    "2"=PART_B, "3"=FULL.  An unrecognised token maps to ``None`` (see
    ``Area.arm_mode``), never silently to ``UNSET``.
    """

    UNSET = "0"
    PART_A = "1"
    PART_B = "2"
    FULL = "3"


class ZoneType(enum.Enum):
    """Decoded function/type of a :class:`Zone`.

    Keyed off the panel's raw ``TYPE`` token (a numeric string).  The
    enumeration is the SPC zone-input-type catalogue - the same codes the SPC
    Web Gateway surfaces - and was cross-checked against a live SPC4300 (e.g.
    an entry/exit hallway reports ``TYPE="1"``).  An unrecognised token maps to
    ``None`` (see ``Zone.zone_type``), never silently to a wrong type; the raw
    ``type`` string stays the source of truth for diagnostics.
    """

    ALARM = "0"
    ENTRY_EXIT = "1"
    EXIT_TERMINATOR = "2"
    FIRE = "3"
    FIRE_EXIT = "4"
    LINE = "5"
    PANIC = "6"
    HOLD_UP = "7"
    TAMPER = "8"
    TECHNICAL = "9"
    MEDICAL = "10"
    KEYARM = "11"
    UNUSED = "12"
    SHUNT = "13"
    X_SHUNT = "14"
    FAULT = "15"
    LOCK_SUPERVISION = "16"
    SEISMIC = "17"
    ALL_OKAY = "18"
    HOLDUP_FAULT = "19"
    WARNING_FAULT = "20"
    SETTING_AUTHORISATION = "21"
    LOCK_ELEMENT = "22"
    GLASSBREAK = "23"
    WATER = "24"
    HEAT = "25"
    FRIDGE_FREEZER = "26"
    GAS = "27"
    SPRINKLER = "28"
    CO = "29"
    ENTRY_EXIT_2 = "30"


# ---------------------------------------------------------------------------
# Plain dataclasses for snapshot state
# ---------------------------------------------------------------------------


def _parse_id(row: Row, kind: str) -> int | None:
    """Return a row's numeric ID, or None (with a warning) if it is missing or
    non-numeric, so one bad row can't abort a whole refresh."""
    raw = row.get("ID")
    if raw is None or not raw.isdigit():
        log.warning("skipping %s row with missing/invalid ID: %r", kind, row)
        return None
    return int(raw)


@dataclass(slots=True)
class PanelInfo:
    """Static panel identity from the INFO command (values are raw strings)."""

    type: str = ""
    variant: str = ""
    version: str = ""
    device_id: str = ""
    sn: str = ""
    hw_ver_major: str = ""
    hw_ver_minor: str = ""
    license_key: str = ""

    @classmethod
    def from_row(cls, row: Row) -> PanelInfo:
        return cls(
            type=row.get("TYPE", ""),
            variant=row.get("VARIANT", ""),
            version=row.get("VERSION", ""),
            device_id=row.get("DEVICE-ID", ""),
            sn=row.get("SN", ""),
            hw_ver_major=row.get("HW_VER_MAJOR", ""),
            hw_ver_minor=row.get("HW_VER_MINOR", ""),
            license_key=row.get("LICENSE_KEY", ""),
        )


@dataclass(slots=True)
class Area:
    """One alarm area and its live arm state.

    String fields hold the panel's raw values.  `mode` is "0"=unset,
    "1"=part-set A, "2"=part-set B, "3"=full-set.  The `last_*` fields and
    `not_ready_set` are passed through verbatim from the panel.
    """

    id: int
    name: str = ""
    mode: str = "0"
    last_set_time: str = ""
    last_unset_time: str = ""
    last_set_user_id: str = ""
    last_set_user_name: str = ""
    last_unset_user_id: str = ""
    last_unset_user_name: str = ""
    last_alarm: str = ""
    not_ready_set: str = ""

    @property
    def arm_mode(self) -> ArmMode | None:
        """Typed view of the raw ``mode`` token.

        Returns the matching :class:`ArmMode`, or ``None`` for a token the
        firmware emits that this release does not recognise - an unknown
        value is never silently treated as ``UNSET``.  The raw ``mode``
        string stays the source of truth for diagnostics.
        """
        try:
            return ArmMode(self.mode)
        except ValueError:
            log.warning("area %d has unrecognised MODE token %r", self.id, self.mode)
            return None

    @property
    def is_armed(self) -> bool | None:
        """``True`` if the area is set in any mode (part or full), ``False`` if
        unset, ``None`` if the raw ``mode`` token is unrecognised."""
        mode = self.arm_mode
        if mode is None:
            return None
        return mode is not ArmMode.UNSET

    @classmethod
    def from_row(cls, row: Row) -> Area | None:
        area_id = _parse_id(row, "area")
        if area_id is None:
            return None
        return cls(
            id=area_id,
            name=row.get("NAME", ""),
            mode=row.get("MODE", "0"),
            last_set_time=row.get("LAST_SET_TIME", ""),
            last_unset_time=row.get("LAST_UNSET_TIME", ""),
            last_set_user_id=row.get("LAST_SET_USER_ID", ""),
            last_set_user_name=row.get("LAST_SET_USER_NAME", ""),
            last_unset_user_id=row.get("LAST_UNSET_USER_ID", ""),
            last_unset_user_name=row.get("LAST_UNSET_USER_NAME", ""),
            last_alarm=row.get("LAST_ALARM", ""),
            not_ready_set=row.get("NOT_READY_SET", ""),
        )


@dataclass(slots=True)
class Zone:
    """One detection zone.

    `type`, `status`, `proc_state`, `input` and `logic_input` are the
    panel's raw strings (e.g. `status` "0"=closed / "1"=open / "2"=isolated).
    The `*_allowed` booleans are derived from the panel's "1"/"0" flags.
    """

    id: int
    type: str
    name: str
    area_id: int
    area_name: str
    input: str
    logic_input: str
    status: str
    proc_state: str
    inhibit_allowed: bool
    isolate_allowed: bool

    @property
    def is_open(self) -> bool | None:
        """Typed view of the raw ``status`` token: ``True`` for "1" (open),
        ``False`` for "0" (closed), ``None`` for any other value.  An
        unrecognised token is never silently reported as closed; the raw
        ``status`` string remains the diagnostic source of truth."""
        if self.status == "1":
            return True
        if self.status == "0":
            return False
        return None

    @property
    def zone_type(self) -> ZoneType | None:
        """Typed view of the raw ``type`` token.

        Returns the matching :class:`ZoneType`, or ``None`` when the zone
        reports no type or a token this release does not recognise - an unknown
        value is never silently mapped to a wrong type.  The raw ``type`` string
        stays the source of truth for diagnostics.
        """
        if not self.type:
            return None
        try:
            return ZoneType(self.type)
        except ValueError:
            log.warning("zone %d has unrecognised TYPE token %r", self.id, self.type)
            return None

    @classmethod
    def from_row(cls, row: Row) -> Zone | None:
        zone_id = _parse_id(row, "zone")
        if zone_id is None:
            return None
        return cls(
            id=zone_id,
            type=row.get("TYPE", ""),
            name=row.get("ZONE_NAME", ""),
            area_id=int(row.get("AREA", "0") or 0),
            area_name=row.get("AREA_NAME", ""),
            input=row.get("INPUT", ""),
            logic_input=row.get("LOGIC_INPUT", ""),
            status=row.get("STATUS", ""),
            proc_state=row.get("PROC_STATE", ""),
            inhibit_allowed=row.get("INHIBIT_ALLOWED") == "1",
            isolate_allowed=row.get("ISOLATE_ALLOWED") == "1",
        )


@dataclass(slots=True)
class Output:
    """One controllable output (e.g. a siren); `state` is the panel's raw string."""

    id: int
    name: str
    state: str

    @property
    def is_active(self) -> bool | None:
        """Typed view of the raw ``state`` token: ``True`` for "1" (active),
        ``False`` for "0" (inactive), ``None`` for any other value.  An
        unrecognised token is never silently reported as inactive; the raw
        ``state`` string remains the diagnostic source of truth."""
        if self.state == "1":
            return True
        if self.state == "0":
            return False
        return None

    @classmethod
    def from_row(cls, row: Row) -> Output | None:
        output_id = _parse_id(row, "output")
        if output_id is None:
            return None
        return cls(
            id=output_id,
            name=row.get("NAME", ""),
            state=row.get("STATE", ""),
        )


@dataclass(slots=True)
class Door:
    """One access-control door; ``state`` is the panel's raw string.

    The attribute set is inferred from the DOOR_STATUS schema and may need
    re-confirmation against a panel that actually has doors configured.
    """

    id: int
    name: str
    state: str

    @classmethod
    def from_row(cls, row: Row) -> Door | None:
        door_id = _parse_id(row, "door")
        if door_id is None:
            return None
        return cls(
            id=door_id,
            name=row.get("NAME", ""),
            state=row.get("STATE", ""),
        )


# ---------------------------------------------------------------------------
# Panel - high-level facade
# ---------------------------------------------------------------------------


class Panel:
    """A connected SPC panel exposed as a friendly object graph.

    Build with the async `Panel.from_session(...)` classmethod rather than
    the constructor directly: `from_session` waits for the handshake and
    loads the initial state.

    SNAPSHOT SEMANTICS (important): `info`, `areas`, `zones`, `outputs` and
    `doors` are a point-in-time snapshot captured by the last `refresh*`
    call (see `last_refresh`).  They do NOT track the live event stream on
    their own: after a `refresh()` the panel may arm, disarm, or trip zones
    and the snapshot will be stale until the next `refresh*`.  `apply_event`
    offers a best-effort in-place reconciliation for clearly-mappable SIA
    codes, but the authoritative way to resync is to call `refresh*` again.

    The snapshot is also stale after a disconnect: a `Panel` does not
    reconnect itself and `last_refresh` keeps the time of the last
    successful read regardless of connection state.  Detecting a dropped
    session, reconnecting, and re-refreshing is the caller's responsibility.
    """

    def __init__(self, session: Session):
        """Wrap a Session.  Prefer `Panel.from_session()`: a directly
        constructed Panel is un-refreshed (empty info/areas/zones/outputs/
        doors, `last_refresh` is None) and assumes the EDP handshake has
        already completed."""
        self._session = session
        self.info = PanelInfo()
        self.areas: dict[int, Area] = {}
        self.zones: dict[int, Zone] = {}
        self.outputs: dict[int, Output] = {}
        self.doors: dict[int, Door] = {}
        self.last_refresh: datetime | None = None

    # ------------------------------------------------------------------ refresh
    @classmethod
    async def from_session(cls, session: Session, *, wait_polls: int = 1) -> Panel:
        """Build a Panel once the panel is ready, then load its full state.

        Waits for the EDP handshake (HELLO + at least `wait_polls` POLL
        exchanges) before issuing any command - firing early makes the panel
        drop the connection - then refreshes info/areas/zones/outputs.
        """
        await session.wait_ready(min_polls=wait_polls)
        self = cls(session)
        await self.refresh()
        return self

    async def refresh(self) -> None:
        """Pull the full picture from the panel and stamp `last_refresh`."""
        info = await self._session.xml_command(XML_INFO)
        self._apply_info(info)
        await self.refresh_areas()
        await self.refresh_zones()
        await self.refresh_outputs()
        await self.refresh_doors()
        self.last_refresh = datetime.now(UTC)

    async def refresh_areas(self) -> None:
        """Rebuild `areas` from a fresh AREA_STATUS read.

        The dict is replaced wholesale, so areas the panel no longer reports
        (deleted or renumbered) disappear instead of lingering as stale
        ghosts with frozen state.
        """
        reply = await self._session.xml_command(XML_AREA_STATUS)
        areas: dict[int, Area] = {}
        for row in reply.get("AREA_STATUS", []):
            area = Area.from_row(row)
            if area is not None:
                areas[area.id] = area
        self.areas = areas

    async def refresh_zones(self) -> None:
        """Rebuild `zones` from a fresh ZONE_STATUS read (see `refresh_areas`
        for the no-stale-ghosts rationale)."""
        reply = await self._session.xml_command(XML_ZONE_STATUS)
        zones: dict[int, Zone] = {}
        for row in reply.get("ZONE_STATUS", []):
            zone = Zone.from_row(row)
            if zone is not None:
                zones[zone.id] = zone
        self.zones = zones

    async def refresh_outputs(self) -> None:
        """Rebuild `outputs` from a fresh OUTPUT_STATUS read (see
        `refresh_areas` for the no-stale-ghosts rationale)."""
        reply = await self._session.xml_command(XML_OUTPUT_STATUS)
        outputs: dict[int, Output] = {}
        for row in reply.get("OUTPUT_STATUS", []):
            output = Output.from_row(row)
            if output is not None:
                outputs[output.id] = output
        self.outputs = outputs

    async def refresh_doors(self) -> None:
        """Rebuild `doors` from a fresh DOOR_STATUS read (see `refresh_areas`
        for the no-stale-ghosts rationale)."""
        reply = await self._session.xml_command(XML_DOOR_STATUS)
        doors: dict[int, Door] = {}
        for row in reply.get("DOOR_STATUS", []):
            door = Door.from_row(row)
            if door is not None:
                doors[door.id] = door
        self.doors = doors

    # ------------------------------------------------------------------ read-only XML
    async def status(self) -> XmlReply:
        """Return the parsed STATUS reply (panel-wide status), unmodelled."""
        return await self._session.xml_command(XML_STATUS)

    async def enet_status(self) -> XmlReply:
        """Return the parsed ENET_STATUS reply (Ethernet status), unmodelled."""
        return await self._session.xml_command(XML_ENET_STATUS)

    async def verification(self) -> XmlReply:
        """Return the parsed VERIFICATION_STATUS reply, unmodelled."""
        return await self._session.xml_command(XML_VERIFICATION_STATUS)

    async def system_log(self, max_events: int) -> XmlReply:
        """Return the parsed system event log, capped at `max_events` rows."""
        return await self._session.xml_command("system_log", MAX_EVENTS=max_events)

    async def zone_log(self, zone_id: int) -> XmlReply:
        """Return the parsed event log for a single zone."""
        return await self._session.xml_command("zone_log", ZONE=zone_id)

    def _apply_info(self, reply: XmlReply) -> None:
        rows = reply.get("INFO", [])
        self.info = PanelInfo.from_row(rows[0]) if rows else PanelInfo()

    # ------------------------------------------------------------------ control
    def zone(self, zone_id: int) -> ZoneControl:
        return ZoneControl(self._session, zone_id)

    def area(self, area_id: int) -> AreaControl:
        return AreaControl(self._session, area_id)

    def output(self, output_id: int) -> OutputControl:
        return OutputControl(self._session, output_id)

    def door(self, door_id: int) -> DoorControl:
        return DoorControl(self._session, door_id)

    # ------------------------------------------------------------------ global
    async def alert_restore(self) -> None:
        await self._session.binary_command(BinaryOp.ALERT_RESTORE)

    async def bell_silence(self) -> None:
        await self._session.binary_command(BinaryOp.BELL_SILENCE)

    async def audio_play(self) -> None:
        await self._session.binary_command(BinaryOp.AUDIO_PLAY)

    # ------------------------------------------------------------------ panel-wide (major=5)
    async def reset(self) -> None:
        """Reset the panel."""
        await self._session.panel_command(PanelOp.RESET)

    async def test(self) -> None:
        """Run the panel self-test."""
        await self._session.panel_command(PanelOp.TEST)

    # ------------------------------------------------------------------ events
    def events(self) -> AsyncIterator[SiaEvent]:
        """Stream SIA events as they arrive (delegates to the Session feed)."""
        return self._session.events()

    def apply_event(self, ev: SiaEvent) -> None:
        """Best-effort in-place reconciliation of the snapshot from a SIA event.

        This is a CONVENIENCE, not a source of truth.  It mutates the raw
        ``status``/``mode`` of an already-known zone/area for a small set of
        clearly-mappable SIA codes (zone open/close, area arm/disarm) so the
        snapshot tracks obvious changes between full refreshes.  For every
        other code - and whenever ``ev.address`` does not resolve to a known
        entity - it is a deliberate no-op (logged at debug, never raised),
        because guessing would risk reporting a wrong state.

        The authoritative resync is always a `refresh*` call: codes are not
        exhaustively mapped, the panel may have changed in ways no single
        event reflects, and unrecognised firmware tokens are left untouched.
        Alarm codes flip the offending zone to open but never derive an
        area's arm mode, which the alarm event does not carry.
        """
        code = ev.sia_code.upper()
        addr = ev.address.strip()
        if not addr.isdigit():
            log.debug("apply_event: non-numeric address %r for %s; ignoring", ev.address, code)
            return
        target = int(addr)

        # Zone open/close (and alarm-implies-open).  ZC is the only close code;
        # ZO and the burglary/fire/panic/holdup/tamper alarm families imply open.
        zone_open: bool | None = None
        if code == "ZC":
            zone_open = False
        elif code in {"ZO", "BA", "FA", "PA", "HA", "TA"}:
            zone_open = True
        if zone_open is not None:
            zone = self.zones.get(target)
            if zone is None:
                log.debug("apply_event: %s for unknown zone %d; ignoring", code, target)
                return
            zone.status = "1" if zone_open else "0"
            return

        # Area arm/disarm.  OP=opening/disarm -> UNSET; CL=closing/arm.  The SIA
        # close event does not distinguish part-set from full-set, so a generic
        # close is recorded as FULL; the exact mode is reconciled by refresh().
        if code == "OP":
            area = self.areas.get(target)
            if area is None:
                log.debug("apply_event: OP for unknown area %d; ignoring", target)
                return
            area.mode = ArmMode.UNSET.value
            return
        if code == "CL":
            area = self.areas.get(target)
            if area is None:
                log.debug("apply_event: CL for unknown area %d; ignoring", target)
                return
            area.mode = ArmMode.FULL.value
            return

        log.debug("apply_event: no mapping for SIA code %r; ignoring", code)


# ---------------------------------------------------------------------------
# Control objects - thin wrappers that issue binary commands
# ---------------------------------------------------------------------------


class ZoneControl:
    def __init__(self, sess: Session, zone_id: int):
        self._s = sess
        self._id = zone_id

    async def inhibit(self) -> None:
        await self._s.binary_command(BinaryOp.ZONE_INHIBIT, self._id)

    async def deinhibit(self) -> None:
        await self._s.binary_command(BinaryOp.ZONE_DEINHIBIT, self._id)

    async def isolate(self) -> None:
        await self._s.binary_command(BinaryOp.ZONE_ISOLATE, self._id)

    async def deisolate(self) -> None:
        await self._s.binary_command(BinaryOp.ZONE_DEISOLATE, self._id)


class AreaControl:
    """Arm / disarm controls (verified live).

    IMPORTANT: issuing any of these (area set/unset/part-set) makes the panel
    drop and re-establish the EDP session (see ``PROTOCOL.md`` §2.4). The panel
    often disconnects before it sends the 1-byte reply, so the command can raise
    ``SpcConnectionLost`` (or ``SpcTimeout``) even though it was applied. A caller
    should treat a connection error from these methods as "probably applied,
    expect the panel to re-dial shortly" and resync from the new session rather
    than surfacing it as a failure. A ``PanelRejected`` (e.g. engineer mode) is a
    genuine rejection.
    """

    def __init__(self, sess: Session, area_id: int):
        self._s = sess
        self._id = area_id

    async def set(self) -> None:
        await self._s.binary_command(BinaryOp.AREA_SET, self._id)

    async def set_a(self) -> None:
        await self._s.binary_command(BinaryOp.AREA_SET_A, self._id)

    async def set_b(self) -> None:
        await self._s.binary_command(BinaryOp.AREA_SET_B, self._id)

    async def unset(self) -> None:
        await self._s.binary_command(BinaryOp.AREA_UNSET, self._id)


class OutputControl:
    """Output (e.g. siren) set / reset (verified live)."""

    def __init__(self, sess: Session, output_id: int):
        self._s = sess
        self._id = output_id

    async def set(self) -> None:
        await self._s.binary_command(BinaryOp.OUTPUT_SET, self._id)

    async def reset(self) -> None:
        await self._s.binary_command(BinaryOp.OUTPUT_RESET, self._id)


class DoorControl:
    """Door state controls (opcodes verified, gates rejected on a panel
    with no doors configured - results on a panel with doors configured
    will need re-verification)."""

    def __init__(self, sess: Session, door_id: int):
        self._s = sess
        self._id = door_id

    async def inhibit(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_INHIBIT, self._id)

    async def deinhibit(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_DEINHIBIT, self._id)

    async def isolate(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_ISOLATE, self._id)

    async def deisolate(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_DEISOLATE, self._id)

    async def open_momentary(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_OPEN_MOMENTARY, self._id)

    async def open_permanent(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_OPEN_PERMANENT, self._id)

    async def set_normal_mode(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_SET_NORMAL, self._id)

    async def lock(self) -> None:
        await self._s.binary_command(BinaryOp.DOOR_LOCK, self._id)
