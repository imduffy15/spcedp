"""Panel snapshots, pushed sensor updates and alarm-area controls."""

from __future__ import annotations

import enum
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime

from .client import Session
from .commands import (
    XML_AREA_STATUS,
    XML_INFO,
    XML_ZONE_STATUS,
    BinaryOp,
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


class ZoneInput(enum.StrEnum):
    """Physical input tokens reported by ``ZONE_STATUS``.

    ``OPEN`` and ``CLOSED`` describe a circuit directly. The other values
    are panel fault/supervision states rather than a reliable open/closed
    indication, so :attr:`Zone.is_open` returns ``None`` for them.
    """

    CLOSED = "0"
    OPEN = "1"
    SHORT = "2"
    DISCONNECTED = "3"
    PIR_MASKED = "4"
    DC_SUBSTITUTION = "5"
    SENSOR_MISSING = "6"
    OFFLINE = "7"


class ZoneType(enum.StrEnum):
    """Zone ``TYPE`` tokens documented by the SPC Web Gateway."""

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
    KEY_ARM = "11"
    UNUSED = "12"
    SHUNT = "13"
    X_SHUNT = "14"
    FAULT = "15"
    LOCK_SUPERVISION = "16"
    SEISMIC = "17"
    ALL_OKAY = "18"
    HOLD_UP_FAULT = "19"
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


@dataclass(frozen=True, slots=True)
class EventStateUpdate:
    """Snapshot objects changed by :meth:`Panel.apply_event`.

    This is intentionally small and framework-neutral. Consumers can update
    only the entities that changed without duplicating protocol SIA routing.
    """

    zone_ids: frozenset[int] = frozenset()
    area_ids: frozenset[int] = frozenset()


# SPC firmware does not expose a reliable, universal arm-mode mapping in the
# SIA event itself.  In particular, NL is used for part-set transitions and
# some releases put the *user* rather than the area in OP/CL's address field.
# These codes therefore require an immediate authoritative AREA_STATUS read.
AREA_STATUS_SIA_CODES = frozenset({"BV", "CG", "CL", "NL", "OG", "OP"})


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
    mode: str = ""
    last_set_time: str = ""
    last_unset_time: str = ""
    last_unset_user_id: str = ""
    last_unset_user_name: str = ""
    last_alarm: str = ""
    not_ready_set: str = ""
    triggered: bool = False

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
            mode=row.get("MODE", ""),
            last_set_time=row.get("LAST_SET_TIME", ""),
            last_unset_time=row.get("LAST_UNSET_TIME", ""),
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
        """Return the physical open/closed state when the panel exposes it.

        SPC4300 firmware reports the physical circuit in ``INPUT`` while
        leaving ``STATUS`` at ``0`` in some normal open states. Prefer known
        input values and retain status as a compatibility fallback.
        """
        if self.input == ZoneInput.OPEN:
            return True
        if self.input == ZoneInput.CLOSED:
            return False
        if self.input:
            return None
        if self.status == "1":
            return True
        if self.status == "0":
            return False
        return None

    @property
    def input_state(self) -> ZoneInput | None:
        """Typed physical input, or ``None`` for an unknown firmware token."""
        try:
            return ZoneInput(self.input)
        except ValueError:
            return None

    @property
    def zone_type(self) -> ZoneType | None:
        """Typed zone type, or ``None`` for an unknown firmware token."""
        try:
            return ZoneType(self.type)
        except ValueError:
            return None

    @classmethod
    def from_row(cls, row: Row) -> Zone | None:
        zone_id = _parse_id(row, "zone")
        if zone_id is None:
            return None
        # An incomplete/reprogrammed panel can briefly report an empty or
        # malformed AREA field.  Keep the zone available instead of allowing
        # one bad row to abort the whole snapshot refresh.
        try:
            area_id = int(row.get("AREA", "0") or 0)
        except TypeError, ValueError:
            log.warning("Ignoring malformed AREA value for zone %d: %r", zone_id, row.get("AREA"))
            area_id = 0
        return cls(
            id=zone_id,
            type=row.get("TYPE", ""),
            name=row.get("ZONE_NAME", ""),
            area_id=area_id,
            area_name=row.get("AREA_NAME", ""),
            input=row.get("INPUT", ""),
            logic_input=row.get("LOGIC_INPUT", ""),
            status=row.get("STATUS", ""),
            proc_state=row.get("PROC_STATE", ""),
            inhibit_allowed=row.get("INHIBIT_ALLOWED") == "1",
            isolate_allowed=row.get("ISOLATE_ALLOWED") == "1",
        )


class Panel:
    """A snapshot of panel identity, alarm areas and detection zones.

    Consume reconcile_event() for pushed updates and refresh areas/zones
    periodically. A new connection needs a new Panel.from_session()."""

    def __init__(self, session: Session):
        """Create an empty snapshot; prefer from_session()."""
        self._session = session
        self.info = PanelInfo()
        self.areas: dict[int, Area] = {}
        self.zones: dict[int, Zone] = {}
        self.last_refresh: datetime | None = None

    @classmethod
    async def from_session(cls, session: Session, *, wait_polls: int = 1) -> Panel:
        """Wait for the first polls, then read identity, areas and zones."""
        await session.wait_ready(min_polls=wait_polls)
        self = cls(session)
        await self.refresh()
        return self

    async def refresh(self) -> None:
        """Read identity, areas and zones and record the refresh time."""
        info = await self._session.xml_command(XML_INFO)
        self._apply_info(info)
        await self.refresh_areas()
        await self.refresh_zones()
        self.last_refresh = datetime.now(UTC)

    async def refresh_areas(self) -> None:
        """Replace the area snapshot, preserving alarms until confirmed disarmed."""
        reply = await self._session.xml_command(XML_AREA_STATUS)
        areas: dict[int, Area] = {}
        for row in reply.get("AREA_STATUS", []):
            area = Area.from_row(row)
            if area is not None:
                # ``triggered`` is event-derived state, not an AREA_STATUS
                # field. Preserve it across reconciliation unless the panel
                # authoritatively reports the area unset.
                previous = self.areas.get(area.id)
                area.triggered = (
                    previous.triggered
                    if previous is not None and area.arm_mode is not ArmMode.UNSET
                    else False
                )
                areas[area.id] = area
        self.areas = areas

    async def refresh_zones(self) -> None:
        """Replace the zone snapshot, including additions and removals."""
        reply = await self._session.xml_command(XML_ZONE_STATUS)
        zones: dict[int, Zone] = {}
        for row in reply.get("ZONE_STATUS", []):
            zone = Zone.from_row(row)
            if zone is not None:
                zones[zone.id] = zone
        self.zones = zones

    def _apply_info(self, reply: XmlReply) -> None:
        rows = reply.get("INFO", [])
        self.info = PanelInfo.from_row(rows[0]) if rows else PanelInfo()

    def area(self, area_id: int) -> AreaControl:
        return AreaControl(self._session, area_id)

    def events(self) -> AsyncIterator[SiaEvent]:
        """Stream SIA events as they arrive (delegates to the Session feed)."""
        return self._session.events()

    def apply_event(self, ev: SiaEvent) -> EventStateUpdate:
        """Apply unambiguous zone events and return changed IDs.

        Arm/disarm events require reconcile_event(): their address may be a
        user ID and their code does not reliably identify the arm mode."""
        code = ev.sia_code.upper()
        addr = ev.address.strip()
        if not addr.isdigit():
            log.debug("apply_event: non-numeric address %r for %s; ignoring", ev.address, code)
            return EventStateUpdate()
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
                return EventStateUpdate()
            zone.status = "1" if zone_open else "0"
            zone.input = "1" if zone_open else "0"
            zone.logic_input = zone.input
            zone.proc_state = zone.input
            if ev.category == "alarm":
                area = self.areas.get(zone.area_id)
                if area is not None:
                    area.triggered = True
                    return EventStateUpdate(
                        zone_ids=frozenset({zone.id}), area_ids=frozenset({area.id})
                    )
            return EventStateUpdate(zone_ids=frozenset({zone.id}))

        log.debug("apply_event: no mapping for SIA code %r; ignoring", code)
        return EventStateUpdate()

    async def reconcile_event(self, ev: SiaEvent) -> EventStateUpdate:
        """Reconcile a pushed SIA event against the authoritative panel state.

        Zone open/close events can be applied directly and are returned without
        network I/O. Area-mode events are less self-contained: firmware varies
        in both the codes it emits and whether the address identifies an area
        or the user who performed the operation. For those events, immediately
        read ``AREA_STATUS`` and report every refreshed area as changed.

        This preserves the low-latency push behaviour of EDP while keeping the
        panel, rather than an incomplete SIA-code table, as the source of truth.
        """
        code = ev.sia_code.upper()
        if code not in AREA_STATUS_SIA_CODES:
            return self.apply_event(ev)

        area_ids = set(self.areas)
        await self.refresh_areas()
        area_ids.update(self.areas)

        # AREA_STATUS has no verified-alarm field. Match the gateway protocol's
        # BV semantics after the refresh so consumers can expose the alarm.
        if code == "BV":
            addr = ev.address.strip()
            if addr.isdigit() and (area := self.areas.get(int(addr))) is not None:
                area.triggered = True
                area_ids.add(area.id)

        return EventStateUpdate(
            area_ids=frozenset(area_ids),
        )


class AreaControl:
    """Arm / disarm controls (verified live)."""

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
