"""Panel snapshot reconciliation tests (campaign H2/M1.5/M3.1/M3.5).

Drives :class:`Panel` against a fake Session (mirroring ``tests/test_panel.py``)
to assert the post-fix behaviour:

  * ``refresh*`` rebuilds the dicts wholesale, so a zone the panel stops
    reporting disappears instead of lingering as a stale ghost (M3).
  * the typed accessors (``ArmMode``, ``Zone.is_open``, ``Output.is_active``)
    map known tokens and return ``None`` for unknown ones, never a silent
    default (H4 surface).
  * ``Panel.apply_event`` reconciles ``zone.status`` / ``area.mode`` in place
    for clearly-mappable SIA codes and is a deliberate no-op otherwise (H2).
  * ``refresh()`` stamps ``last_refresh`` (M1.5/M3.1).
"""

from __future__ import annotations

from datetime import datetime

import pytest

from spcedp.events import SiaEvent
from spcedp.panel import Area, ArmMode, Output, Panel, Zone, ZoneInput, ZoneType

# This module mixes synchronous accessor tests with async refresh/apply_event
# tests, so the asyncio mark is applied per-test rather than module-wide (under
# asyncio_mode="strict" a module-level mark would wrongly flag the sync tests).


class FakeSession:
    """Canned-reply Session stand-in whose per-command replies can be swapped.

    ``replies`` maps a command_id to the dict ``xml_command`` returns. Mutating
    it between ``refresh*`` calls lets a test feed a different ZONE_STATUS the
    second time around (the stale-ghost scenario).
    """

    def __init__(self, replies: dict) -> None:
        self.replies = replies

    async def wait_ready(self, min_polls: int = 1) -> None:
        return

    async def xml_command(self, command_id: str, timeout: float = 5.0, **attrs):
        return self.replies.get(command_id, {})

    async def binary_command(
        self, op, target_id: int = 0, param: int = 0, timeout: float = 5.0
    ) -> None:  # pragma: no cover - not exercised here
        return

    async def panel_command(self, op, timeout: float = 5.0) -> None:  # pragma: no cover
        return


def _zone_rows(*ids: int) -> dict:
    return {
        "ZONE_STATUS": [
            {
                "ID": str(i),
                "ZONE_NAME": f"Z{i}",
                "TYPE": "1",
                "AREA": "1",
                "STATUS": "0",
            }
            for i in ids
        ]
    }


def _ev(code: str, address: str) -> SiaEvent:
    return SiaEvent(
        spc_id=1000,
        timestamp=None,
        timestamp_raw="08521203062026",
        sia_code=code,
        address=address,
        description="",
        verification_id="",
    )


# --------------------------------------------------------------------------- M3
@pytest.mark.asyncio
async def test_refresh_zones_drops_stale_ghost() -> None:
    """A zone the panel stops reporting must vanish, not linger frozen (M3)."""
    sess = FakeSession({"zone_status": _zone_rows(1, 2, 3)})
    panel = Panel(sess)
    await panel.refresh_zones()
    assert list(panel.zones) == [1, 2, 3]

    # Panel now reports only zones 1 and 3 (zone 2 deleted/renumbered).
    sess.replies["zone_status"] = _zone_rows(1, 3)
    await panel.refresh_zones()
    assert list(panel.zones) == [1, 3]
    assert 2 not in panel.zones


# --------------------------------------------------------------------------- M1.5/M3.1
@pytest.mark.asyncio
async def test_refresh_sets_last_refresh() -> None:
    """A full refresh stamps last_refresh; it starts None on a bare Panel."""
    sess = FakeSession(
        {
            "info": {},
            "area_status": {},
            "zone_status": {},
            "output_status": {},
            "door_status": {},
        }
    )
    panel = Panel(sess)
    assert panel.last_refresh is None
    await panel.refresh()
    assert isinstance(panel.last_refresh, datetime)
    assert panel.last_refresh.tzinfo is not None  # timezone-aware (UTC)


# --------------------------------------------------------------------------- H4: ArmMode
@pytest.mark.parametrize(
    "token,expected",
    [("0", ArmMode.UNSET), ("1", ArmMode.PART_A), ("2", ArmMode.PART_B), ("3", ArmMode.FULL)],
)
def test_arm_mode_maps_known_tokens(token: str, expected: ArmMode) -> None:
    area = Area(id=1, mode=token)
    assert area.arm_mode is expected


def test_arm_mode_unknown_token_is_none() -> None:
    """An unrecognised MODE token maps to None, never silently to UNSET."""
    area = Area(id=1, mode="9")
    assert area.arm_mode is None
    assert area.is_armed is None  # unknown propagates, not coerced to False


@pytest.mark.parametrize(
    "token,is_armed",
    [("0", False), ("1", True), ("2", True), ("3", True)],
)
def test_is_armed_reflects_known_tokens(token: str, is_armed: bool) -> None:
    assert Area(id=1, mode=token).is_armed is is_armed


# --------------------------------------------------------------------------- H4: Zone.is_open
def _zone(status: str) -> Zone:
    return Zone(
        id=1,
        type="1",
        name="Z1",
        area_id=1,
        area_name="A",
        input="",
        logic_input="",
        status=status,
        proc_state="",
        inhibit_allowed=False,
        isolate_allowed=False,
    )


def test_zone_is_open_typed_accessor() -> None:
    assert _zone("1").is_open is True
    assert _zone("0").is_open is False
    assert _zone("").is_open is None  # unknown -> None, never silently closed
    assert _zone("7").is_open is None


def test_zone_input_is_authoritative_over_stale_status() -> None:
    """SPC4300 exposes physical state in INPUT even when STATUS is stale."""
    zone = _zone("0")
    zone.input = ZoneInput.OPEN.value
    assert zone.is_open is True
    assert zone.input_state is ZoneInput.OPEN
    assert zone.zone_type is ZoneType.ENTRY_EXIT


def test_zone_with_malformed_area_is_still_available() -> None:
    zone = Zone.from_row(
        {
            "ID": "5",
            "TYPE": "1",
            "ZONE_NAME": "Front Door",
            "AREA": "not-a-number",
        }
    )
    assert zone is not None
    assert zone.area_id == 0


# --------------------------------------------------------------------------- H4: Output.is_active
def test_output_is_active_typed_accessor() -> None:
    assert Output(id=1, name="Siren", state="1").is_active is True
    assert Output(id=1, name="Siren", state="0").is_active is False
    assert Output(id=1, name="Siren", state="").is_active is None
    assert Output(id=1, name="Siren", state="x").is_active is None


# --------------------------------------------------------------------------- H2: apply_event zones
@pytest.mark.asyncio
async def test_apply_event_zone_open_close() -> None:
    sess = FakeSession({"zone_status": _zone_rows(5)})
    panel = Panel(sess)
    await panel.refresh_zones()
    assert panel.zones[5].status == "0"
    assert panel.zones[5].is_open is False

    panel.apply_event(_ev("ZO", "5"))
    assert panel.zones[5].status == "1"
    assert panel.zones[5].input == "1"
    assert panel.zones[5].is_open is True

    panel.apply_event(_ev("ZC", "5"))
    assert panel.zones[5].status == "0"
    assert panel.zones[5].is_open is False


@pytest.mark.asyncio
@pytest.mark.parametrize("alarm_code", ["BA", "FA", "PA", "HA", "TA"])
async def test_apply_event_alarm_implies_zone_open(alarm_code: str) -> None:
    """The burglary/fire/panic/holdup/tamper families flip the zone to open."""
    sess = FakeSession({"zone_status": _zone_rows(5)})
    panel = Panel(sess)
    await panel.refresh_zones()
    panel.apply_event(_ev(alarm_code, "5"))
    assert panel.zones[5].status == "1"


@pytest.mark.asyncio
async def test_apply_event_unknown_zone_is_noop() -> None:
    sess = FakeSession({"zone_status": _zone_rows(5)})
    panel = Panel(sess)
    await panel.refresh_zones()
    # Address resolves to a zone the snapshot does not know -> no-op, no raise.
    panel.apply_event(_ev("ZO", "99"))
    assert list(panel.zones) == [5]
    assert panel.zones[5].status == "0"


# --------------------------------------------------------------------------- H2: apply_event areas
@pytest.mark.asyncio
async def test_apply_event_area_arm_disarm() -> None:
    sess = FakeSession({"area_status": {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "0"}]}})
    panel = Panel(sess)
    await panel.refresh_areas()
    assert panel.areas[1].mode == "0"
    assert panel.areas[1].arm_mode is ArmMode.UNSET

    # CL = closing/arm -> recorded as FULL (the event does not carry part-set).
    panel.apply_event(_ev("CL", "1"))
    assert panel.areas[1].mode == ArmMode.FULL.value
    assert panel.areas[1].arm_mode is ArmMode.FULL
    assert panel.areas[1].is_armed is True

    # OP = opening/disarm -> UNSET.
    panel.apply_event(_ev("OP", "1"))
    assert panel.areas[1].mode == ArmMode.UNSET.value
    assert panel.areas[1].is_armed is False


@pytest.mark.asyncio
async def test_alarm_event_tracks_area_trigger_and_refresh_preserves_it() -> None:
    """Event-derived triggered state survives a normal reconciliation pass."""
    sess = FakeSession(
        {
            "area_status": {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "3"}]},
            "zone_status": _zone_rows(5),
        }
    )
    panel = Panel(sess)
    await panel.refresh_areas()
    await panel.refresh_zones()

    update = panel.apply_event(_ev("BA", "5"))
    assert update.zone_ids == frozenset({5})
    assert update.area_ids == frozenset({1})
    assert panel.areas[1].triggered is True

    await panel.refresh_areas()
    assert panel.areas[1].triggered is True

    panel.apply_event(_ev("OP", "1"))
    assert panel.areas[1].triggered is False


@pytest.mark.asyncio
async def test_apply_event_unknown_area_is_noop() -> None:
    sess = FakeSession({"area_status": {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "0"}]}})
    panel = Panel(sess)
    await panel.refresh_areas()
    panel.apply_event(_ev("CL", "42"))
    assert panel.areas[1].mode == "0"  # untouched


# --------------------------------------------------------------------------- H2: apply_event no-ops
@pytest.mark.asyncio
async def test_apply_event_unmapped_code_is_noop() -> None:
    """A code with no zone/area mapping leaves the whole snapshot untouched."""
    sess = FakeSession(
        {
            "zone_status": _zone_rows(5),
            "area_status": {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "0"}]},
        }
    )
    panel = Panel(sess)
    await panel.refresh_zones()
    await panel.refresh_areas()

    # NT (network trouble) carries no per-zone/area state to reconcile.
    panel.apply_event(_ev("NT", "0"))
    assert panel.zones[5].status == "0"
    assert panel.areas[1].mode == "0"


@pytest.mark.asyncio
async def test_apply_event_non_numeric_address_is_noop() -> None:
    sess = FakeSession({"zone_status": _zone_rows(5)})
    panel = Panel(sess)
    await panel.refresh_zones()
    # A non-numeric address cannot resolve to an entity -> no-op, no raise.
    panel.apply_event(_ev("ZO", "abc"))
    assert panel.zones[5].status == "0"


@pytest.mark.asyncio
async def test_apply_event_code_is_case_insensitive() -> None:
    sess = FakeSession({"zone_status": _zone_rows(5)})
    panel = Panel(sess)
    await panel.refresh_zones()
    panel.apply_event(_ev("zo", "5"))
    assert panel.zones[5].status == "1"


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["CG", "NL", "OG", "BV"])
async def test_reconcile_event_refreshes_area_status_codes(code: str) -> None:
    """Area events trigger an authoritative refresh instead of code guessing."""
    sess = FakeSession({"area_status": {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "0"}]}})
    panel = Panel(sess)
    await panel.refresh_areas()
    sess.replies["area_status"] = {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "2"}]}

    update = await panel.reconcile_event(_ev(code, "1"))

    assert panel.areas[1].arm_mode is ArmMode.PART_B
    assert update.area_ids == frozenset({1})


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ["CL", "OP"])
async def test_reconcile_event_refreshes_all_areas_when_address_is_user(code: str) -> None:
    """OP/CL addresses can identify a user, so refresh every area."""
    sess = FakeSession(
        {
            "area_status": {
                "AREA_STATUS": [
                    {"ID": "1", "NAME": "Home", "MODE": "0"},
                    {"ID": "2", "NAME": "Garage", "MODE": "0"},
                ]
            }
        }
    )
    panel = Panel(sess)
    await panel.refresh_areas()
    sess.replies["area_status"] = {
        "AREA_STATUS": [
            {"ID": "1", "NAME": "Home", "MODE": "3"},
            {"ID": "2", "NAME": "Garage", "MODE": "1"},
        ]
    }

    update = await panel.reconcile_event(_ev(code, "9998"))

    assert panel.areas[1].arm_mode is ArmMode.FULL
    assert panel.areas[2].arm_mode is ArmMode.PART_A
    assert update.area_ids == frozenset({1, 2})


@pytest.mark.asyncio
async def test_reconcile_verified_alarm_marks_target_area_triggered() -> None:
    sess = FakeSession({"area_status": {"AREA_STATUS": [{"ID": "1", "NAME": "Home", "MODE": "3"}]}})
    panel = Panel(sess)
    await panel.refresh_areas()

    await panel.reconcile_event(_ev("BV", "1"))

    assert panel.areas[1].triggered is True
