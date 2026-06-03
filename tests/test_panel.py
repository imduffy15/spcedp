"""Tests for the Panel facade: refresh parsing, control opcodes, event feed.

Drives Panel against a fake Session that returns canned parse_reply dicts and
records the binary/panel commands the control wrappers issue - no live panel.
"""

from __future__ import annotations

import asyncio

import pytest

from spcedp.commands import BinaryOp, PanelOp
from spcedp.events import SiaEvent
from spcedp.panel import Area, Panel, Zone, ZoneType

pytestmark = pytest.mark.asyncio


async def test_zone_type_decodes_known_token() -> None:
    # TYPE="1" is the entry/exit input type (cross-checked live: a hallway zone).
    zone = Zone.from_row({"ID": "5", "ZONE_NAME": "Hall", "TYPE": "1", "AREA": "1"})
    assert zone is not None
    assert zone.type == "1"  # raw token preserved
    assert zone.zone_type is ZoneType.ENTRY_EXIT


async def test_zone_type_maps_the_full_catalogue() -> None:
    # Every documented TYPE token round-trips to its ZoneType member.
    for member in ZoneType:
        zone = Zone.from_row({"ID": "1", "ZONE_NAME": "z", "TYPE": member.value, "AREA": "1"})
        assert zone is not None
        assert zone.zone_type is member


async def test_zone_type_unknown_or_missing_is_none() -> None:
    # An unrecognised token is never silently mapped to a wrong type.
    unknown = Zone.from_row({"ID": "1", "ZONE_NAME": "z", "TYPE": "999", "AREA": "1"})
    assert unknown is not None
    assert unknown.zone_type is None
    # A zone reporting no type at all is None too, without a spurious warning path.
    missing = Zone.from_row({"ID": "2", "ZONE_NAME": "z", "AREA": "1"})
    assert missing is not None
    assert missing.type == ""
    assert missing.zone_type is None


async def test_area_captures_last_set_user() -> None:
    # changed_by parity: the set-user fields are read when the panel reports them.
    area = Area.from_row(
        {
            "ID": "1",
            "NAME": "Home",
            "MODE": "3",
            "LAST_SET_USER_ID": "7",
            "LAST_SET_USER_NAME": "Alice",
            "LAST_UNSET_USER_NAME": "Bob",
        }
    )
    assert area is not None
    assert area.last_set_user_id == "7"
    assert area.last_set_user_name == "Alice"
    assert area.last_unset_user_name == "Bob"


class FakeSession:
    def __init__(self, replies: dict) -> None:
        self._replies = replies
        self.binary_calls: list[tuple] = []
        self.panel_calls: list = []
        self._events: asyncio.Queue[SiaEvent] = asyncio.Queue()

    async def wait_ready(self, min_polls: int = 1) -> None:
        return

    async def xml_command(self, command_id: str, timeout: float = 5.0, **attrs):
        return self._replies.get(command_id, {})

    async def binary_command(
        self, op, target_id: int = 0, param: int = 0, timeout: float = 5.0
    ) -> None:
        self.binary_calls.append((op, target_id, param))

    async def panel_command(self, op, timeout: float = 5.0) -> None:
        self.panel_calls.append(op)

    async def events(self):
        while True:
            yield await self._events.get()


FULL_REPLIES = {
    "info": {"INFO": [{"TYPE": "SPC4000", "VARIANT": "4300", "VERSION": "3.15.0"}]},
    "area_status": {
        "AREA_STATUS": [
            {"ID": "1", "NAME": "Home", "MODE": "3"},
            {"NAME": "MissingID"},  # no ID -> skipped, not fatal
        ]
    },
    "zone_status": {
        "ZONE_STATUS": [
            {
                "ID": "5",
                "ZONE_NAME": "Hall",
                "TYPE": "1",
                "AREA": "1",
                "INHIBIT_ALLOWED": "1",
                "ISOLATE_ALLOWED": "0",
            },
        ]
    },
    "output_status": {"OUTPUT_STATUS": [{"ID": "2", "NAME": "Siren", "STATE": "0"}]},
}


async def test_refresh_builds_object_graph() -> None:
    panel = await Panel.from_session(FakeSession(FULL_REPLIES))
    assert panel.info.type == "SPC4000"
    assert panel.info.version == "3.15.0"
    assert panel.areas[1].name == "Home"
    assert panel.areas[1].mode == "3"
    zone = panel.zones[5]
    assert zone.name == "Hall"
    assert zone.area_id == 1
    assert zone.inhibit_allowed is True
    assert zone.isolate_allowed is False
    assert panel.outputs[2].name == "Siren"


async def test_refresh_skips_rows_with_missing_or_bad_id() -> None:
    # The MissingID area row above is dropped rather than aborting refresh.
    panel = await Panel.from_session(FakeSession(FULL_REPLIES))
    assert list(panel.areas) == [1]

    bad = FakeSession(
        {
            "info": {},
            "zone_status": {},
            "output_status": {},
            "area_status": {"AREA_STATUS": [{"ID": "abc", "NAME": "Bad"}]},
        }
    )
    panel2 = await Panel.from_session(bad)
    assert panel2.areas == {}


async def test_control_wrappers_emit_correct_opcodes() -> None:
    sess = FakeSession({})
    panel = Panel(sess)
    await panel.zone(7).inhibit()
    await panel.area(2).set_b()
    await panel.output(4).set()
    await panel.door(3).open_permanent()
    assert sess.binary_calls == [
        (BinaryOp.ZONE_INHIBIT, 7, 0),
        (BinaryOp.AREA_SET_B, 2, 0),
        (BinaryOp.OUTPUT_SET, 4, 0),
        (BinaryOp.DOOR_OPEN_PERMANENT, 3, 0),
    ]


async def test_panel_reset_and_test_use_panel_channel() -> None:
    sess = FakeSession({})
    panel = Panel(sess)
    await panel.reset()
    await panel.test()
    assert sess.panel_calls == [PanelOp.RESET, PanelOp.TEST]


async def test_events_delegates_to_session_feed() -> None:
    sess = FakeSession({})
    panel = Panel(sess)
    ev = SiaEvent(
        spc_id=1,
        timestamp=None,
        timestamp_raw="08521203062026",
        sia_code="BA",
        address="",
        description="",
        verification_id="",
    )
    sess._events.put_nowait(ev)
    agen = panel.events()
    got = await asyncio.wait_for(agen.__anext__(), 1.0)
    assert got is ev
    await agen.aclose()
