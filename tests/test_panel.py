"""Tests for the Panel facade: refresh parsing, control opcodes, event feed.

Drives Panel against a fake Session that returns canned parse_reply dicts and
records the binary/panel commands the control wrappers issue - no live panel.
"""

from __future__ import annotations

import asyncio

import pytest

from spcedp.commands import BinaryOp
from spcedp.events import SiaEvent
from spcedp.panel import Panel

pytestmark = pytest.mark.asyncio


class FakeSession:
    def __init__(self, replies: dict) -> None:
        self._replies = replies
        self.binary_calls: list[tuple] = []
        self._events: asyncio.Queue[SiaEvent] = asyncio.Queue()

    async def wait_ready(self, min_polls: int = 1) -> None:
        return

    async def xml_command(self, command_id: str, timeout: float = 5.0, **attrs):
        return self._replies.get(command_id, {})

    async def binary_command(self, op: BinaryOp, target_id: int, *, timeout: float = 5.0) -> None:
        self.binary_calls.append((op, target_id))

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
            },
        ]
    },
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


async def test_alarm_controls_emit_correct_opcodes() -> None:
    sess = FakeSession({})
    panel = Panel(sess)
    await panel.area(2).set()
    await panel.area(2).set_a()
    await panel.area(2).set_b()
    await panel.area(2).unset()
    assert sess.binary_calls == [
        (BinaryOp.AREA_SET, 2),
        (BinaryOp.AREA_SET_A, 2),
        (BinaryOp.AREA_SET_B, 2),
        (BinaryOp.AREA_UNSET, 2),
    ]


async def test_initial_read_only_requests_identity_areas_and_zones() -> None:
    from unittest.mock import AsyncMock

    sess = FakeSession(FULL_REPLIES)
    sess.xml_command = AsyncMock(wraps=sess.xml_command)
    await Panel.from_session(sess)
    assert [call.args[0] for call in sess.xml_command.await_args_list] == [
        "info",
        "area_status",
        "zone_status",
    ]


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
