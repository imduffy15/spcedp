"""Tests for SIA event payload parsing."""

import datetime as dt

import pytest

from spcedp.events import SiaEvent


def test_parse_real_event_nt() -> None:
    ev = SiaEvent.parse(b"E2[#1000|08521203062026|NT|0|IP Link Fail||0]")
    assert ev.spc_id == 1000
    assert ev.timestamp == dt.datetime(2026, 6, 3, 8, 52, 12)
    assert ev.sia_code == "NT"
    assert ev.description == "IP Link Fail"
    assert ev.verification_id == "0"


def test_parse_real_event_nr() -> None:
    ev = SiaEvent.parse("E2[#1000|09153403062026|NR|0|IP Link Restore||0]")
    assert ev.sia_code == "NR"
    assert ev.description == "IP Link Restore"
    assert ev.timestamp.hour == 9
    assert ev.timestamp.minute == 15


def test_parse_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="not an SIA event"):
        SiaEvent.parse(b"this is not an event")


def test_parse_exposes_address_and_extra_fields() -> None:
    ev = SiaEvent.parse(b"E2[#1000|08521203062026|BA|5|Burglar|xtra|7]")
    assert ev.address == "5"
    assert ev.extra == "xtra"
    assert ev.verification_id == "7"
    assert ev.description == "Burglar"


def test_parse_tolerates_trailing_whitespace() -> None:
    ev = SiaEvent.parse("E2[#1000|08521203062026|NT|0|IP Link Fail||0]   \r\n")
    assert ev.sia_code == "NT"


def test_parse_accepts_bytes_and_str_equivalently() -> None:
    payload = "E2[#1000|08521203062026|NT|0|x||0]"
    assert SiaEvent.parse(payload.encode()).timestamp == SiaEvent.parse(payload).timestamp


def test_parse_normalises_spc_description_separator() -> None:
    """SPC's Latin-1 separator is rendered without a replacement glyph."""
    event = SiaEvent.parse(b"E2[#1000|08521203062026|ZO|1|BackDoor\xa6ZONE\xa61\xa6Home||0]")
    assert event.description == "BackDoor¦ZONE¦1¦Home"


def test_parse_out_of_range_timestamp_keeps_event() -> None:
    # Month 13 (HHMMSSDDMMYYYY): a panel clock glitch must not discard the
    # alarm - the event surfaces with timestamp=None.
    ev = SiaEvent.parse(b"E2[#1000|08521203132026|BA|0|Burglar||0]")
    assert ev.timestamp is None
    assert ev.sia_code == "BA"
    assert ev.description == "Burglar"
