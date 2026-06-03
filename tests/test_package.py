"""Package-level sanity checks: version and the public export surface.

Beyond the basic version/``__all__`` guards, this module is a *golden
public-surface lock* (campaign M3.7).  It snapshots, in literal form:

  * the sorted ``spcedp.__all__`` list,
  * the ``inspect.signature()`` of every public callable,
  * the dataclass field order of the public state dataclasses,
  * the member name->value mapping of every public enum (including aliases).

The point is intentional: any drift in the public surface fails CI and forces
a conscious semver decision rather than slipping out unnoticed.  When a change
is deliberate, update the corresponding golden constant in the same commit -
the diff then documents the API break.
"""

from __future__ import annotations

import dataclasses
import enum
import inspect

import spcedp

# ---------------------------------------------------------------------------
# Existing guards (keep intact)
# ---------------------------------------------------------------------------


def test_version_is_a_nonempty_string() -> None:
    assert isinstance(spcedp.__version__, str)
    assert spcedp.__version__


def test_all_names_are_importable() -> None:
    # Guards against __all__ drifting from what the package actually exports.
    for name in spcedp.__all__:
        assert hasattr(spcedp, name), name


# ---------------------------------------------------------------------------
# Golden: sorted(__all__)
# ---------------------------------------------------------------------------

# The complete, frozen public export surface.  Adding or removing a public
# name is a semver event: update this list in the same commit.
GOLDEN_ALL = [
    "Area",
    "ArmMode",
    "AttrValue",
    "BinaryCommand",
    "BinaryOp",
    "Door",
    "EncryptionRequired",
    "Frame",
    "FrameDecodeError",
    "FrameDecoder",
    "MajorCode",
    "MinorCode",
    "Output",
    "Panel",
    "PanelInfo",
    "PanelOp",
    "PanelRejected",
    "PanelServer",
    "ReplyCode",
    "Row",
    "Session",
    "SiaEvent",
    "SpcConnectionLost",
    "SpcError",
    "SpcProtocolError",
    "SpcTimeout",
    "XML_AREA_STATUS",
    "XML_DOOR_STATUS",
    "XML_ENET_STATUS",
    "XML_INFO",
    "XML_OUTPUT_STATUS",
    "XML_STATUS",
    "XML_VERIFICATION_STATUS",
    "XML_ZONE_STATUS",
    "XmlReply",
    "Zone",
    "reply_message",
]


def test_all_is_frozen() -> None:
    # Exact set + no accidental duplicates in __all__.
    assert sorted(spcedp.__all__) == GOLDEN_ALL
    assert len(spcedp.__all__) == len(set(spcedp.__all__)), "duplicate name in __all__"


def test_every_all_name_is_importable_from_top_level() -> None:
    # Every advertised name must resolve off the top-level package object.
    for name in GOLDEN_ALL:
        assert hasattr(spcedp, name), f"{name} listed in __all__ but missing from package"


# ---------------------------------------------------------------------------
# Golden: signatures of public callables
# ---------------------------------------------------------------------------

# Snapshot of inspect.signature() rendered as a string for every public
# callable that exposes one.  The builtin exception types (no own __init__)
# carry no introspectable signature and are handled separately below.
GOLDEN_SIGNATURES = {
    "Area": (
        "(id: 'int', name: 'str' = '', mode: 'str' = '0', "
        "last_set_time: 'str' = '', last_unset_time: 'str' = '', "
        "last_unset_user_id: 'str' = '', last_unset_user_name: 'str' = '', "
        "last_alarm: 'str' = '', not_ready_set: 'str' = '') -> None"
    ),
    "ArmMode": "(*values)",
    "BinaryCommand": "(op: 'BinaryOp | int', target_id: 'int' = 0, param: 'int' = 0) -> None",
    "BinaryOp": "(*values)",
    "Door": "(id: 'int', name: 'str', state: 'str') -> None",
    "Frame": (
        "(src_id: 'int', dst_id: 'int', sequence: 'int', major: 'int', "
        "minor: 'int', payload: 'bytes' = b'', checksum: 'int' = 0, "
        "src_flag: 'int' = 0) -> None"
    ),
    "FrameDecoder": "(key: 'bytes | None' = None) -> 'None'",
    "MajorCode": "(*values)",
    "MinorCode": "(*values)",
    "Output": "(id: 'int', name: 'str', state: 'str') -> None",
    "Panel": "(session: 'Session')",
    "PanelInfo": (
        "(type: 'str' = '', variant: 'str' = '', version: 'str' = '', "
        "device_id: 'str' = '', sn: 'str' = '', hw_ver_major: 'str' = '', "
        "hw_ver_minor: 'str' = '', license_key: 'str' = '') -> None"
    ),
    "PanelOp": "(*values)",
    "PanelRejected": "(code: 'int', *, command: 'str | None' = None)",
    "PanelServer": (
        "(*, receiver_id: 'int', bind: 'str' = '0.0.0.0', port: 'int' = 50000, "
        "key: 'bytes | str | None' = None, idle_timeout: 'float | None' = 120.0, "
        "on_event: 'Callable[[Session, SiaEvent], Coroutine[Any, Any, None]] | None' = None, "
        "on_session: 'Callable[[Session], Coroutine[Any, Any, None]] | None' = None) -> 'None'"
    ),
    "ReplyCode": "(*values)",
    "Session": (
        "(panel_id: 'int', receiver_id: 'int', reader: 'asyncio.StreamReader', "
        "writer: 'asyncio.StreamWriter', next_seq: 'int' = 0, key: 'bytes | None' = None, "
        "_pending_xml: 'dict[int, asyncio.Future[bytes]]' = <factory>, "
        "_pending_bin: 'dict[int, asyncio.Future[bytes]]' = <factory>, "
        "_ready: 'asyncio.Event' = <factory>, "
        "_events: 'asyncio.Queue[SiaEvent]' = <factory>, "
        "_write_queue: 'asyncio.Queue[bytes]' = <factory>, "
        "_tasks: 'set[asyncio.Task]' = <factory>, "
        "_closed: 'asyncio.Event' = <factory>, _poll_count: 'int' = 0, "
        "_write_warned: 'bool' = False, "
        "_teardown_requested: 'asyncio.Event' = <factory>) -> None"
    ),
    "SiaEvent": (
        "(spc_id: 'int', timestamp: 'dt.datetime | None', timestamp_raw: 'str', "
        "sia_code: 'str', address: 'str', description: 'str', "
        "verification_id: 'str', extra: 'str' = '') -> None"
    ),
    "Zone": (
        "(id: 'int', type: 'str', name: 'str', area_id: 'int', area_name: 'str', "
        "input: 'str', logic_input: 'str', status: 'str', proc_state: 'str', "
        "inhibit_allowed: 'bool', isolate_allowed: 'bool') -> None"
    ),
    "reply_message": "(code: 'int') -> 'str'",
}

# Public exception types: builtin (no introspectable __init__ signature). We
# lock that they remain exceptions and stay un-introspectable rather than
# silently growing a constructor that breaks the "just an exception" contract.
GOLDEN_NO_SIGNATURE_EXCEPTIONS = frozenset(
    {
        "SpcError",
        "SpcConnectionLost",
        "SpcProtocolError",
        "SpcTimeout",
        "FrameDecodeError",
        "EncryptionRequired",
    }
)

# Public names that are plain values/type-aliases, not callables.
GOLDEN_VALUE_EXPORTS = frozenset(
    {
        "AttrValue",
        "Row",
        "XmlReply",
        "XML_AREA_STATUS",
        "XML_DOOR_STATUS",
        "XML_ENET_STATUS",
        "XML_INFO",
        "XML_OUTPUT_STATUS",
        "XML_STATUS",
        "XML_VERIFICATION_STATUS",
        "XML_ZONE_STATUS",
    }
)


def test_signature_snapshot_partitions_the_whole_surface() -> None:
    # Sanity: the three buckets together must cover exactly __all__, so a new
    # export can't slip past the signature lock by living in no bucket.
    covered = set(GOLDEN_SIGNATURES) | GOLDEN_NO_SIGNATURE_EXCEPTIONS | GOLDEN_VALUE_EXPORTS
    assert covered == set(GOLDEN_ALL)


def test_public_callable_signatures_are_frozen() -> None:
    for name, expected in GOLDEN_SIGNATURES.items():
        obj = getattr(spcedp, name)
        assert callable(obj), f"{name} expected callable, got {type(obj)!r}"
        actual = str(inspect.signature(obj))
        assert actual == expected, f"signature drift for {name}: {actual!r}"


def test_exception_exports_have_no_constructor_signature() -> None:
    for name in GOLDEN_NO_SIGNATURE_EXCEPTIONS:
        obj = getattr(spcedp, name)
        assert isinstance(obj, type) and issubclass(obj, Exception), name
        # No bespoke __init__: still the plain-exception contract.
        try:
            inspect.signature(obj)
        except ValueError:
            continue
        raise AssertionError(f"{name} grew an introspectable signature; semver review needed")


# Exact, frozen repr of each value export.  XML_* are wire-facing command-id
# strings; Row/XmlReply/AttrValue are public type aliases - their rendered form
# is part of the documented surface, so a change to the alias definition (e.g.
# Row gaining a non-str value type) fails here.
GOLDEN_VALUE_REPRS = {
    "AttrValue": "str | int | None",
    "Row": "dict[str, str]",
    "XmlReply": "dict[str, list[dict[str, str]]]",
    "XML_AREA_STATUS": "'area_status'",
    "XML_DOOR_STATUS": "'door_status'",
    "XML_ENET_STATUS": "'enet_status'",
    "XML_INFO": "'info'",
    "XML_OUTPUT_STATUS": "'output_status'",
    "XML_STATUS": "'status'",
    "XML_VERIFICATION_STATUS": "'verification_status'",
    "XML_ZONE_STATUS": "'zone_status'",
}


def test_value_exports_are_frozen() -> None:
    # These are command-id strings and type aliases, NOT functions or classes.
    # Lock both that they are not classes (an accidental promotion to a real
    # class would be an API break) and their exact rendered form.
    assert set(GOLDEN_VALUE_REPRS) == GOLDEN_VALUE_EXPORTS
    for name, expected in GOLDEN_VALUE_REPRS.items():
        obj = getattr(spcedp, name)
        assert not isinstance(obj, type), f"{name} unexpectedly became a class: {obj!r}"
        assert repr(obj) == expected, f"value-export drift for {name}: {obj!r}"


def test_xml_command_id_values_are_frozen() -> None:
    # The XML command IDs are wire-facing argument values to Session.xml_command.
    assert spcedp.XML_INFO == "info"
    assert spcedp.XML_STATUS == "status"
    assert spcedp.XML_AREA_STATUS == "area_status"
    assert spcedp.XML_ENET_STATUS == "enet_status"
    assert spcedp.XML_ZONE_STATUS == "zone_status"
    assert spcedp.XML_DOOR_STATUS == "door_status"
    assert spcedp.XML_VERIFICATION_STATUS == "verification_status"
    assert spcedp.XML_OUTPUT_STATUS == "output_status"


# ---------------------------------------------------------------------------
# Golden: dataclass field order
# ---------------------------------------------------------------------------

# Field NAMES in declaration order for the public state dataclasses.  Order is
# load-bearing: these are positional-constructible, so reordering is a break.
GOLDEN_DATACLASS_FIELDS = {
    "Area": [
        "id",
        "name",
        "mode",
        "last_set_time",
        "last_unset_time",
        "last_unset_user_id",
        "last_unset_user_name",
        "last_alarm",
        "not_ready_set",
    ],
    "Zone": [
        "id",
        "type",
        "name",
        "area_id",
        "area_name",
        "input",
        "logic_input",
        "status",
        "proc_state",
        "inhibit_allowed",
        "isolate_allowed",
    ],
    "Output": ["id", "name", "state"],
    "Door": ["id", "name", "state"],
}


def test_dataclass_field_order_is_frozen() -> None:
    for name, expected in GOLDEN_DATACLASS_FIELDS.items():
        cls = getattr(spcedp, name)
        assert dataclasses.is_dataclass(cls), f"{name} is no longer a dataclass"
        actual = [f.name for f in dataclasses.fields(cls)]
        assert actual == expected, f"dataclass field-order drift for {name}: {actual}"


def test_state_dataclasses_use_slots() -> None:
    # slots=True is part of these objects' memory/behaviour contract (no stray
    # attribute assignment); losing it would silently relax the API.
    for name in GOLDEN_DATACLASS_FIELDS:
        cls = getattr(spcedp, name)
        assert hasattr(cls, "__slots__"), f"{name} lost __slots__"


# ---------------------------------------------------------------------------
# Golden: enum member names + values
# ---------------------------------------------------------------------------

# Full member mapping (name -> value) for each public enum, captured via
# __members__ so ALIASES are included too (e.g. MinorCode.REQUEST/REPLY/
# EVENT_PUSH alias the canonical low values - they are part of the surface and
# are referenced across the dispatch code, so drift in an alias must also fail).
GOLDEN_ENUM_MEMBERS = {
    "BinaryOp": {
        "AREA_SET": 1,
        "AREA_UNSET": 2,
        "ZONE_INHIBIT": 3,
        "ZONE_DEINHIBIT": 4,
        "ZONE_ISOLATE": 9,
        "ZONE_DEISOLATE": 10,
        "OUTPUT_SET": 13,
        "OUTPUT_RESET": 14,
        "AREA_SET_A": 15,
        "AREA_SET_B": 16,
        "DOOR_INHIBIT": 19,
        "DOOR_DEINHIBIT": 20,
        "DOOR_ISOLATE": 21,
        "DOOR_DEISOLATE": 22,
        "DOOR_OPEN_MOMENTARY": 24,
        "DOOR_OPEN_PERMANENT": 25,
        "DOOR_SET_NORMAL": 26,
        "DOOR_LOCK": 27,
        "ALERT_RESTORE": 11,
        "BELL_SILENCE": 28,
        "AUDIO_PLAY": 29,
        "CLOCK_SET": 6,
        "PIN_SET": 7,
    },
    "PanelOp": {
        "RESET": 4,
        "TEST": 7,
    },
    "ReplyCode": {
        "OK": 0xF0,
        "MORE_DATA_FOLLOWS": 0xF1,
        "INVALID_PARAMS": 0xF2,
        "PANEL_WAITING": 0xF3,
        "PANEL_ENGINEER": 0xF4,
        "NOT_POSSIBLE_NOW": 0xF5,
        "NOT_PERMITTED": 0xFB,
        "NOT_IMPLEMENTED": 0xFC,
        "NOT_IMPLEMENTED_PANEL": 0xFF,
    },
    "MajorCode": {
        "SESSION": 1,
        "EVENT": 2,
        "BINARY_CMD": 4,
        "PANEL_CMD": 5,
        "XML_CMD": 10,
    },
    "MinorCode": {
        # Canonical members
        "POLL": 0,
        "POLL_ACK": 1,
        "HELLO": 2,
        "HELLO_ACK": 3,
        # Aliases (same underlying values, distinct names)
        "EVENT_PUSH": 0,
        "EVENT_ACK": 1,
        "REQUEST": 0,
        "REPLY": 1,
        "BINARY_REPLY": 2,
        "PANEL_REPLY": 1,
    },
    "ArmMode": {
        "UNSET": "0",
        "PART_A": "1",
        "PART_B": "2",
        "FULL": "3",
    },
}


def test_enum_members_are_frozen() -> None:
    for name, expected in GOLDEN_ENUM_MEMBERS.items():
        cls = getattr(spcedp, name)
        assert isinstance(cls, enum.EnumMeta), f"{name} is no longer an enum"
        # __members__ preserves declaration order AND aliases; dict equality
        # also catches a renamed/removed alias or a changed value.
        actual = {member_name: member.value for member_name, member in cls.__members__.items()}
        assert actual == expected, f"enum drift for {name}: {actual}"


def test_enum_member_order_is_frozen() -> None:
    # Order is observable (iteration, error rendering); lock it explicitly.
    for name, expected in GOLDEN_ENUM_MEMBERS.items():
        cls = getattr(spcedp, name)
        assert list(cls.__members__) == list(expected), f"enum member-order drift for {name}"


def test_intenum_and_strenum_kinds_are_frozen() -> None:
    # The numeric enums must stay IntEnum (they are int()-coerced onto the wire);
    # ArmMode stays a plain str-valued Enum (its values are the raw MODE tokens).
    for name in ("BinaryOp", "PanelOp", "ReplyCode", "MajorCode", "MinorCode"):
        assert issubclass(getattr(spcedp, name), enum.IntEnum), f"{name} is no longer IntEnum"
    assert issubclass(spcedp.ArmMode, enum.Enum)
    assert not issubclass(spcedp.ArmMode, enum.IntEnum)
    assert all(isinstance(m.value, str) for m in spcedp.ArmMode)
