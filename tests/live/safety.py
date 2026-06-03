"""Live-campaign safety preflight and guards (campaign B.0).

Imported by every live script. Provides the hard gates that MUST pass before
any live step touches the physical panel, plus the ``gated_actuate`` wrapper
that counts down, applies a reversible action, and ALWAYS reverts within a hard
timeout - even if the apply hangs.

The dominant rule (CLAUDE.md, safety-critical): no path may leave the panel
armed, a siren sounding, or an output stuck on. Every dangerous action is
gated behind an explicit per-step ``--confirm-physical <step>`` flag AND
auto-reverts under a watchdog.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import Awaitable, Callable, Iterable
from contextlib import suppress
from dataclasses import dataclass, field

log = logging.getLogger("spcedp.live")

# A zone whose lower-cased name contains any of these is never actuated
# (mirrors integration_test.py:100, extended to fire). Smoke/fire detectors
# are life-safety devices; the campaign only ever reads them.
PROTECTED_ZONE_KEYWORDS = ("smoke", "fire")

# Hard ceiling on how long a revert is allowed to take before we give up
# awaiting it (the watchdog still fires the revert; this just bounds the wait).
REVERT_TIMEOUT_S = 5.0


class SafetyAbort(Exception):
    """Raised to abort the entire live run when a hard gate fails.

    Catching this at the top level should result in a non-zero exit and NO
    further live steps - it means a precondition that protects the building or
    the panel was not met."""


@dataclass(slots=True)
class SafetyConfig:
    """Parsed safety flags shared by every live step.

    ``confirm_physical`` is the set of step names the operator explicitly
    enabled for actuation; a dangerous step not in this set is skipped, never
    silently run. ``i_confirm_unoccupied`` must be explicitly set or the run
    refuses to start."""

    i_confirm_unoccupied: bool = False
    confirm_physical: set[str] = field(default_factory=set)


def add_safety_args(ap: argparse.ArgumentParser) -> None:
    """Register the shared safety flags on an argument parser.

    ``--i-confirm-unoccupied`` is required (no default); ``--confirm-physical``
    is repeatable and names each dangerous step that may actuate."""
    ap.add_argument(
        "--i-confirm-unoccupied",
        action="store_true",
        help="REQUIRED: assert the building is unoccupied / owner consents. "
        "Without it the run refuses to start.",
    )
    ap.add_argument(
        "--confirm-physical",
        action="append",
        default=[],
        metavar="STEP",
        help="Enable a dangerous physical step (e.g. 'arm', 'siren', 'reset'). "
        "Repeatable. A dangerous step not named here is skipped.",
    )


def safety_config_from_args(args: argparse.Namespace) -> SafetyConfig:
    """Build a SafetyConfig from parsed args and enforce the unoccupied gate."""
    cfg = SafetyConfig(
        i_confirm_unoccupied=bool(args.i_confirm_unoccupied),
        confirm_physical=set(args.confirm_physical or []),
    )
    if not cfg.i_confirm_unoccupied:
        raise SafetyAbort(
            "refusing to start: pass --i-confirm-unoccupied to assert the "
            "building is unoccupied (or the owner consents) before any live step"
        )
    return cfg


def is_protected_zone(name: str) -> bool:
    """True if a zone name marks a life-safety device that must not be actuated."""
    lowered = name.lower()
    return any(kw in lowered for kw in PROTECTED_ZONE_KEYWORDS)


def refuse_if_armed(areas: Iterable[object]) -> None:
    """Abort the whole run if any area is armed.

    ``areas`` is an iterable of objects with a ``mode`` attribute (``Panel``
    ``Area`` values). Mirrors integration_test.py:89 but raises SafetyAbort so
    the abort is total (not just a skip of mutation steps): an armed building
    means every live step is unsafe."""
    armed = []
    for area in areas:
        mode = getattr(area, "mode", "0")
        if mode != "0":
            armed.append(getattr(area, "id", "?"))
    if armed:
        raise SafetyAbort(
            f"refusing to run: areas {armed} are armed. Disarm the panel before "
            "running the live campaign; an armed building is never safe to probe."
        )


def require_confirmed(step: str, cfg: SafetyConfig) -> bool:
    """Return True if ``step`` was explicitly confirmed for actuation.

    Logs a skip and returns False otherwise, so the caller bypasses the
    dangerous action rather than running it unconfirmed."""
    if step in cfg.confirm_physical:
        return True
    log.warning("step %r is gated; skipping (pass --confirm-physical %s to enable)", step, step)
    return False


async def countdown(name: str, seconds: int) -> None:
    """Print a visible countdown banner before a dangerous actuation.

    Gives the operator a last chance to abort (Ctrl-C) before the panel is
    physically actuated."""
    log.warning("=== ACTUATING %r in %ds - Ctrl-C to abort ===", name, seconds)
    for remaining in range(seconds, 0, -1):
        log.warning("  %s in %d ...", name, remaining)
        await asyncio.sleep(1)
    log.warning("=== ACTUATING %r now ===", name)


async def gated_actuate(
    apply: Callable[[], Awaitable[None]],
    revert: Callable[[], Awaitable[None]],
    *,
    name: str,
    hold_s: float,
    confirm: set[str] | SafetyConfig,
    countdown_s: int = 5,
) -> bool:
    """Apply a reversible physical action, hold, then ALWAYS revert.

    Safety contract (CLAUDE.md): the revert ALWAYS runs within a hard timeout,
    even if ``apply`` or the hold hangs. A watchdog task fires the revert
    independently so a hung apply cannot leave the panel armed / a siren
    sounding. Returns True if the action was applied, False if it was skipped
    because ``name`` was not confirmed.

      * gated behind ``--confirm-physical <name>`` (via ``confirm``);
      * prints a countdown banner;
      * bounds the hold with ``asyncio.wait_for``;
      * reverts in a ``finally`` AND via an independent watchdog, both bounded
        by ``REVERT_TIMEOUT_S``.
    """
    confirmed = confirm.confirm_physical if isinstance(confirm, SafetyConfig) else confirm
    if name not in confirmed:
        log.warning(
            "gated step %r not confirmed; skipping (pass --confirm-physical %s)", name, name
        )
        return False

    reverted = asyncio.Event()

    async def _revert_once() -> None:
        if reverted.is_set():
            return
        reverted.set()
        with suppress(Exception):
            await asyncio.wait_for(revert(), REVERT_TIMEOUT_S)

    async def _watchdog() -> None:
        # Fire the revert no later than hold + countdown + slack, even if the
        # main coroutine is wedged in apply()/hold and never reaches `finally`.
        await asyncio.sleep(hold_s + countdown_s + REVERT_TIMEOUT_S + 1.0)
        log.error("watchdog firing forced revert of %r (apply/hold appears hung)", name)
        await _revert_once()

    watchdog = asyncio.ensure_future(_watchdog())
    try:
        await countdown(name, countdown_s)
        await apply()
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.sleep(hold_s), hold_s + 1.0)
        return True
    finally:
        await _revert_once()
        watchdog.cancel()
        with suppress(asyncio.CancelledError):
            await watchdog


async def verify_disarmed(panel: object) -> None:
    """Re-read areas and abort if any is still armed (post-run safety check).

    Called at the end of a run that may have armed an area, so the script never
    exits leaving the panel set. ``panel`` must expose ``refresh_areas`` and an
    ``areas`` mapping (the live ``Panel`` facade)."""
    refresh = getattr(panel, "refresh_areas", None)
    if refresh is not None:
        with suppress(Exception):
            await refresh()
    areas = getattr(panel, "areas", {})
    values = areas.values() if hasattr(areas, "values") else areas
    refuse_if_armed(values)
    log.info("post-run check: all areas disarmed")
