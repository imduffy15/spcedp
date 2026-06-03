"""Live SPC4300 campaign harness (campaign B).

CODE ONLY - these modules are never collected or run by pytest (they are not
``test_*.py``) and never run in CI. They drive the physical panel described in
the live-panel config and are executed by hand, on a self-hosted runner with
network reach to the panel, behind explicit safety flags. See ``safety.py`` for
the preflight gates and ``matrix.py`` for the ordered runner.
"""

from __future__ import annotations
