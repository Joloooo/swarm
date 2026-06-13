"""Agentic-testing harness (Tier 5 — counterfactual decision replay).

Replays one captured agent decision through the REAL ``src/`` code under a
changed input/config and scores baseline-vs-candidate, so prompt/architecture
work is a fast evidence loop instead of a 30-minute benchmark rerun. See
``.claude/skills/agentic-testing/SKILL.md`` for the design and the cardinal
principle (the harness controls inputs/config; the code under test is always
imported from ``src/``; the model's output is never mocked).

This package only ever IMPORTS from ``src/`` — ``src/`` never imports it (the
one-directional dependency enforced by ``test_probe_guard.py``).

``src.graph`` is imported here, once, before anything else: ``src.nodes.planner``
does ``from src.graph import config`` while ``src.graph`` builds the nodes, so
importing a node module first hits a partially-initialised ``src.nodes``.
Importing ``src.graph`` at package load bootstraps the correct order for every
harness module that later reaches into ``src``.
"""

from __future__ import annotations

import src.graph  # noqa: F401  — bootstrap import order (see module docstring)
