"""Shared pytest fixtures for SwarmAttacker tests.

Per the test-on-failure policy, this file stays small. Add fixtures here
only when more than one test needs them. Per-test scaffolding belongs in
the test file itself.

Currently only Tier 1 (unit) tests live in the suite, so this file is
mostly empty. Tier 2 (node tests with FakeListChatModel) and Tier 4
(live-LLM tests) will add fixtures here when they get written.

Import-order warm-up
--------------------
``src/nodes/planner.py`` does ``from src.graph import budgets`` at module
level, and ``src.graph`` in turn does ``from src.nodes import ...``.
The existing entry points (``langgraph dev``, the ``swarmattacker``
CLI) hit ``src.graph`` first so the cycle resolves, but a test that
imports ``src.nodes.X`` directly trips the partially-initialized
``src.nodes`` package. Warming ``src.graph`` here once, before any
test collects, defers to the same import order production uses. See
``tests/FAILURES.md`` 2026-04-30 for the original diagnosis.
"""

from __future__ import annotations

import src.graph  # noqa: F401 — import-order warm-up, see module docstring

import pytest


@pytest.fixture
def target_url() -> str:
    """A canonical target URL for tests that need a placeholder."""
    return "http://example.test"
