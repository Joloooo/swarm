# Failure Log

Per the test-on-failure policy in the root `CLAUDE.md`, every failure encountered
during development is recorded here — even ones that did **not** result in a
test being added. This file is a thesis artefact: a real, dated record of the
agent-failure modes encountered while building SwarmAttacker.

| Date | Symptom | Root cause | Test added? |
|------|---------|------------|-------------|
| 2026-04-30 | `pytest` collection failed with `ImportError: cannot import name 'planner_node' from partially initialized module 'src.nodes'` whenever a test imported `src.nodes.X` directly. | `src/nodes/planner.py` does `from src.graph import budgets` at module load, and `src.graph` does `from src.nodes import ...` — circular. Production entry points (`langgraph dev`, CLI) happen to import `src.graph` first so the cycle resolves; tests don't. | No test added. Worked around in `tests/conftest.py` by importing `src.graph` once before any test collects (matches the production import order). The proper fix is to move `budgets` into its own module so `planner.py` doesn't have to pull `src.graph`; deferred until a real failure motivates it. |
