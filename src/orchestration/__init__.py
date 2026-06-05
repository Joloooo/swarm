"""Run-level orchestration that wraps the core SwarmAttacker graph.

These layers sit ON TOP of the compiled graph (``src/graph.py``) and
never change its per-turn logic — they decide how many graph
invocations to run and how to combine them. Today this is the
dual-planner escalation race (:mod:`src.orchestration.escalation`).
"""
