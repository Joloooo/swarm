"""Offline tests for the Level-2 node-replay machinery (Phase 3).

Validates the parts that must be right before any live node run: the target gate
(only the executor needs a container), that the harness binds the SAME node
singleton production wires into the graph (F1), state construction from a
fixture's state_seed, and the node-result scorer. The live whole-node run is
exercised in verification (planner) and Phase 4 (executor on Docker) — a fake
model is forbidden here (SKILL §3), so it is not part of this offline suite.
"""

from __future__ import annotations

import asyncio

import pytest
from langchain_core.messages import HumanMessage

from tests.probe.level2 import (
    build_initial_state,
    needs_target,
    node_singleton,
    run_executor_node,
    run_node_n,
)
from tests.probe.loader import load_fixture
from tests.probe.score import score_node_once


def test_gate_only_executor_needs_a_target():
    assert needs_target("executor") is True
    assert needs_target("planner") is False
    assert needs_target("summarizer") is False


def test_node_singleton_is_the_real_graph_node():
    from src.nodes import planner_node

    # F1: the harness runs the SAME object the graph registers — no second
    # construction, nothing to drift.
    assert node_singleton("planner") is planner_node
    assert node_singleton("does-not-exist") is None


def test_build_initial_state_from_seed():
    fx = load_fixture("063-planner-coldstart.yaml")
    state = build_initial_state(fx)
    assert state["target_url"] == "http://127.0.0.1:5000"
    assert isinstance(state["messages"][0], HumanMessage)
    assert state["findings"] == []
    assert state["crawl_mode"] == "9"


def test_score_node_result():
    crit = {"kind": "node_action", "equals": "recon"}
    assert score_node_once({"next_action": "recon"}, crit) is True
    assert score_node_once({"next_action": "attack"}, crit) is False
    assert score_node_once({"findings": [1, 2]}, {"kind": "findings_min", "min": 2}) is True
    assert score_node_once({"captured_flag": "FLAG{x}"}, {"kind": "captured_flag"}) is True


def test_executor_level2_refuses_without_a_live_target():
    # The executor acts on the target, so run_node_n must reject it and point at
    # the provisioning path rather than run it against a dead target.
    with pytest.raises(RuntimeError, match="acts on the target"):
        asyncio.run(run_node_n("executor", {}, n=1))


def test_executor_runner_requires_config_name_and_benchmark():
    # run_executor_node validates the load-bearing inputs BEFORE provisioning a
    # container (so a bad fixture fails fast, not after a Docker bring-up).
    fx = load_fixture("063-ssti-executor.yaml")
    assert fx.config_name == "ssti" and fx.benchmark_id == "XBEN-063-24"

    no_config = load_fixture("063-ssti-executor.yaml")
    no_config.config_name = ""
    with pytest.raises(ValueError, match="config_name"):
        asyncio.run(run_executor_node(no_config, n=1))

    no_bench = load_fixture("063-ssti-executor.yaml")
    no_bench.benchmark_id = ""
    with pytest.raises(ValueError, match="benchmark_id"):
        asyncio.run(run_executor_node(no_bench, n=1))
