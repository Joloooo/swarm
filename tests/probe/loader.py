"""Load a reflection-point fixture (pure YAML data) and resolve its captured input.

A fixture is a POINTER + a desired direction + a perturbation spec + a score
criterion — no agent logic, no prompt text (that all lives in ``src/``). The
captured LLM input lives either in a committed asset (``capture.mode: messages``,
``capture.ref: <file>.json``) or is read from the source run's
``full_logs.jsonl`` at the locator (``capture`` with no ``ref``). Logs are
gitignored, so a corpus fixture should ship the committed asset for durability.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

import yaml

PROBE_DIR = pathlib.Path(__file__).resolve().parent
FIXTURES_DIR = PROBE_DIR / "fixtures"
REPO_ROOT = PROBE_DIR.parents[1]  # .../SwarmAttacker


@dataclass
class Capture:
    mode: str                                  # "messages" | "state"
    ref: str = ""                              # asset filename (under fixtures/) — optional
    tools: list[str] = field(default_factory=list)  # tool NAMES to bind (F2: not in the log)


@dataclass
class Perturbation:
    name: str
    mode: str                                  # "crude" | "state" | "config"
    splice: dict = field(default_factory=dict)  # {find, replace} for crude
    patch: dict = field(default_factory=dict)   # state/config patch for honest mode


@dataclass
class Evaluation:
    type: str                                  # "deterministic" | "llm_judge"
    criterion: dict = field(default_factory=dict)
    n: int = 3
    pass_threshold: int = 2


@dataclass
class Fixture:
    id: str
    node: str                                  # planner | executor | summarizer
    level: int = 1                             # 1 = single-call replay, 2 = whole-node
    source_run: str = ""
    benchmark_id: str = ""
    agent_id: str = ""
    config_name: str = ""                      # skill identity (load-bearing for executor)
    locator: dict = field(default_factory=dict)
    capture: Capture | None = None
    state_seed: dict = field(default_factory=dict)  # Level-2: construct the node's input state
    observed_decision: str = ""
    desired_direction: str = ""
    perturbations: list[Perturbation] = field(default_factory=list)
    evaluation: Evaluation | None = None


def load_fixture(path: str | pathlib.Path) -> Fixture:
    """Parse a fixture YAML into a :class:`Fixture`. ``path`` may be absolute, a
    repo-relative path, or a bare filename resolved under ``fixtures/``."""
    p = pathlib.Path(path)
    if not p.is_absolute() and not p.exists():
        p = FIXTURES_DIR / path
    data = yaml.safe_load(p.read_text())
    cap = data.get("capture") or {}
    ev = data.get("evaluation") or {}
    return Fixture(
        id=data["id"],
        node=data["node"],
        level=int(data.get("level", 1)),
        source_run=data.get("source_run", ""),
        benchmark_id=data.get("benchmark_id", ""),
        agent_id=data.get("agent_id", ""),
        config_name=data.get("config_name", ""),
        locator=data.get("locator") or {},
        capture=Capture(
            mode=cap.get("mode", "messages"),
            ref=cap.get("ref", ""),
            tools=list(cap.get("tools") or []),
        ),
        state_seed=data.get("state_seed") or {},
        observed_decision=data.get("observed_decision", ""),
        desired_direction=data.get("desired_direction", ""),
        perturbations=[
            Perturbation(
                name=pp["name"],
                mode=pp.get("mode", "crude"),
                splice=pp.get("splice") or {},
                patch=pp.get("patch") or {},
            )
            for pp in (data.get("perturbations") or [])
        ],
        evaluation=Evaluation(
            type=ev.get("type", "deterministic"),
            criterion=ev.get("criterion") or {},
            n=int(ev.get("n", 3)),
            pass_threshold=int(ev.get("pass_threshold", 2)),
        ),
    )


def load_captured_event(fixture: Fixture) -> dict:
    """Return the captured ``llm_start`` event (with verbatim ``request.messages``)
    for a messages-mode fixture: the committed asset if ``capture.ref`` is set,
    else the source run's ``full_logs.jsonl`` located by ``(node, ts, match)``."""
    cap = fixture.capture
    if cap and cap.ref:
        ref = pathlib.Path(cap.ref)
        if not ref.is_absolute():
            ref = FIXTURES_DIR / cap.ref
        return json.loads(ref.read_text())
    return _locate_in_log(fixture)


def _locate_in_log(fixture: Fixture) -> dict:
    run = pathlib.Path(fixture.source_run)
    if not run.is_absolute():
        run = REPO_ROOT / fixture.source_run
    log = run if run.suffix == ".jsonl" else run / "full_logs.jsonl"
    ts = (fixture.locator or {}).get("ts")
    match = (fixture.locator or {}).get("match", "")
    for line in log.read_text().splitlines():
        if not line.strip():
            continue
        e = json.loads(line)
        if e.get("type") != "llm_start":
            continue
        if fixture.node and e.get("node") != fixture.node:
            continue
        if ts and e.get("ts") != ts:
            continue
        if match and match not in json.dumps(e.get("request", {})):
            continue
        return e
    raise LookupError(f"no llm_start matching locator {fixture.locator} in {log}")
