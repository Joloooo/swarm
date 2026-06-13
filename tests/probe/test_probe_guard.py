"""Guard test — the no-divergence enforcement contract (SKILL enforcement-contract.md).

The harness must be a DRIVER OVER DATA: it may import prompts/builders/nodes from
``src/`` but must re-define none of them, must not subclass a node, must not mock
the model's output, and ``src/`` must never import the harness (one-directional
dependency). These are cheap AST/grep checks kept in the default suite so a future
edit cannot quietly add a copy that drifts from production.
"""

from __future__ import annotations

import ast
import pathlib
import re

PROBE_DIR = pathlib.Path(__file__).resolve().parent
SRC_DIR = PROBE_DIR.parents[1] / "src"

# Names that would mean the harness re-implemented a prompt/builder rather than
# importing it. Importing any of these from src/ is fine; DEFINING one is not.
_FORBIDDEN_DEF = re.compile(
    r"^(get_\w+_prompt|_build_system_message|_format_\w+|build_nodes|_seed\w*|\w+_directive)$"
)


def _harness_modules() -> list[pathlib.Path]:
    return [p for p in PROBE_DIR.glob("*.py") if not p.name.startswith("test_")]


def test_harness_redefines_no_prompt_builder_or_node():
    offenders = []
    for path in _harness_modules():
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _FORBIDDEN_DEF.match(node.name):
                offenders.append(f"{path.name}: def {node.name}")
            if isinstance(node, ast.ClassDef):
                base_names = {b.id for b in node.bases if isinstance(b, ast.Name)}
                if "BaseNode" in base_names:
                    offenders.append(f"{path.name}: class {node.name}(BaseNode)")
    assert not offenders, "harness re-defines src/ builder/node: " + "; ".join(offenders)


def test_harness_does_not_mock_model_output():
    for path in _harness_modules():
        text = path.read_text()
        assert "FakeListChatModel" not in text, (
            f"{path.name} uses FakeListChatModel — forbidden in agentic testing, "
            "where the model's real output is the thing under test (SKILL §3)."
        )


def test_dependency_is_one_directional():
    offenders = []
    for path in SRC_DIR.rglob("*.py"):
        text = path.read_text(errors="ignore")
        if "import tests.probe" in text or "from tests.probe" in text:
            offenders.append(str(path.relative_to(SRC_DIR.parent)))
    assert not offenders, "src/ imports the harness (must be one-directional): " + ", ".join(offenders)
