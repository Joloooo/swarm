"""Graph nodes — every node inherits from ``BaseNode`` (see ``base.py``).

Each module exposes both the class (``PlannerNode``, ``ReconNode``, ...)
and a singleton instance under the function-style name
(``planner_node``, ``recon_node``, ...) so ``src/graph.py`` can import
the instance and pass it straight to ``graph.add_node`` — instances
are callable via ``BaseNode.__call__``.
"""

from src.nodes.base import AgentConfig, BaseNode
from src.nodes.executor import ExecutorNode, executor_node
from src.nodes.initialize import InitializeNode, initialize_node
from src.nodes.planner import PlannerNode, planner_node
from src.nodes.recon import ReconNode, recon_node
from src.nodes.report import ReportNode, report_node
from src.nodes.summarizer import SummarizerNode, summarizer_node
from src.nodes.web_search import WebSearchNode, web_search_node

__all__ = [
    "AgentConfig",
    "BaseNode",
    "ExecutorNode",
    "InitializeNode",
    "PlannerNode",
    "ReconNode",
    "ReportNode",
    "SummarizerNode",
    "WebSearchNode",
    "executor_node",
    "initialize_node",
    "planner_node",
    "recon_node",
    "report_node",
    "summarizer_node",
    "web_search_node",
]
