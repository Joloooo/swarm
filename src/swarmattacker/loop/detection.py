"""Loop detection strategies.

Multi-strategy approach:
1. Hard cap — absolute maximum tool calls per agent
2. Repeating call detector — catches agents stuck in a loop
3. Budget pressure — injects remaining budget into tool responses
4. Similarity detector — catches near-identical (not just exact) repeated calls

Integrated into the agent execution via a tool wrapper that intercepts
every tool call, records it, and checks for loop conditions.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class LoopDetectionResult:
    should_stop: bool
    reason: str = ""
    budget_warning: str = ""  # Injected into tool output as budget pressure


class LoopDetector:
    """Monitors an agent's tool calls and decides when to stop."""

    def __init__(
        self,
        max_tool_calls: int = 50,
        max_repeated_calls: int = 3,
        budget_pressure: bool = True,
    ):
        self.max_tool_calls = max_tool_calls
        self.max_repeated_calls = max_repeated_calls
        self.budget_pressure = budget_pressure
        self._call_history: list[str] = []
        self._tool_names: list[str] = []

    def record_call(self, tool_name: str, args_str: str) -> None:
        """Record a tool call for analysis."""
        args_hash = hashlib.md5(args_str.encode()).hexdigest()[:8]
        self._call_history.append(f"{tool_name}:{args_hash}")
        self._tool_names.append(tool_name)

    def check(self) -> LoopDetectionResult:
        """Check all loop detection strategies."""
        # Strategy 1: Hard cap
        if len(self._call_history) >= self.max_tool_calls:
            return LoopDetectionResult(
                should_stop=True,
                reason=f"Hard cap reached: {self.max_tool_calls} tool calls",
            )

        # Strategy 2: Exact repeating call detector
        if len(self._call_history) >= self.max_repeated_calls:
            recent = self._call_history[-self.max_repeated_calls:]
            if len(set(recent)) == 1:
                return LoopDetectionResult(
                    should_stop=True,
                    reason=(
                        f"Repeated identical call {self.max_repeated_calls} times: "
                        f"{recent[0]}"
                    ),
                )

        # Strategy 3: Same-tool repetition (different args but same tool)
        if len(self._tool_names) >= 5:
            recent_tools = self._tool_names[-5:]
            if len(set(recent_tools)) == 1:
                return LoopDetectionResult(
                    should_stop=True,
                    reason=(
                        f"Same tool called 5 times in a row: {recent_tools[0]}. "
                        f"Agent may be stuck."
                    ),
                )

        # Strategy 4: Budget pressure (warning, not a stop)
        budget_warning = ""
        if self.budget_pressure:
            remaining = self.calls_remaining
            total = self.max_tool_calls
            if remaining <= 5:
                budget_warning = (
                    f"\n[BUDGET WARNING: {remaining}/{total} tool calls remaining. "
                    f"Wrap up and report your findings now.]\n"
                )
            elif remaining <= total * 0.25:
                budget_warning = (
                    f"\n[BUDGET: {remaining}/{total} tool calls remaining. "
                    f"Prioritize your most important tests.]\n"
                )

        return LoopDetectionResult(
            should_stop=False,
            budget_warning=budget_warning,
        )

    @property
    def calls_remaining(self) -> int:
        return max(0, self.max_tool_calls - len(self._call_history))

    @property
    def total_calls(self) -> int:
        return len(self._call_history)

    def summary(self) -> str:
        """Return a summary of tool usage for the report."""
        counter = Counter(self._tool_names)
        lines = [f"Total tool calls: {self.total_calls}"]
        for tool, count in counter.most_common():
            lines.append(f"  {tool}: {count}")
        return "\n".join(lines)
