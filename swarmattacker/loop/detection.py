"""Loop detection strategies.

Multi-strategy approach:
1. Hard cap — absolute maximum tool calls per agent
2. Repeating call detector — catches agents stuck in a loop
3. Budget pressure — reduces remaining calls after each iteration

Phase 4 will implement the full system. This module provides the
interface and a basic hard-cap implementation.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass


@dataclass
class LoopDetectionResult:
    should_stop: bool
    reason: str = ""


class LoopDetector:
    """Monitors an agent's tool calls and decides when to stop."""

    def __init__(
        self,
        max_tool_calls: int = 50,
        max_repeated_calls: int = 3,
    ):
        self.max_tool_calls = max_tool_calls
        self.max_repeated_calls = max_repeated_calls
        self._call_history: list[str] = []

    def record_call(self, tool_name: str, args_hash: str) -> None:
        """Record a tool call for analysis."""
        self._call_history.append(f"{tool_name}:{args_hash}")

    def check(self) -> LoopDetectionResult:
        """Check all loop detection strategies."""
        # Strategy 1: Hard cap
        if len(self._call_history) >= self.max_tool_calls:
            return LoopDetectionResult(
                should_stop=True,
                reason=f"Hard cap reached: {self.max_tool_calls} tool calls",
            )

        # Strategy 2: Repeating call detector
        if len(self._call_history) >= self.max_repeated_calls:
            recent = self._call_history[-self.max_repeated_calls:]
            if len(set(recent)) == 1:
                return LoopDetectionResult(
                    should_stop=True,
                    reason=f"Repeated identical call {self.max_repeated_calls} times: {recent[0]}",
                )

        # Strategy 3: Budget pressure (returns remaining budget info)
        # Full implementation in Phase 4
        return LoopDetectionResult(should_stop=False)

    @property
    def calls_remaining(self) -> int:
        return max(0, self.max_tool_calls - len(self._call_history))

    @property
    def total_calls(self) -> int:
        return len(self._call_history)
