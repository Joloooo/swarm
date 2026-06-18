# Worker-side LangChain callbacks for cooperative flag-capture cancellation
# (benchmark mode only — all hooks no-op when expected_flag is empty). Two
# channels: state.captured_flag drives routing post-node; a process-global
# _CAPTURED_FLAG lets in-flight siblings bail on their next LLM call. skill_runner
# catches both signals, so no exception escapes the executor node.

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler

from src.edges.flag_match import extract_flags, flags_match


# Process-global capture signal, checked by in-flight workers via callback hooks.
# Plain module var (workers are single-thread asyncio coroutines); a double-match
# race is harmless — both call signal_captured with the same value, both raise.
_CAPTURED_FLAG: str = ""


def signal_captured(flag: str) -> None:
    # Mark the run captured (idempotent). Called from on_tool_end the instant a
    # tool output matches expected_flag; later calls from siblings are no-ops.
    global _CAPTURED_FLAG
    if not _CAPTURED_FLAG:
        _CAPTURED_FLAG = (flag or "").strip()


def is_captured() -> bool:
    # True if any worker in this process has already captured the flag.
    return bool(_CAPTURED_FLAG)


def get_captured_flag() -> str:
    # The captured flag value (empty string until capture).
    return _CAPTURED_FLAG


def reset_captured() -> None:
    # Clear the signal. MUST run at the start of every benchmark in the daily
    # sweep (benchmarks.xbow_runner.run_one), else bench N+1 starts with bench N's
    # flag set and every worker exits immediately.
    global _CAPTURED_FLAG
    _CAPTURED_FLAG = ""


# ── Signals — raised by callbacks, caught by skill_runner ─────────────────


class FlagCapturedSignal(Exception):
    # Raised by on_tool_end on this worker's OWN flag match; carries the value.
    # skill_runner converts it to a normal result dict (it does NOT escape the
    # node). Siblings instead see the module-global and raise SiblingCapturedSignal.
    # NOT a Codex-refusal subclass, so the refusal-retry loop won't swallow it.

    def __init__(self, *, flag: str, agent_id: str = "", tool_name: str = ""):
        self.flag = flag
        self.agent_id = agent_id
        self.tool_name = tool_name
        super().__init__(
            f"flag captured by {agent_id or 'worker'} "
            f"via {tool_name or 'tool'}: {flag}"
        )


class SiblingCapturedSignal(Exception):
    # Raised by a sibling's LLM-start hook once another worker has captured.
    # The worker exits cleanly; skill_runner returns a minimal update so the
    # fan-in completes fast. Carries the flag for logging only (routing reads
    # state.captured_flag). NOT a Codex-refusal subclass, same as above.

    def __init__(self, *, captured_flag: str = "", agent_id: str = ""):
        self.captured_flag = captured_flag
        self.agent_id = agent_id
        super().__init__(
            f"sibling worker {agent_id or '?'} stopping early — "
            f"flag was captured by another worker: {captured_flag}"
        )


# ── The callback — own-match scan + sibling-cancel check ──────────────────


class FlagWatcherCallback(AsyncCallbackHandler):
    # Hooks tool/LLM events for cooperative capture cancellation; one instance
    # per worker (attach via call_config["callbacks"]). on_tool_end = own-match
    # (raise FlagCapturedSignal); on_(chat_model|llm)_start = sibling-cancel
    # (raise SiblingCapturedSignal before the next costly Codex call).

    # Load-bearing: without raise_error, LangChain's dispatcher logs the callback
    # exception and continues (the worker keeps iterating). With it, the signal
    # propagates through agent.astream to skill_runner, which catches it on purpose.
    raise_error: bool = True

    def __init__(
        self,
        *,
        expected_flag: str | Iterable[str],
        agent_id: str = "",
    ):
        # Accept a single expected flag (back-compat) or an iterable of candidates;
        # see src.edges.flag_match.flags_match for why benchmarks can have several.
        super().__init__()
        if isinstance(expected_flag, str):
            raw_candidates: tuple[str, ...] = (expected_flag,)
        else:
            raw_candidates = tuple(expected_flag or ())
        # Keep a normalized non-empty tuple — used by both the
        # callback hooks and (rare) external introspection.
        self.expected_flag_candidates: tuple[str, ...] = tuple(
            c.strip() for c in raw_candidates if (c or "").strip()
        )
        # Back-compat alias: the first candidate (or empty string).
        # Older callers and tests may still reach for ``expected_flag``.
        self.expected_flag: str = (
            self.expected_flag_candidates[0]
            if self.expected_flag_candidates
            else ""
        )
        self.agent_id = agent_id

    # ── Own-match path ───────────────────────────────────────────────

    async def on_tool_end(
        self,
        output: Any,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Real-pentest mode → no oracle, nothing to match against.
        if not self.expected_flag_candidates:
            return
        # Defence in depth: if a sibling captured the EXACT same flag
        # while we were running this tool, surface that as a sibling
        # signal so we don't double-write state.
        if is_captured():
            raise SiblingCapturedSignal(
                captured_flag=get_captured_flag(),
                agent_id=self.agent_id,
            )
        text = _coerce_to_text(output)
        # Cheap pre-filter: skip the regex walk when there's no "{" at all (the
        # dominant case — recon/gobuster/curl output with no flag).
        if not text or "{" not in text:
            return
        tool_name = kwargs.get("name") or ""
        for candidate in extract_flags(text):
            if flags_match(
                submitted=candidate,
                expected=self.expected_flag_candidates,
            ):
                # Mark process-globally BEFORE raising, so sibling
                # workers can see it at their next callback hook.
                signal_captured(candidate)
                raise FlagCapturedSignal(
                    flag=candidate,
                    agent_id=self.agent_id,
                    tool_name=tool_name,
                )

    # ── Sibling-cancel path ──────────────────────────────────────────

    async def on_llm_start(
        self,
        serialized: Any = None,
        prompts: Any = None,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Fires before a (non-chat) LLM call. Most agents use on_chat_model_start;
        # we hook both so a future provider switch can't silently break sibling-cancel.
        if not self.expected_flag_candidates:
            return
        if is_captured():
            raise SiblingCapturedSignal(
                captured_flag=get_captured_flag(),
                agent_id=self.agent_id,
            )

    async def on_chat_model_start(
        self,
        serialized: Any = None,
        messages: Any = None,
        *,
        run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        # Fires before each chat-model call — the load-bearing sibling-cancel hook
        # (gpt-5.5 calls are 60–90 s; this is the earliest a sibling can abort).
        if not self.expected_flag_candidates:
            return
        if is_captured():
            raise SiblingCapturedSignal(
                captured_flag=get_captured_flag(),
                agent_id=self.agent_id,
            )


def _coerce_to_text(output: Any) -> str:
    # Flatten an arbitrary tool-output value into a searchable string. bash returns
    # str (the common case), but LangChain may wrap outputs in a ToolMessage or a
    # content-block list, so flatten defensively. Unrepresentable objects return ""
    # rather than raising — observability must never break a worker loop.
    if output is None:
        return ""
    if isinstance(output, str):
        return output
    # ToolMessage / AIMessage / any message-like object.
    content = getattr(output, "content", None)
    if content is not None and content is not output:
        return _coerce_to_text(content)
    if isinstance(output, list):
        return "\n".join(_coerce_to_text(x) for x in output)
    if isinstance(output, dict):
        # Common content-block shape: {"type": "text", "text": "..."}.
        if "text" in output:
            return _coerce_to_text(output.get("text"))
        return "\n".join(_coerce_to_text(v) for v in output.values())
    try:
        return str(output)
    except Exception:  # noqa: BLE001
        return ""
