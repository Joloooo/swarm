"""Live terminal renderer — the colored, mode-aware view on stderr.

This is the *only* place stderr formatting happens during a run. Every
other emission site (``BaseNode.__call__``, ``shell._common._verbose_print``,
``benchmarks.xbow_runner``) calls into the ``LIVE`` singleton here.

The single ``config.verbosity.mode`` (``silent``/``compact``/``verbose``)
decides what each call actually prints:

* ``silent``  — only ``LIVE.bench_start`` / ``LIVE.bench_end`` / runner errors.
* ``compact`` — one colored line per planner decision, shell command,
  shell outcome, finding, warning, node lifecycle. Default.
* ``verbose`` — today's behaviour: full multi-line dump of every new
  ``AIMessage``/``ToolMessage`` and every command tail line.

Disk artefacts (``logs/run-<id>/...``) are *unchanged in every mode*. This
module never writes to disk — only to stderr.

``config`` is imported lazily inside each method so this module can be
imported from ``observability/__init__.py`` without triggering the
``graph → nodes → base → observability → graph`` cycle.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sys
import time
from typing import Any
from uuid import UUID


# ─────────────────────────── ANSI helpers ────────────────────────────

_RESET   = "\033[0m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"
_RED     = "\033[31m"
_GREEN   = "\033[32m"
_YELLOW  = "\033[33m"
_BLUE    = "\033[34m"
_MAGENTA = "\033[35m"
_CYAN    = "\033[36m"
_WHITE   = "\033[37m"


def _color_enabled() -> bool:
    """Read the live config; default to no-color if config not yet loaded."""
    try:
        from src.graph import config
        return bool(config.verbosity.color)
    except Exception:
        return False


def _mode() -> str:
    """Read the live config; default to ``compact`` if not yet loaded."""
    try:
        from src.graph import config
        return str(config.verbosity.mode)
    except Exception:
        return "compact"


def _paint(text: str, *codes: str) -> str:
    """Wrap ``text`` in ANSI codes if color is enabled, else return as-is."""
    if not _color_enabled() or not codes:
        return text
    return "".join(codes) + text + _RESET


def _now() -> str:
    return time.strftime("%H:%M:%S")


def _emit(line: str) -> None:
    """Single stderr write — keeps every line atomic across threads."""
    print(line, file=sys.stderr, flush=True)


# ─────────────── Helpers for trimming / extracting text ──────────────

_MAX_CMD = 120
_MAX_TAIL_INLINE = 200  # bytes — below this we may inline the full output


def _clip(s: str, n: int) -> str:
    s = s.replace("\n", " ⏎ ")
    return s if len(s) <= n else s[: n - 1] + "…"


def _first_nonempty(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def _last_nonempty(text: str) -> str:
    for line in reversed(text.splitlines()):
        line = line.strip()
        if line:
            return line
    return ""


def _summarize_output(tail: str, exit_code: int | None) -> str:
    """One-line summary of a command tail. Used in ``compact`` mode.

    * empty tail → just the exit-code chip (caller adds it).
    * exit==0 and short → first non-empty line.
    * exit==0 and long  → first line + ``+N more lines`` if multi-line.
    * exit!=0 → last non-empty line (the actual error usually surfaces last).
    * HTTP responses (first line starts with ``HTTP/``) → status + server.
    """
    text = (tail or "").strip()
    if not text:
        return ""

    lines = [ln for ln in text.splitlines() if ln.strip()]
    first = lines[0] if lines else ""
    if first.startswith("HTTP/"):
        # Tight HTTP one-liner: status line + Server header (if present).
        # Total response size is already shown by the parent line as bytes.
        bits = [first]
        for ln in lines[:20]:
            if ln.lower().startswith("server:"):
                bits.append(f"server={ln.split(':', 1)[1].strip()}")
                break
        return ", ".join(bits)

    if (exit_code is not None) and exit_code != 0:
        return _clip(_last_nonempty(text), 200)

    if len(lines) <= 1 and len(text) < _MAX_TAIL_INLINE:
        return _clip(text, 200)

    extra = len(lines) - 1
    suffix = f"  +{extra} more line{'s' if extra != 1 else ''}" if extra > 0 else ""
    return _clip(first, 180) + suffix


# ───────────────── Planner JSON → one-line decision ──────────────────

_JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


def _extract_planner_decision(text: str) -> dict | None:
    """Pull the ``{action, target_url, reasoning, ...}`` dict out of an
    AIMessage emitted by the planner. The supervisor wraps it in a
    fenced ```json ...``` block; we also accept a bare ``{...}`` body.
    Returns ``None`` if nothing parseable is found.
    """
    if not text:
        return None
    m = _JSON_FENCE.search(text)
    candidate = m.group(1) if m else None
    if candidate is None:
        # fall back: look for the first {...} block that contains "action"
        idx = text.find("{")
        if idx < 0:
            return None
        candidate = text[idx:]
    # tolerate trailing commas: trim to the last `}`
    last = candidate.rfind("}")
    if last >= 0:
        candidate = candidate[: last + 1]
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        try:
            # second chance: drop trailing commas
            cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) and "action" in data else None


# ─────────────────────────── The renderer ────────────────────────────


class _Live:
    """Singleton — call methods on the module-level ``LIVE`` instance.

    All public methods are no-ops in ``silent`` mode except those that
    mark benchmark boundaries. They delegate to ``_compact_*`` /
    ``_verbose_*`` based on the live mode.
    """

    def __init__(self) -> None:
        # Per-node dedup of duplicated AIMessage content (planner emits
        # the same JSON twice across retry+repaired-parse path).
        self._seen_msg_hashes: set[int] = set()
        # Per-LLM-call thinking state, keyed by the LangChain run_id
        # UUID. Each entry holds:
        #   started   — perf_counter timestamp
        #   agent     — agent_id label for the header
        #   model     — display string
        #   delta_seen— True once any reasoning delta has arrived
        #               (suppresses heartbeat — deltas already prove
        #               liveness and the heartbeat would race them)
        #   last_delta— perf_counter of the most recent delta
        #   on_new_line — True when the next delta needs to start on a
        #                 fresh line (after the header, after a "still
        #                 thinking" heartbeat). Guards against deltas
        #                 appearing concatenated on the same line as
        #                 prior emit() output.
        #   heartbeat_task — asyncio.Task or None
        self._think_state: dict[Any, dict[str, Any]] = {}
        # Startup banner runs once per process even if the runner
        # invokes the renderer multiple times (e.g. langgraph dev).
        self._banner_emitted: bool = False

    # -------- benchmark boundaries (always visible) ----------

    def bench_start(
        self,
        bench_id: str,
        target: str | None,
        expected_flag: str | None,
    ) -> None:
        self._seen_msg_hashes.clear()
        head = _paint(f"◆ {bench_id}", _BOLD, _CYAN)
        target_part = f"target={target}" if target else "target=?"
        flag_part = ""
        if expected_flag:
            short = expected_flag if len(expected_flag) <= 18 else expected_flag[:15] + "…}"
            flag_part = f"  expected={short}"
        _emit(f"{_now()}  {head}  {target_part}{flag_part}")

    def bench_end(
        self,
        bench_id: str,
        *,
        ok: bool,
        duration_s: float,
        findings_n: int,
        summary_path: str | None,
        error: str | None = None,
    ) -> None:
        if error:
            head = _paint(f"⚠ {bench_id}", _BOLD, _YELLOW)
            verdict = _paint(f"ERROR: {error}", _YELLOW)
        elif ok:
            head = _paint(f"◆ {bench_id}", _BOLD, _GREEN)
            verdict = _paint("✓ FLAG FOUND", _BOLD, _GREEN)
        else:
            head = _paint(f"◇ {bench_id}", _YELLOW)
            verdict = _paint("✗ no flag", _YELLOW)
        tail = f"({duration_s:.1f}s, {findings_n} finding{'s' if findings_n != 1 else ''})"
        _emit(f"{_now()}  {head}  {verdict}  {tail}")
        if summary_path:
            _emit(f"           {_paint('summary', _DIM)} → {summary_path}")

    # -------- runner-side messages ----------

    def runner_message(self, text: str, *, level: str = "info") -> None:
        if _mode() == "silent" and level == "info":
            return
        if level == "error":
            _emit(_paint(text, _RED))
        elif level == "warn":
            _emit(_paint(text, _YELLOW))
        else:
            _emit(_paint(text, _DIM))

    def docker_phase(
        self,
        bench_id: str,
        phase: str,
        duration_s: float,
    ) -> None:
        if _mode() == "silent":
            return
        _emit(
            f"{_now()}  {_paint('▸ docker  ', _DIM, _BLUE)}"
            f"{bench_id} {phase} ({duration_s:.1f}s)"
        )

    # -------- node lifecycle ----------

    def node_finished(
        self,
        name: str,
        duration_ms: int,
        summary: str,
        new_messages: list[Any] | None,
    ) -> None:
        mode = _mode()
        if mode == "silent":
            return
        if mode == "verbose":
            self._verbose_node(name, duration_ms, summary, new_messages or [])
            return
        # compact
        self._compact_node(name, duration_ms, summary, new_messages or [])

    def _verbose_node(
        self,
        name: str,
        duration_ms: int,
        summary: str,
        new_messages: list[Any],
    ) -> None:
        # Reproduces the original SWARM_VERBOSE block from base.py.
        ts = _now()
        _emit(f"\n─── [{ts}] node `{name}` finished in {duration_ms} ms ───\n"
              f"    {summary}")
        for msg in new_messages:
            content = getattr(msg, "content", None)
            if not content:
                continue
            kw = getattr(msg, "additional_kwargs", None) or {}
            if kw.get("node") and isinstance(content, str) and (
                content.startswith("✅ [") or content.startswith("❌ [")
            ):
                continue
            role = type(msg).__name__
            text = content if isinstance(content, str) else str(content)
            _emit(f"    └── {role}:")
            for line in text.splitlines() or [""]:
                _emit(f"        {line}")

    def _compact_node(
        self,
        name: str,
        duration_ms: int,
        summary: str,
        new_messages: list[Any],
    ) -> None:
        # Planner: parse decisions out of the AIMessages; render one line
        # per unique decision. Other nodes: a single dim "▸ name finished"
        # line — tool calls are surfaced separately by shell_command.
        if name == "planner":
            self._render_planner_messages(new_messages, duration_ms)
            return

        # Worker / lifecycle node — structured summary line first.
        head = _paint(f"▸ {name:<8s}", _DIM, _BLUE)
        body = f"{summary}" if summary else "ok"
        # Append a per-agent token totals chip so the user sees the
        # cost of the worker turn inline. Pulls from the running
        # totals maintained by TokenLoggingCallback. We aggregate
        # across every active_agents entry mentioned in the summary
        # — at worker exit there's typically one, sometimes more
        # for fan-out skills like custom-attack.
        tokens_chip = self._aggregate_token_chip(summary)
        tail = f"  ({_fmt_ms(duration_ms)})"
        if tokens_chip:
            tail = f"  ({_fmt_ms(duration_ms)}, {tokens_chip})"
        _emit(f"{_now()}  {head} {body}{tail}")
        # Then a 💭 line per non-trivial worker AIMessage so the LLM's
        # narrative between tool calls is visible. Without this the user
        # only sees commands, not reasoning between them.
        self._emit_worker_thoughts(new_messages)

    def _aggregate_token_chip(self, summary: str) -> str:
        """Pull running token totals for whichever agent_ids appear in
        ``summary`` (the ``active: foo,bar`` part) and render a chip
        like ``in=187k peak=22k think=8.5k``.

        Empty string when no totals are recorded yet (e.g. a node that
        does no LLM calls). Uses lazy import so live.py doesn't have a
        compile-time dependency on llm/callbacks.py — that module
        imports observability which re-exports this one.
        """
        try:
            from src.llm.callbacks import TOKEN_TOTALS
        except Exception:
            return ""
        # Pull active-agent ids out of the summary string. Format:
        # ``... active: a,b,c ...``. If absent, fall back to all agents.
        m = re.search(r"active:\s*([^\s]+)", summary or "")
        if m:
            agents = [s.strip() for s in m.group(1).split(",") if s.strip()]
        else:
            agents = list(TOKEN_TOTALS.keys())
        if not agents:
            return ""
        in_sum = 0
        out_sum = 0
        think_sum = 0
        peak = 0
        for a in agents:
            t = TOKEN_TOTALS.get(a)
            if not t:
                continue
            in_sum += t.input_tokens
            out_sum += t.output_tokens
            think_sum += t.reasoning_tokens
            if t.peak_input > peak:
                peak = t.peak_input
        if not in_sum and not out_sum:
            return ""
        return (
            f"in={_fmt_tokens(in_sum)} "
            f"out={_fmt_tokens(out_sum)} "
            f"think={_fmt_tokens(think_sum)} "
            f"peak={_fmt_tokens(peak)}"
        )

    def _render_planner_messages(
        self,
        new_messages: list[Any],
        duration_ms: int,
    ) -> None:
        """Walk the planner's new AIMessages, print one ``● planner →...``
        line per *unique* decision. Duplicate JSON copies (the supervisor
        retry path re-emits the same payload) are deduped by content hash.
        """
        rendered_any = False
        for msg in new_messages:
            content = getattr(msg, "content", None)
            if not isinstance(content, str) or not content:
                continue
            kw = getattr(msg, "additional_kwargs", None) or {}
            # Skip the boundary ✅/❌ messages base.py injects.
            if kw.get("node") and (
                content.startswith("✅ [") or content.startswith("❌ [")
            ):
                continue
            decision = _extract_planner_decision(content)
            if decision is None:
                continue
            # Dedup duplicate JSON emissions within a single planner turn.
            key = hash((decision.get("action"),
                        decision.get("target_url"),
                        decision.get("reasoning")))
            if key in self._seen_msg_hashes:
                continue
            self._seen_msg_hashes.add(key)

            action = str(decision.get("action") or "?")
            target = decision.get("target_url") or ""
            reasoning = (decision.get("reasoning") or "").strip()
            short = _clip(reasoning, 110)

            head = _paint("● planner ", _MAGENTA)
            arrow = _paint(f"→ {action}", _BOLD, _MAGENTA)
            target_part = f"  {target}" if target else ""
            reason_part = f'  "{short}"' if short else ""
            _emit(f"{_now()}  {head}{arrow}{target_part}"
                  f"{reason_part}  ({_fmt_ms(duration_ms)})")
            rendered_any = True

        if not rendered_any:
            # Fallback — planner produced no parseable decision (e.g. tool
            # call only). Still mark the lifecycle so the user sees the
            # planner ran.
            head = _paint("▸ planner ", _DIM, _BLUE)
            _emit(f"{_now()}  {head} (no decision yet, {_fmt_ms(duration_ms)})")

    def _emit_multiline(
        self,
        prefix: str,
        text: str,
        *,
        color: str = "",
        indent_cols: int = 12,
    ) -> None:
        """Emit ``text`` under the timestamp column, full-width, no clipping.

        First line gets ``prefix`` (e.g. ``"💭 [agent] "`` or ``"↳ "``);
        subsequent paragraph lines get a hanging indent that aligns with
        the start of the prefixed text so multi-line LLM narratives stay
        visually grouped. Color is applied to the *body text only* — the
        prefix stays neutral so the marker is obvious even on dim
        terminals.

        ``indent_cols`` matches the width of the ``HH:MM:SS  `` column
        so the body sits under the timestamp gutter.
        """
        indent = " " * indent_cols
        # Hanging indent for continuation lines: the prefix is visual
        # (emoji + brackets); approximate its display width with len().
        # Two-space pad keeps the wrapper readable even when the prefix
        # is short ("↳ ").
        hang = " " * max(len(prefix), 2)
        lines = [ln for ln in text.splitlines() if ln.strip()] or [text]
        first, rest = lines[0], lines[1:]
        _emit(f"{indent}{prefix}{_paint(first, color) if color else first}")
        for cont in rest:
            painted = _paint(cont, color) if color else cont
            _emit(f"{indent}{hang}{painted}")

    def _emit_worker_thoughts(self, new_messages: list[Any]) -> None:
        """Render worker AIMessages between tool calls as 💭 lines.

        These are the LLM's narrative reasoning — the analysis it
        emits after seeing a tool result and before deciding the next
        action. Without this stream, compact mode shows commands but
        not why each was chosen or what the LLM made of the result.

        Emits the *full* content of each message (no clipping) in
        bold so the LLM's voice is the most-readable thing on screen
        — bash commands and tool mechanics fade into the dim
        background, the operator's eye lands on what the model said.

        Skips:
          - non-AIMessage entries (ToolMessages — already shown via
            ``LIVE.shell_output``);
          - empty content (tool-call-only AIMessages);
          - boundary ``✅``/``❌`` messages we ourselves inject;
          - finding markdown blocks (already rendered via
            ``LIVE.finding`` from base.py with severity coloring).
        """
        # Lazy import — keeps live.py importable without langchain at
        # module-load time.
        from langchain_core.messages import AIMessage

        for msg in new_messages:
            if not isinstance(msg, AIMessage):
                continue
            content = getattr(msg, "content", None)
            if not isinstance(content, str) or not content.strip():
                continue
            kw = getattr(msg, "additional_kwargs", None) or {}
            if kw.get("node") and (
                content.startswith("✅ [") or content.startswith("❌ [")
            ):
                continue
            stripped = content.strip()
            # Findings get their own ▣ line via base.py — don't re-show.
            if (
                stripped.startswith("**FINDING:**")
                or stripped.startswith("## FINDING")
                or stripped.startswith("## Finding")
            ):
                continue
            agent = kw.get("agent_id") or ""
            agent_part = f"[{agent}] " if agent else ""
            self._emit_multiline(
                f"💭 {agent_part}", stripped, color=_BOLD,
            )

    # -------- shell tool ----------

    def shell_command(
        self,
        agent: str | None,
        backend: str,
        cmd: str,
        reasoning: str,
    ) -> None:
        mode = _mode()
        if mode == "silent":
            return
        if mode == "verbose":
            ts = _now()
            tag = f"[{agent or '?'} @ {ts}]"
            _emit(f"\n{tag} ({backend}) $ {cmd}")
            if reasoning:
                _emit(f"{tag}   reasoning: {reasoning}")
            return
        # compact — bash command (mechanics) is dim; the LLM's reasoning
        # underneath is bold so it stands out, since *why* the LLM ran the
        # command is the higher-signal information for the operator.
        head = _paint("$ ", _DIM, _WHITE)
        ag = _paint(_agent_tag(agent), _CYAN)
        cmd_text = _paint(_clip(cmd, _MAX_CMD), _DIM)
        _emit(f"{_now()}  {head}{ag} {cmd_text}")
        if reasoning and reasoning.strip():
            # Indent under the timestamp column so the reasoning visually
            # belongs to its parent command. Full text — no clipping —
            # so the operator can read the LLM's complete hypothesis.
            self._emit_multiline(
                "↳ ", reasoning.strip(), color=_BOLD,
            )

    def shell_output(
        self,
        agent: str | None,
        *,
        exit_code: int | None,
        duration_ms: int | str,
        n_bytes: int | str,
        tail: str,
    ) -> None:
        mode = _mode()
        if mode == "silent":
            return
        if mode == "verbose":
            ts = _now()
            tag = f"[{agent or '?'} @ {ts}]"
            suffix = f", exit={exit_code}" if exit_code is not None else ""
            _emit(f"{tag} ↳ output ({duration_ms} ms, {n_bytes} bytes{suffix}):")
            for line in str(tail).splitlines() or [""]:
                _emit(f"{tag}   {line}")
            return
        # compact
        ok = (exit_code == 0) or (exit_code is None)
        if ok:
            mark = _paint("✓ ", _GREEN)
        else:
            mark = _paint("✗ ", _RED)
        ag = _paint(_agent_tag(agent), _CYAN)
        ec = "" if exit_code is None else f"exit={exit_code}  "
        size = _fmt_bytes(n_bytes)
        dur = _fmt_ms(duration_ms)
        synopsis = _summarize_output(tail, exit_code)
        # Synopsis is tool-output mechanics — dim by default so the
        # operator's eye lands on LLM reasoning instead. Errors stay
        # red because real failures are something the user needs to notice.
        if not synopsis:
            synopsis_part = ""
        elif not ok:
            synopsis_part = "  " + _paint(synopsis, _RED)
        else:
            synopsis_part = "  " + _paint(synopsis, _DIM)
        meta = _paint(f"{ec}{size}  ({dur})", _DIM)
        _emit(f"{_now()}  {mark}{ag} {meta}{synopsis_part}")

    # -------- findings & warnings ----------

    def finding(
        self,
        *,
        severity: str,
        title: str,
        agent: str | None = None,
        url: str | None = None,
        payload: str | None = None,
    ) -> None:
        if _mode() == "silent":
            return
        sev = (severity or "INFO").upper()
        if sev in ("CRITICAL", "HIGH"):
            color = _RED
            decoration = (_BOLD,)
        elif sev == "MEDIUM":
            color = _YELLOW
            decoration = ()
        else:
            color = _WHITE
            decoration = (_DIM,)
        head = _paint(f"▣ [{sev}]", color, *decoration)
        bits = [head, title]
        if agent:
            bits.append(_paint(f"({agent})", _DIM))
        if url:
            bits.append(_paint(url, _DIM))
        if payload:
            bits.append(_paint(f'payload="{_clip(payload, 60)}"', _DIM))
        _emit(f"{_now()}  " + "  ".join(bits))

    def warning(self, text: str, *, kind: str = "warning") -> None:
        if _mode() == "silent":
            return
        head = _paint("⚠ ", _BOLD, _YELLOW)
        _emit(f"{_now()}  {head}{_paint(text, _YELLOW)}")

    # -------- LLM call observability ----------

    # Context-rot threshold. Codex models advertise a 256k window, but
    # quality on multi-turn tool-use trajectories degrades visibly past
    # ~128k. The threshold is set to 100k so a warning fires *before*
    # we hit the rot zone, giving the user time to abort or trim. Override
    # with SWARM_LIVE_CONTEXT_WARN env var if a future model raises the
    # bar.
    _CONTEXT_WARN_INPUT_TOKENS = 100_000

    # Heartbeat cadence — how often to print "…still thinking" while
    # the model is producing zero reasoning deltas. 30 s lands between
    # "too noisy" and "useful pulse" for the typical xhigh-effort
    # 30 s – 3 min Codex thinking phase.
    _HEARTBEAT_SECS = float(os.environ.get(
        "SWARM_LIVE_THINK_HEARTBEAT_SECS", "30",
    ))

    def thinking_started(
        self,
        *,
        agent: str,
        run_id: Any,
        model: str,
        reasoning_effort: str = "",
    ) -> None:
        """Print the "🧠 thinking…" header for a new LLM call and
        schedule a heartbeat task.

        Mode behaviour:
          - silent: no output, no heartbeat.
          - compact: header + heartbeat (deltas suppressed; the
            heartbeat is the user's only mid-call signal).
          - verbose: header + per-delta streaming + heartbeat
            fallback when no delta has arrived for HEARTBEAT_SECS.

        Idempotent — calling twice with the same ``run_id`` cancels
        the previous heartbeat and starts fresh.
        """
        mode = _mode()
        if mode == "silent":
            return

        # Cancel any pre-existing state for this run_id (LangChain
        # doesn't normally re-emit start with the same UUID, but
        # defensive — leaked tasks would race the heartbeat).
        self._cancel_heartbeat(run_id)

        ag = _agent_tag(agent)
        effort = f", {reasoning_effort}" if reasoning_effort else ""
        head = _paint("🧠 ", _DIM, _CYAN)
        body = _paint(f"thinking ({model}{effort})…", _DIM)
        _emit(f"{_now()}  {head}{ag} {body}")

        # Record state for delta routing + heartbeat.
        self._think_state[run_id] = {
            "started":     time.perf_counter(),
            "agent":       agent,
            "model":       model,
            "delta_seen":  False,
            "last_delta":  time.perf_counter(),
            "on_new_line": True,  # next delta starts on its own line
            "heartbeat_task": None,
        }
        # Schedule the heartbeat. If we're not running inside an event
        # loop (sync ChatCodex._generate path, tests), skip it — the
        # heartbeat is a quality-of-life feature, not load-bearing.
        try:
            loop = asyncio.get_running_loop()
            self._think_state[run_id]["heartbeat_task"] = loop.create_task(
                self._heartbeat_loop(run_id),
            )
        except RuntimeError:
            # No running loop — skip heartbeat. Done line still fires.
            pass

    async def _heartbeat_loop(self, run_id: Any) -> None:
        """Per-call heartbeat. Emits "…still thinking (Xs elapsed)"
        every ``_HEARTBEAT_SECS`` *if* no reasoning delta has arrived
        in that window. Cancelled by ``thinking_finished``.
        """
        try:
            while True:
                await asyncio.sleep(self._HEARTBEAT_SECS)
                state = self._think_state.get(run_id)
                if state is None:
                    return  # call finished while we slept
                # If a delta arrived recently, the user already has
                # mid-call signal — skip this beat.
                quiet_for = time.perf_counter() - state["last_delta"]
                if quiet_for < self._HEARTBEAT_SECS:
                    continue
                elapsed = time.perf_counter() - state["started"]
                ag = _agent_tag(state["agent"])
                head = _paint("🧠 ", _DIM, _CYAN)
                body = _paint(
                    f"…still thinking ({elapsed:.0f}s elapsed)", _DIM,
                )
                # If a delta was streaming on a continuation line,
                # break to a fresh line BEFORE the heartbeat so we
                # don't concatenate it onto in-progress text. Mark
                # ``on_new_line`` so the next delta also starts fresh.
                if not state["on_new_line"]:
                    print("", file=sys.stderr, flush=True)
                state["on_new_line"] = True
                _emit(f"{_now()}  {head}{ag} {body}")
        except asyncio.CancelledError:
            return

    def thinking_delta(
        self,
        *,
        agent: str,
        run_id: Any,
        text: str,
    ) -> None:
        """Stream a chunk of the model's chain-of-thought summary to
        stderr. Called from inside the SSE parser (via the closure
        built in ``ChatCodex._build_reasoning_sink``) so deltas land
        live as the model produces them.

        Mode behaviour:
          - silent / compact: suppressed. Compact users get the
            header + heartbeat + done line, but not the live text.
          - verbose: dim cyan, written directly without ``_now()``
            timestamp so successive deltas concatenate into a
            running paragraph rather than fragmenting per chunk.
        """
        if not text:
            return
        if _mode() != "verbose":
            # Even when not rendered, mark delta-seen so the
            # heartbeat suppresses itself — we know the call is
            # alive even if we're not painting it.
            state = self._think_state.get(run_id)
            if state is not None:
                state["delta_seen"] = True
                state["last_delta"] = time.perf_counter()
            return

        state = self._think_state.get(run_id)
        if state is None:
            # Late delta after thinking_finished — drop silently.
            return
        state["delta_seen"] = True
        state["last_delta"] = time.perf_counter()

        # If we're starting a fresh continuation block (right after
        # the header or after a heartbeat broke the line), emit an
        # indent prefix so the streaming text aligns under the
        # header column.
        if state["on_new_line"]:
            indent = " " * 12  # matches the existing 💭 hanging indent
            sys.stderr.write(_paint(indent, _DIM, _CYAN))
            state["on_new_line"] = False

        # Write the raw delta. Trailing newlines split the stream
        # across multiple visual lines — preserve them but reset
        # on_new_line so the next delta re-indents.
        out = _paint(text, _DIM, _CYAN)
        sys.stderr.write(out)
        if text.endswith("\n"):
            state["on_new_line"] = True
        sys.stderr.flush()

    def thinking_finished(
        self,
        *,
        agent: str,
        run_id: Any,
        duration_ms: int,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        reasoning_tokens: int = 0,
        running_input: int = 0,
        peak_input: int = 0,
        error: str | None = None,
    ) -> None:
        """Close the streaming thinking line for ``run_id`` and emit
        the per-call "done" summary. Always cancels the heartbeat.

        Compact and verbose both get the done line; only the format
        differs slightly. Silent mode still cancels the heartbeat
        (it must, to avoid leaking asyncio tasks) but emits nothing.
        """
        # Cancel heartbeat first so it can't fire after the done
        # line is painted.
        self._cancel_heartbeat(run_id)
        state = self._think_state.pop(run_id, None)

        mode = _mode()
        if mode == "silent":
            return

        # If a delta was mid-line in verbose mode, flush a newline
        # so the done line lands cleanly.
        if state is not None and not state.get("on_new_line", True):
            print("", file=sys.stderr, flush=True)

        ag = _agent_tag(agent)
        rot = peak_input >= self._CONTEXT_WARN_INPUT_TOKENS

        if error:
            head = _paint("🧠 ", _BOLD, _RED)
            body = _paint(
                f"failed ({_fmt_ms(duration_ms)}, {error})", _RED,
            )
            _emit(f"{_now()}  {head}{ag} {body}")
            return

        tokens_part = (
            f"in={_fmt_tokens(input_tokens)} "
            f"out={_fmt_tokens(output_tokens)} "
            f"think={_fmt_tokens(reasoning_tokens)}"
        )
        if mode == "verbose":
            tokens_part += f" running_in={_fmt_tokens(running_input)}"

        if rot:
            head = _paint("🧠 ", _BOLD, _YELLOW)
            tail = _paint(
                f"done ({_fmt_ms(duration_ms)}, {tokens_part})  "
                f"⚠ context-rot at peak={_fmt_tokens(peak_input)}",
                _BOLD, _YELLOW,
            )
            _emit(f"{_now()}  {head}{ag} {tail}")
        else:
            head = _paint("🧠 ", _DIM, _CYAN)
            body = _paint(
                f"done ({_fmt_ms(duration_ms)}, {tokens_part})", _DIM,
            )
            _emit(f"{_now()}  {head}{ag} {body}")

    def _cancel_heartbeat(self, run_id: Any) -> None:
        """Cancel and forget the heartbeat task for ``run_id`` if any.

        Idempotent — safe to call when no task exists or after the
        task has already completed.
        """
        state = self._think_state.get(run_id)
        if state is None:
            return
        task = state.get("heartbeat_task")
        if task is None:
            return
        try:
            if not task.done():
                task.cancel()
        except Exception:  # noqa: BLE001
            pass

    # -------- Back-compat shim ----------
    #
    # ``llm_call`` was the old per-call stderr emitter. The
    # ``thinking_*`` pipeline supersedes it but call sites that
    # imported it directly (none currently, but defensive) get a
    # no-op so nothing breaks.

    def llm_call(self, **_kwargs: Any) -> None:
        """Deprecated — see ``thinking_started`` /
        ``thinking_finished``. Kept as a no-op for back-compat."""
        return

    # -------- Startup banner ----------

    def startup_banner(
        self,
        *,
        model_info: dict | None,
        log_dir: str | None,
        bench_ids: list[str] | None,
        budgets_text: str | None = None,
    ) -> None:
        """Print the startup banner once per process invocation.

        Shows provider/model/reasoning, all budgets and verbosity
        knobs, the **absolute** log directory, and a legend
        explaining which JSONL files populate live vs. at run end.

        ``silent`` mode falls back to a single one-liner so even
        the most muted runs still announce what they're running.
        """
        if self._banner_emitted:
            return
        self._banner_emitted = True

        mi = model_info or {}
        bench_count = len(bench_ids or [])
        provider = str(mi.get("provider") or "?")
        model = str(mi.get("model") or "?")
        mode = _mode()

        if mode == "silent":
            _emit(
                f"=== SwarmAttacker  {provider}/{model}  {mode}  "
                f"{bench_count} benches ==="
            )
            return

        # Determine terminal width so the rule line fits cleanly.
        try:
            cols = shutil.get_terminal_size((80, 24)).columns
        except Exception:  # noqa: BLE001
            cols = 80
        cols = max(60, min(cols, 100))

        # Title line: ═════ SwarmAttacker run ═════
        # Center the label within ``cols`` *visible* columns, then
        # apply ANSI colour AFTER the centring so the escape codes
        # don't break the math.
        label = " SwarmAttacker run "
        pad = max(0, cols - len(label))
        left = "═" * (pad // 2)
        right = "═" * (pad - pad // 2)
        title_line = left + label + right
        _emit(_paint(title_line, _BOLD, _CYAN))
        _emit(_paint("═" * cols, _CYAN))

        def kv(key: str, val: str) -> None:
            _emit(f"  {_paint(key, _BOLD)}{val}")

        # LLM block
        reff = mi.get("reasoning_effort") or "—"
        rsum = mi.get("reasoning_summary") or "—"
        kv("Provider:   ", f"{provider}   {_paint('Model:', _BOLD)} {model}")
        kv("Reasoning:  ", f"effort={reff}  summary={rsum}")

        # Budgets / verbosity from describe_config()
        cfg_block = (budgets_text or "").splitlines()
        if cfg_block:
            for ln in cfg_block:
                # describe_config() emits "Budgets:\n  k = v\n..." —
                # rewrap so each line is indented uniformly under the
                # banner column.
                _emit(f"  {ln}" if not ln.startswith(" ") else f"  {ln}")

        # Log dir + file legend
        if log_dir:
            kv("Log root:   ", str(log_dir))
            legend = [
                ("nodes.jsonl",          "1 line per node finish — quiet during long workers"),
                ("state_diffs.jsonl",    "1 line per node finish — full text of new msgs/findings + size deltas"),
                ("llm_calls.jsonl",      "1 line per LLM call end — token counts, populates live"),
                ("llm_requests.jsonl",   "1 line per LLM call start — full prompt sent, populates live"),
                ("terminal_events.jsonl","1 line per shell command — populates live"),
                ("final_state.json",    "final agent_state at run end"),
                ("summary.md",          "human digest at run end"),
            ]
            for i, (name, desc) in enumerate(legend):
                bullet = "└─" if i == len(legend) - 1 else "├─"
                _emit(_paint(
                    f"              {bullet} {name:<22s} ({desc})", _DIM,
                ))

        # Benches
        if bench_ids:
            preview = ", ".join(bench_ids[:8])
            if len(bench_ids) > 8:
                preview += f", … ({len(bench_ids)} total)"
            kv("Benches:    ", preview)

        _emit(_paint(rule, _CYAN))


_AGENT_TAG_WIDTH = 24  # fits owasp-input-validation (22) without truncation


def _agent_tag(agent: str | None) -> str:
    """Render an agent id as a left-padded fixed-width tag.

    Names longer than ``_AGENT_TAG_WIDTH`` are clipped with an ellipsis;
    shorter names are right-padded so the column after stays aligned.
    """
    name = agent or "?"
    if len(name) > _AGENT_TAG_WIDTH:
        return name[: _AGENT_TAG_WIDTH - 1] + "…"
    return f"{name:<{_AGENT_TAG_WIDTH}s}"


def _fmt_ms(ms: int | str) -> str:
    try:
        n = int(ms)
    except (TypeError, ValueError):
        return f"{ms}ms"
    if n < 1000:
        return f"{n}ms"
    if n < 60_000:
        return f"{n / 1000:.1f}s"
    return f"{n // 60_000}m{(n % 60_000) // 1000}s"


def _fmt_bytes(n: int | str) -> str:
    try:
        v = int(n)
    except (TypeError, ValueError):
        return f"{n}B"
    if v < 1024:
        return f"{v}B"
    if v < 1024 * 1024:
        return f"{v / 1024:.1f}KB"
    return f"{v / (1024 * 1024):.1f}MB"


def _fmt_tokens(n: int) -> str:
    """Format a token count as ``Xk`` or ``X.Xk`` past 1000.

    Below 1000 we keep the raw integer because per-call output_tokens is
    often in the low hundreds and the ``k`` suffix would round those
    to ``0k`` and lose the signal.
    """
    try:
        v = int(n)
    except (TypeError, ValueError):
        return str(n)
    if v < 1_000:
        return str(v)
    if v < 10_000:
        return f"{v / 1_000:.1f}k"
    return f"{v // 1_000}k"


# Module-level singleton. Importers do ``from src.observability.live import LIVE``.
LIVE = _Live()


# ─────────────────────── stdlib logging integration ───────────────────────


class HttpxQuietFilter:
    """Drop ``httpx`` INFO records unless ``config.verbosity.show_http``.

    Installed once at runner start-up. The library logs every LLM call at
    INFO level (``HTTP Request: POST chatgpt.com/...``); without this filter
    those lines flood the terminal in compact mode. Disk logs are unaffected
    — we don't write a separate httpx log file.
    """

    def filter(self, record) -> bool:  # noqa: D401 — logging.Filter API
        try:
            from src.graph import config
            show = bool(config.verbosity.show_http)
        except Exception:
            show = False
        if show:
            return True
        # Hide httpx INFO; let WARNING+ through so real errors still surface.
        return record.levelno >= 30  # WARNING and above


class LiveLogHandler(logging.Handler):
    """Stdlib logging handler that reformats records through :data:`LIVE`.

    Installed in compact/silent mode so warnings and errors appear in the
    same colored ``⚠`` / red format as the rest of the live stream
    instead of the raw ``2026-05-03 21:19:11,401 WARNING node.recon: …``
    timestamped lines that ``logging.basicConfig`` produces. Records
    below WARNING are dropped (their content is already surfaced by
    LIVE itself in compact mode); errors are routed through
    ``LIVE.runner_message`` with ``level="error"``.

    Verbose mode does NOT install this — the runner keeps
    ``logging.basicConfig`` so the full timestamped log stream is
    available for deep debugging.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
        except Exception:  # noqa: BLE001 — never let a log call crash a run
            try:
                msg = self.format(record)
            except Exception:
                return
        # Tag the source if it's a recognizable node logger so the user
        # can tell whether a warning came from the planner, a worker,
        # the LLM provider, etc.
        prefix = ""
        if record.name.startswith("node."):
            prefix = f"[{record.name[5:]}] "
        elif record.name.startswith("src."):
            prefix = f"[{record.name[4:]}] "
        text = f"{prefix}{msg}".strip()
        if record.levelno >= logging.ERROR:
            # Errors go through the same ⚠ path as warnings so they get
            # the timestamp + colored prefix; the "error:" prefix keeps
            # them distinguishable in the stream.
            LIVE.warning(f"error: {text}")
        elif record.levelno >= logging.WARNING:
            LIVE.warning(text)
        # INFO/DEBUG: dropped intentionally.
