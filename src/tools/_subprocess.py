"""Shared subprocess helper for typed CLI-tool wrappers.

Used by sqlmap, sslscan, testssl, gobuster, whatweb, nikto, hydra and any
other typed wrapper around a command-line binary. Centralizes:

- Async ``asyncio.create_subprocess_exec`` invocation
- Combined stdout+stderr capture
- Per-call timeout with graceful termination
- Output truncation so very chatty tools don't blow up the LLM context
- Friendly ``[NOT INSTALLED]`` message when the binary isn't on PATH

This is intentionally simpler than the tmux-backed ``run_command`` in
``terminal.py``. tmux gives session-isolated shells with shared state across
calls — the right fit when an agent wants a working REPL. Typed wrappers
don't need session state: each invocation is one self-contained command,
and the wrapper enforces argument shape so the LLM can't malform flags.
"""

from __future__ import annotations

import asyncio
import shlex

# Defaults — individual tools override when they have stronger needs
# (e.g. testssl is slow, gobuster wordlists are large).
DEFAULT_TIMEOUT_S = 300       # 5 min
DEFAULT_OUTPUT_CAP_BYTES = 8000  # cap returned text so the LLM context survives


async def run_subprocess(
    cmd: list[str],
    *,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    output_cap_bytes: int = DEFAULT_OUTPUT_CAP_BYTES,
    stdin_data: bytes | None = None,
) -> str:
    """Run *cmd* as a subprocess and return combined stdout+stderr.

    Args:
        cmd: Argv list (no shell). First element is the binary name.
        timeout_s: Seconds before the subprocess is terminated. The
            wrapper returns a ``[TIMEOUT ...]`` string when the deadline
            hits — never raises.
        output_cap_bytes: Maximum size of returned text. Larger output
            is truncated with a marker so the LLM sees that something
            was dropped.
        stdin_data: Optional bytes to feed the subprocess on stdin.

    Returns:
        The subprocess's combined stdout+stderr decoded as UTF-8 (errors
        replaced), possibly truncated. On ``FileNotFoundError`` returns
        a ``[NOT INSTALLED]`` marker so the caller can decide whether to
        fall back. Never raises.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        )
    except FileNotFoundError:
        return (
            f"[NOT INSTALLED] {cmd[0]!r} is not available on PATH in this "
            "environment. Either install it, or fall back to ``run_command`` "
            "with an alternative tool."
        )
    except Exception as exc:  # noqa: BLE001 — return string, never crash
        return f"[ERROR] {cmd[0]!r} failed to start: {exc}"

    try:
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=stdin_data),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        return (
            f"[TIMEOUT after {timeout_s}s]\n"
            f"command: {shlex.join(cmd)}\n"
            "Re-run with a tighter scope (smaller wordlist, fewer payloads, "
            "narrower port range) instead of just retrying."
        )

    text = stdout.decode("utf-8", errors="replace") if stdout else ""
    if len(text) > output_cap_bytes:
        original = len(text)
        text = (
            text[:output_cap_bytes]
            + f"\n... [truncated; original {original} bytes]"
        )
    return text
