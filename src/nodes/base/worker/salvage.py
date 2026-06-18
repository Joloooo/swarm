# Refusal-path primitive salvage.
# The Codex classifier fires most often right when a worker received its most
# valuable output (dumped table, `id` line, /etc/passwd) — so a refused worker
# can lose a PROVEN primitive. This scan mints a HIGH Finding from received
# ToolMessage output only (negation-guarded), markers strongest-first.

from __future__ import annotations

from langchain_core.messages import ToolMessage

from src.state import Finding, Severity


_REFUSAL_PRIMITIVE_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("root:x:0:0", "file_read", "lfi"),        # /etc/passwd contents
    ("uid=", "rce", "rce"),                     # `id` command output
    ("gid=", "rce", "rce"),
    ("information_schema", "sqli_read", "sqli"),
    ("group_concat", "sqli_read", "sqli"),
    ("@@version", "sqli_read", "sqli"),
    ("database()", "sqli_read", "sqli"),
    ("union select", "sqli_read", "sqli"),
    ("www-data", "rce", "rce"),
)
_REFUSAL_NEGATION_CUES: tuple[str, ...] = (
    "no ", "not ", "n't ", "without ", "none", "zero ", "never ",
)


def _refusal_marker_is_real(text_lower: str, marker: str) -> bool:
    # True if marker occurs at least once without a negation cue in the ~32 chars
    # before it.
    start = 0
    while True:
        idx = text_lower.find(marker, start)
        if idx < 0:
            return False
        window = text_lower[max(0, idx - 32):idx]
        if not any(cue in window for cue in _REFUSAL_NEGATION_CUES):
            return True
        start = idx + len(marker)


def _salvage_primitive_from_trace(
    partial_messages: list, agent_id: str,
) -> Finding | None:
    # Scan a refused worker's RECEIVED tool output for a proven primitive. Returns
    # a HIGH Finding tagged with the matching primitive, or None. The worker's own
    # request text is never scanned, so a typed payload can't self-trigger.
    tool_parts: list[str] = []
    for m in partial_messages:
        if not isinstance(m, ToolMessage):
            continue
        c = getattr(m, "content", None)
        if isinstance(c, str):
            tool_parts.append(c)
        elif isinstance(c, list):
            for block in c:
                if isinstance(block, dict):
                    tool_parts.append(str(block.get("text") or ""))
    haystack = "\n".join(tool_parts)
    if not haystack:
        return None
    low = haystack.lower()
    for marker, primitive_tag, category in _REFUSAL_PRIMITIVE_MARKERS:
        if marker in low and _refusal_marker_is_real(low, marker):
            idx = low.find(marker)
            excerpt = haystack[max(0, idx - 240):idx + len(marker) + 240]
            return Finding(
                title=(
                    "[salvaged from refused worker] proven "
                    f"{primitive_tag} primitive in tool output before "
                    f"refusal ({marker})"
                )[:240],
                severity=Severity.HIGH,
                category=category,
                description=(
                    "The worker hit a Codex policy refusal mid-run, but "
                    "its partial tool trace already contained received "
                    "output proving a working primitive. Refusals land "
                    "on exactly this high-value output; this finding "
                    "preserves the proven capability so it can be driven "
                    "to the objective on a later turn instead of lost."
                ),
                evidence=excerpt[:2400],
                agent_id=agent_id,
                url="",
                primitive=primitive_tag,
            )
    return None
