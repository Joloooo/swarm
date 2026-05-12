"""Render a single Finding as a markdown block.

One small file because that's the entire findings-section rendering
contract. The findings-table consumer in ``builder.py`` calls
:func:`_render_finding_md` once per finding (severity-sorted) and joins
the results.
"""

from __future__ import annotations

from typing import Any

from src.observability.summary._helpers import (
    _details,
    _ev_field,
    _md_code_block,
    _severity_str,
)


def _render_finding_md(f: Any, depth: int = 3) -> str:
    """Render one finding as a markdown block with collapsed evidence."""
    sev = _severity_str(f).upper()
    title = str(_ev_field(f, "title", "(no title)"))
    cat = str(_ev_field(f, "category", "?"))
    agent = str(_ev_field(f, "agent_id", "?"))
    url = str(_ev_field(f, "url", ""))
    evidence = str(_ev_field(f, "evidence", ""))
    description = str(_ev_field(f, "description", ""))
    cwe = str(_ev_field(f, "cwe", ""))
    reproduced = bool(_ev_field(f, "reproduced", False))

    h = "#" * max(1, min(depth, 6))
    parts = [f"{h} [{sev}] {title}"]
    parts.append("")
    bullets = [
        f"- **Agent**: `{agent}`",
        f"- **Category**: `{cat}`",
    ]
    if url:
        bullets.append(f"- **URL**: `{url}`")
    if cwe:
        bullets.append(f"- **CWE**: `{cwe}`")
    bullets.append(f"- **Reproduced**: {'yes' if reproduced else 'no'}")
    parts.extend(bullets)
    if description:
        parts.append("")
        parts.append(f"> {description}")
    if evidence:
        parts.append("")
        parts.append(_details("Evidence", _md_code_block(evidence)))
    parts.append("")
    return "\n".join(parts)
