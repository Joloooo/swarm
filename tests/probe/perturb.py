"""Perturbations — declared changes applied to the INPUT before replay.

Honest modes change STATE or CONFIG and let the REAL ``src/`` builder re-render
the prompt (used by Level-2 node replays, where a captured state exists). The
crude text-splice mode edits message text directly — it can test a string the
real builder would never emit, so it is THROWAWAY ONLY and never the basis for a
kept result (SKILL §3). Reports flag any crude result loudly.

This module changes inputs; it never builds a prompt.
"""

from __future__ import annotations

import copy

from langchain_core.messages import BaseMessage


def crude_splice(
    messages: list[BaseMessage], find: str, replace: str
) -> list[BaseMessage]:
    """THROWAWAY: find/replace text inside message contents and return a new list.

    Used only for quick "what if the prompt literally said X" exploration. The
    honest path is :func:`apply_state_patch` + the real node builder.
    """
    if not find:
        return list(messages)
    out: list[BaseMessage] = []
    for m in messages:
        content = m.content
        if isinstance(content, str) and find in content:
            m = m.model_copy(update={"content": content.replace(find, replace)})
        out.append(m)
    return out


def apply_state_patch(state: dict, patch: dict) -> dict:
    """HONEST (Level-2): deep-merge ``patch`` into a copy of the captured state.

    The patched state is then fed to the REAL node, whose REAL builder renders
    the prompt — so what is tested is the exact code path that would ship. No
    prompt text is constructed here.
    """
    new = copy.deepcopy(state)
    _deep_merge(new, patch or {})
    return new


def _deep_merge(dst: dict, src: dict) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = v
