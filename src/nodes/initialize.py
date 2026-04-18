"""Initialize node — sets up the run with target info and defaults.

Also tears down any leftover tmux session from a previous run so the recon
agent's first ``tmux new-session`` call can't collide with a stale session
(the source of the user-visible ``duplicate session: swarmattacker`` error).
"""

import logging
import re

from langchain_core.messages import AIMessage, HumanMessage

from src.state import SwarmGraphState
from src.tools.terminal import cleanup_session

logger = logging.getLogger(__name__)


URL_PATTERN = re.compile(r"https?://\S+|(?:[a-zA-Z0-9][\w-]*\.)+[a-zA-Z]{2,}(?:/\S*)?")
TRAILING_JUNK = re.compile(r"[.,;:!?'\"\)\]\}>]+$")


def _clean_url(url: str) -> str:
    """Strip trailing punctuation that regex often pulls in."""
    url = TRAILING_JUNK.sub("", url)
    if not url.startswith("http"):
        url = "http://" + url
    return url


def _extract_target_from_messages(state: SwarmGraphState) -> str | None:
    """Find a URL in the newest HumanMessage.

    Skips our own status messages ("Starting penetration test against: ...")
    and report messages so that reruns inside the same thread still pick
    up the freshest user-supplied URL.
    """
    for msg in reversed(state.get("messages", []) or []):
        if not isinstance(msg, HumanMessage):
            continue
        raw = msg.content
        if isinstance(raw, str):
            content = raw
        elif isinstance(raw, list):
            # LangGraph Studio sends content as a list of blocks like
            # [{"type": "text", "text": "..."}]. Concatenate all text parts.
            parts = []
            for block in raw:
                if isinstance(block, dict):
                    parts.append(block.get("text") or block.get("content") or "")
                elif isinstance(block, str):
                    parts.append(block)
            content = " ".join(p for p in parts if p)
        else:
            content = ""
        if not content:
            continue
        if content.startswith("Starting penetration test"):
            continue
        if content.startswith("## SwarmAttacker"):
            continue
        match = URL_PATTERN.search(content)
        if match:
            return _clean_url(match.group(0))
    return None


async def initialize_node(state: SwarmGraphState) -> dict:
    """Set up the run: clean tmux state, validate target, set defaults.

    Always prefers the newest user-provided URL over any stale target_url
    left in the thread state from a previous run.
    """
    # Wipe any leftover tmux session from a prior run before any agent
    # calls _ensure_session(). Without this, the next agent can collide
    # with a stale session created by a previous run inside the same
    # `langgraph dev` process and fail with `duplicate session`.
    try:
        cleanup_session()
    except Exception as e:  # noqa: BLE001 — never block the graph on cleanup
        logger.warning(f"tmux cleanup failed (non-fatal): {e}")

    target_url = _extract_target_from_messages(state) or state.get("target_url")

    if not target_url:
        return {
            "messages": [
                AIMessage(
                    content=(
                        "ERROR: No target URL provided. Please paste a URL "
                        "into the chat."
                    )
                )
            ],
        }

    return {
        "target_url": target_url,
        "target_scope": state.get("target_scope") or target_url,
        "waf_detected": False,
        "stealth_level": 0,
        "tier2_activated": False,
        "messages": [
            AIMessage(content=f"Starting penetration test against: {target_url}")
        ],
    }
