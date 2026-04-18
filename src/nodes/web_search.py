"""Web search node — Tavily-backed search with LLM-synthesized answer.

The node runs a Tavily web search for a query (taken from state or the
latest human message), then asks the LLM to produce a grounded answer
that cites only the returned sources. The answer and the used sources
are posted back as an AIMessage so the supervisor planner can read them
like any other worker output.
"""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage
from langchain_tavily import TavilySearch
from pydantic import BaseModel, Field

from src.llm.provider import LLMConfig, get_llm
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)


class WebSearchAnalysis(BaseModel):
    """Structured output for an analyzed web-search result set."""

    answer: str = Field(
        description="Comprehensive answer based on the search results."
    )
    sources_used: list[int] = Field(
        description="Indices of sources used in the answer (0-based)."
    )


def _extract_query(state: SwarmGraphState) -> str | None:
    """Pick the query the search should run.

    Priority: explicit ``search_query`` field, then ``query``, then the
    last HumanMessage content.
    """
    query = state.get("search_query") or state.get("query")
    if query:
        return str(query)
    for msg in reversed(state.get("messages", []) or []):
        if isinstance(msg, HumanMessage):
            content = msg.content
            if isinstance(content, str) and content.strip():
                return content
    return None


async def web_search_node(state: SwarmGraphState) -> dict[str, Any]:
    """Run a Tavily search and have the LLM synthesize a cited answer."""
    query = _extract_query(state)
    if not query:
        return {
            "messages": [
                AIMessage(content="[Web Search] No query provided; skipping.")
            ]
        }

    logger.info("🔍 Web search node processing query: %s", query)

    try:
        # Step 1: Tavily search.
        tavily_tool = TavilySearch(
            max_results=10,
            search_depth="basic",
            include_answer=False,
            include_raw_content=False,
        )
        tavily_result = tavily_tool.invoke({"query": query})
        raw_results = tavily_result.get("results", []) if isinstance(tavily_result, dict) else []
        logger.info("Tavily returned %d results", len(raw_results))

        # Step 2: Compact enumerated context for the LLM.
        context = f"User Query: {query}\n\nSearch Results:\n"
        for idx, result in enumerate(raw_results):
            context += f"\n[{idx}] Title: {result.get('title', 'No title')}\n"
            context += f"URL: {result.get('url', 'No URL')}\n"
            context += f"Content: {result.get('content', 'No content')[:100]}...\n"
        context += (
            "\n\nIMPORTANT: Answer ONLY based on the search results provided above.\n"
            "DO NOT use your own knowledge or training data.\n"
            "If the search results don't contain relevant information, respond with: "
            '"The search results don\'t contain information about this topic."\n\n'
            "Provide a comprehensive answer using ONLY information from the search results.\n"
            "You MUST cite at least one source index in your answer. If no sources are "
            "relevant, return an empty sources_used list."
        )

        # Step 3: Structured LLM analysis.
        llm = get_llm(LLMConfig())
        structured_llm = llm.with_structured_output(WebSearchAnalysis)
        analysis: WebSearchAnalysis = await structured_llm.ainvoke(context)
        logger.info("LLM used %d sources", len(analysis.sources_used))

        # Step 4: Keep only the cited sources.
        sources_list: list[dict[str, Any]] = []
        for idx in analysis.sources_used:
            if 0 <= idx < len(raw_results):
                result = raw_results[idx]
                sources_list.append(
                    {
                        "url": result.get("url"),
                        "title": result.get("title"),
                        "content": (result.get("content") or "")[:300],
                        "score": result.get("score"),
                    }
                )

        has_answer = bool(analysis.answer and sources_list)
        logger.info("Web search complete, has_answer=%s", has_answer)

        if has_answer:
            body = f"[Web Search] {analysis.answer}\n\nSources:\n" + "\n".join(
                f"- {s['title']} — {s['url']}" for s in sources_list
            )
        else:
            body = "[Web Search] No relevant information found from web search."

        return {"messages": [AIMessage(content=body)]}

    except Exception as e:
        logger.exception("Web search error: %s", e)
        return {
            "messages": [
                AIMessage(content=f"[Web Search] Web search failed: {e}")
            ]
        }
