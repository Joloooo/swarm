"""Web search node — Tavily search + crawler-fetched content + LLM synthesis.

Flow:
1. Tavily returns candidate URLs and short snippets for the query.
2. The :func:`src.tools.crawler.crawl_many` tool fetches each URL in
   parallel with an HTTP-first, Playwright-fallback strategy so we
   actually have the full page HTML, not just Tavily's teaser snippet.
3. The LLM is given the enriched context (snippet + crawled content,
   truncated) and produces a cited, grounded answer.

The answer and the used sources are posted back as an AIMessage so
the supervisor planner can read them like any other worker output.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage
from langchain_tavily import TavilySearch
from pydantic import BaseModel, Field

from src.graph import budgets
from src.llm.provider import LLMConfig, get_llm
from src.nodes.base import BaseNode
from src.state import SwarmGraphState
from src.tools.crawler import crawl_many

# How much crawled HTML/text to include per source in the LLM context.
# Tavily snippets are ~300 chars; adding ~3k chars of real page content
# gives the model enough to ground the answer without blowing the
# context window when Tavily returns 10 URLs. Centralized in src/graph.py.
_MAX_CRAWLED_CHARS = budgets.web_search_max_crawled_chars


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


class WebSearchNode(BaseNode):
    """Run a Tavily search, crawl each hit, then synthesize a cited answer."""

    async def execute(self, state: SwarmGraphState) -> dict[str, Any]:
        query = _extract_query(state)
        if not query:
            return {
                "messages": [
                    AIMessage(content="[Web Search] No query provided; skipping.")
                ]
            }

        self.log.info("🔍 Web search node processing query: %s", query)

        try:
            # Step 1: Tavily search.
            tavily_tool = TavilySearch(
                max_results=10,
                search_depth="basic",
                include_answer=False,
                include_raw_content=False,
            )
            tavily_result = tavily_tool.invoke({"query": query})
            raw_results = (
                tavily_result.get("results", [])
                if isinstance(tavily_result, dict)
                else []
            )
            self.log.info("Tavily returned %d results", len(raw_results))

            # Step 2: Crawl each result URL in parallel (HTTP, then Playwright).
            urls = [r.get("url") for r in raw_results if r.get("url")]
            crawl_batch = await crawl_many(urls) if urls else None
            crawled_by_url: dict[str, str] = {}
            if crawl_batch is not None:
                for cr in crawl_batch.results:
                    if cr.success and cr.content:
                        crawled_by_url[cr.url] = cr.content
                self.log.info(
                    "Crawled %d/%d URLs (http=%d, playwright=%d)",
                    crawl_batch.stats.total_success,
                    len(urls),
                    crawl_batch.stats.http_success,
                    crawl_batch.stats.playwright_success,
                )

            # Step 3: Build enriched context for the LLM.
            context = f"User Query: {query}\n\nSearch Results:\n"
            for idx, result in enumerate(raw_results):
                url = result.get("url", "No URL")
                context += f"\n[{idx}] Title: {result.get('title', 'No title')}\n"
                context += f"URL: {url}\n"
                snippet = (result.get("content") or "No content")[:300]
                context += f"Snippet: {snippet}\n"
                page_text = crawled_by_url.get(url)
                if page_text:
                    context += (
                        f"Page Content (truncated): "
                        f"{page_text[:_MAX_CRAWLED_CHARS]}\n"
                    )
            context += (
                "\n\nIMPORTANT: Answer ONLY based on the search results and page "
                "content provided above.\n"
                "DO NOT use your own knowledge or training data.\n"
                "If the results don't contain relevant information, respond with: "
                '"The search results don\'t contain information about this topic."\n\n'
                "Provide a comprehensive answer using ONLY information from the "
                "results above.\n"
                "You MUST cite at least one source index in your answer. If no "
                "sources are relevant, return an empty sources_used list."
            )

            # Step 4: Structured LLM analysis.
            llm = get_llm(LLMConfig())
            structured_llm = llm.with_structured_output(WebSearchAnalysis)
            analysis: WebSearchAnalysis = await structured_llm.ainvoke(context)
            self.log.info("LLM used %d sources", len(analysis.sources_used))

            # Step 5: Keep only the cited sources.
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
            self.log.info("Web search complete, has_answer=%s", has_answer)

            if has_answer:
                body = f"[Web Search] {analysis.answer}\n\nSources:\n" + "\n".join(
                    f"- {s['title']} — {s['url']}" for s in sources_list
                )
            else:
                body = "[Web Search] No relevant information found from web search."

            return {"messages": [AIMessage(content=body)]}

        except Exception as e:
            self.log.exception("Web search error: %s", e)
            return {
                "messages": [
                    AIMessage(content=f"[Web Search] Web search failed: {e}")
                ]
            }


web_search_node = WebSearchNode()
