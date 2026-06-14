"""Web search node — Codex-native web search + curated references.

Flow:
1. Detect the vuln class (explicit state, else inferred from the query) and
   deep-fetch the curated authoritative references for it (HackTricks mirror /
   PayloadsAllTheThings raw markdown) — the payload-rich pages.
2. Hand the query (plus that curated markdown as context) to the Codex hosted
   ``web_search`` tool. The MODEL issues its own keyword searches, reads the
   result pages, and writes a cited summary in one call.
3. Post the synthesized answer + cited sources back as an AIMessage so the
   supervisor planner reads it like any other worker output.

This replaces the old Tavily pipeline (search → crawl N URLs → separate
synthesis LLM). Tavily did literal keyword search, so the planner's long
defensive-framing query returned 0 results, and product/version queries like
"Apache 2.4.54" (no vuln-class keyword) had neither a curated source nor a
usable Tavily hit — 72% of crawls came back empty. The Codex model rewrites
the query into sharp search terms itself, so those same queries now return
real sources. See :mod:`src.tools.web_recon.codex_search`.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from src.graph import config
from src.llm.callbacks import record_external_usage
from src.nodes.base import BaseNode
from src.nodes.base.flag_watcher import (
    SiblingCapturedSignal,
    get_captured_flag,
    is_captured,
)
from src.refusals.detect import looks_like_refusal
from src.refusals.vocabulary import filter_text
from src.state import SwarmGraphState
from src.tools.crawler import crawl_many
from src.tools.web_recon.codex_search import codex_web_search
from src.tools.web_recon.extract import extract_markdown
from src.tools.web_recon.sources import infer_class, sources_for

# Curated authoritative sources (HackTricks mirror, PayloadsAllTheThings leaf
# files) arrive as clean markdown (extractor passthrough), so the whole
# technique section fits: the HackTricks SSTI page is ~50k chars and its
# Django/blind payloads sit past a small cap. Tunable via env.
import os

_CURATED_MAX_CHARS = int(os.getenv("SWARM_WEB_CURATED_MAX_CHARS", "30000"))

# How often the in-flight web search polls the process-global capture flag
# while its (uncancellable, hosted) Codex call is running. See
# ``WebSearchNode._run_until_capture`` for why this node needs its own
# stop-on-capture path instead of the FlagWatcherCallback the executor
# workers get.
_CAPTURE_POLL_INTERVAL_S = float(os.getenv("SWARM_WEB_CAPTURE_POLL_S", "2"))


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
    """Fetch curated references, then let Codex web_search find + synthesize."""

    async def _fetch_curated(self, curated_urls: list[str]) -> list[dict[str, str]]:
        """Deep-fetch the curated raw-markdown URLs that crawled successfully."""
        out: list[dict[str, str]] = []
        if not curated_urls:
            return out
        cur_batch = await crawl_many(curated_urls)
        cur_by_url = {
            cr.url: cr.content
            for cr in cur_batch.results if cr.success and cr.content
        }
        for url in curated_urls:
            raw = cur_by_url.get(url)
            if not raw:
                continue
            md = extract_markdown(raw)[:_CURATED_MAX_CHARS]
            out.append({"url": url, "content": md})
        self.log.info("Crawled %d/%d curated sources", len(out), len(curated_urls))
        return out

    async def _run_codex_search(self, query: str, extra_context: str):
        """Run Codex web_search on the configured synth model, with a one-shot
        fallback to the flagship slug if that model rejects the tool."""
        primary_model = getattr(
            config.budgets, "web_search_synth_model", "gpt-5.5"
        )
        effort = getattr(
            config.budgets, "web_search_synth_reasoning_effort", "low"
        )
        res = await codex_web_search(
            query, extra_context=extra_context,
            model=primary_model, reasoning_effort=effort,
        )
        # If the cheaper synth model can't run the hosted web_search tool
        # (unsupported tool/model → a 400 from the backend), retry once on the
        # flagship slug, which we verified does support it.
        err = (res.error or "").lower()
        tool_problem = res.answer == "" and not res.hard_refused and (
            "tool" in err or "400" in err or "unsupported" in err
        )
        if tool_problem:
            flagship = getattr(config.budgets, "model", "gpt-5.5")
            if flagship != primary_model:
                self.log.warning(
                    "web_search on %s failed (%s); retrying on %s",
                    primary_model, res.error, flagship,
                )
                res = await codex_web_search(
                    query, extra_context=extra_context,
                    model=flagship, reasoning_effort=effort,
                )
        return res

    async def _run_until_capture(self, coro):
        """Run ``coro`` but abort it the moment a sibling captures the flag.

        ``web_search`` is the one fan-out branch with no LangChain
        ``FlagWatcherCallback`` — its hosted Codex ``web_search`` call
        bypasses the callback path entirely (see ``record_external_usage``
        note in :meth:`execute`). Without this, when the planner fans
        ``web_search`` out ALONGSIDE executor workers and one of them
        captures the flag, this node keeps running its full 1–2 min search.
        Because the summarizer is a fan-in barrier, that delays the
        ``route_after_summarizer → END`` transition by the whole search
        duration — the run sits idle on a flag it already has.

        Polling the process-global ``is_captured()`` and cancelling the
        in-flight task gives ``web_search`` the same stop-on-capture
        behaviour the executor workers get for free. Raises
        :class:`SiblingCapturedSignal` on capture so :meth:`execute`'s
        handler returns an empty update (no message), letting the barrier
        complete fast.
        """
        task = asyncio.ensure_future(coro)
        while True:
            done, _ = await asyncio.wait(
                {task}, timeout=_CAPTURE_POLL_INTERVAL_S
            )
            if task in done:
                return task.result()
            if is_captured():
                task.cancel()
                try:
                    await task
                except BaseException:  # noqa: BLE001 — cancellation cleanup
                    pass
                raise SiblingCapturedSignal(
                    captured_flag=get_captured_flag(), agent_id="web_search",
                )

    async def execute(self, state: SwarmGraphState) -> dict[str, Any]:
        # Stop-on-capture, entry path: a sibling worker may have captured
        # the flag between this node being dispatched and actually starting.
        # ``BaseNode.__call__``'s ``state.captured_flag`` guard does NOT
        # cover this — that snapshot is frozen at wave-dispatch time, so a
        # same-wave capture is invisible to it. The module-global is live.
        if is_captured():
            self.log.info(
                "web_search skipped — flag already captured by a sibling "
                "worker; not starting a search the run will discard",
            )
            return {}

        query = _extract_query(state)
        if not query:
            return {"messages": [
                AIMessage(content="[Web Search] No query provided; skipping.")
            ]}

        self.log.info("🔍 Web search (codex) processing query: %s", query)

        # Vuln class drives the curated-reference prepend. Taken from explicit
        # state if the planner set it, else inferred from the query text.
        vuln_class = (
            state.get("vuln_class")
            or state.get("attack_type")
            or infer_class(query)
        )
        curated_urls = sources_for(vuln_class) if vuln_class else []
        self.log.info(
            "Web search vuln_class=%s curated=%d", vuln_class, len(curated_urls),
        )

        try:
            curated_sources = await self._run_until_capture(
                self._fetch_curated(curated_urls)
            )

            # Curated markdown is passed to the model as extra context; the
            # query + context both go through the lossless vocab filter the
            # worker refusal ladder uses, to de-risk the call before it ships.
            extra_context = "\n\n".join(
                f"[authoritative] {s['url']}\n{s['content']}"
                for s in curated_sources
            )
            safe_query, _ = filter_text(query)
            safe_context, _ = filter_text(extra_context) if extra_context else ("", 0)

            result = await self._run_until_capture(
                self._run_codex_search(safe_query, safe_context)
            )
            self.log.info(
                "Codex web_search: searches=%d citations=%d refused=%s err=%s",
                result.num_searches, len(result.citations),
                result.hard_refused, result.error,
            )
            # Account the hosted-search tokens. This Codex call bypasses the
            # LangChain callback, so without this the web_search node's cost is
            # invisible (no NODE_TOTALS entry → blank ▸ web_search chip). No-op
            # when the plan didn't report usage.
            record_external_usage(
                result.usage,
                agent_id="web_search",
                node="web_search",
                model=result.model,
            )

            answer = result.answer
            if answer and not result.hard_refused and not looks_like_refusal(answer):
                # Cite the model's URLs; if it cited none, fall back to the
                # curated source URLs so the planner still gets attribution.
                cited = result.citations or [
                    (f"[authoritative] {s['url']}", s["url"])
                    for s in curated_sources
                ]
                body = f"[Web Search] {answer}"
                if cited:
                    body += "\n\nSources:\n" + "\n".join(
                        f"- {t} — {u}" for t, u in cited
                    )
                return {"messages": [AIMessage(content=body)]}

            # Fallback: the model refused, errored, or returned nothing. If we
            # have curated raw markdown (already payload-rich), stitch it so the
            # planner still gets ungated content instead of an empty result.
            self.log.warning(
                "Codex web_search unusable (refused=%s err=%s); falling back "
                "to curated raw-source stitch.",
                result.hard_refused, result.error,
            )
            if curated_sources:
                stitched = "\n\n".join(
                    f"[{i}] {s['url']}\n{s['content'][:1500]}"
                    for i, s in enumerate(curated_sources)
                )
                body = (
                    "[Web Search] (Codex web_search unavailable/refused; raw "
                    f"authoritative sources follow)\n\nQuery: {query}\n\n{stitched}"
                )
                return {"messages": [AIMessage(content=body)]}

            note = result.error or "no results"
            return {"messages": [AIMessage(content=(
                f"[Web Search] No sources could be retrieved for this query ({note})."
            ))]}

        except SiblingCapturedSignal as sig:
            # A sibling captured the flag while this search was in flight.
            # Exit with an empty update so the summarizer barrier completes
            # immediately and ``route_after_summarizer`` can route to END.
            # No message: the run is over, nothing here would be consumed.
            self.log.info(
                "web_search stopping early — flag captured by a sibling "
                "worker (%s); cancelled in-flight search to unblock fan-in",
                sig.captured_flag,
            )
            return {}

        except Exception as e:
            self.log.exception("Web search error: %s", e)
            return {"messages": [
                AIMessage(content=f"[Web Search] Web search failed: {e}")
            ]}


web_search_node = WebSearchNode()
