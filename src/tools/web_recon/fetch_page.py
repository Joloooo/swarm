"""Typed page-fetch tool — wraps :func:`src.tools.crawler.crawl` as
the recon agent's first-look tool.

For HTTP targets the homepage almost always reveals the things port
scans miss: form actions, API endpoints, JS bundle URLs that hint
at routes, framework name. Calling ``fetch_page`` early prevents
the planner from picking attack skills based on incomplete recon.
"""

from __future__ import annotations

from langchain_core.tools import tool

from src.tools.crawler import crawl
from src.tools.shell._common import truncate_output


@tool
async def fetch_page(reasoning: str, url: str) -> str:
    """Fetch a single web page and return its HTML body.

    Use this as the FIRST recon step on any web target. The HTML
    almost always reveals form actions, API endpoints, JS calls,
    and framework hints that port scans miss. For an SPA, the JS
    bundle references the API routes you'll attack.

    Tries plain HTTP first, falls back to a real Playwright browser
    if the page is JS-rendered. Follows redirects and language-path
    variations, so a single call covers most reachable surfaces.

    Args:
        reasoning: Required. State what you expect to learn from
            the page (form endpoints, framework, hidden inputs)
            and how it'll shape the next probe.
        url: Absolute URL to fetch.

    Returns:
        The page HTML, prefixed with a small status header showing
        the fetch method and the final (post-redirect) URL.
        Truncated for context if the body is very large.
    """
    result = await crawl(url)
    body = (result.content or "").strip()

    head_lines = [
        f"[fetch_page] url={url}",
        f"[fetch_page] success={result.success} method={result.method}",
    ]
    if result.final_url and result.final_url != url:
        head_lines.append(f"[fetch_page] final_url={result.final_url}")
    if result.redirect_type:
        head_lines.append(f"[fetch_page] redirect_type={result.redirect_type}")
    if result.error:
        head_lines.append(f"[fetch_page] error={result.error}")
    header = "\n".join(head_lines)

    if not body:
        return f"{header}\n[fetch_page] empty body"

    return truncate_output(f"{header}\n\n{body}")
