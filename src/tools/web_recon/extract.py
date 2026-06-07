"""HTML → clean markdown extraction.

Why: the crawler returns raw ``response.text`` (HTML). On a reference
article (PortSwigger, OWASP) ~60% of that is tag/script/style/nav noise,
so feeding raw HTML to the web_search synthesizer under a char cap wastes
most of the budget on markup — and the actual payload, which lives deep in
a ``<pre>``/``<code>`` block, gets truncated away.

This mirrors the chaindeal scraper's strip-then-convert approach
(``backend/src/agent/tools/page-crawl.ts`` +
``backend/src/data-discovery/parsing/html-to-markdown.service.ts``):
drop the noise tags with BeautifulSoup, then convert the remainder to
markdown — preserving the things that matter for security references:
fenced code blocks, tables, links, and headings.

GitHub raw ``.md`` URLs are already markdown; callers should skip this
for them (see :func:`looks_like_markdown`).
"""

from __future__ import annotations

import re

# Tags whose entire subtree is noise for reference-doc extraction.
_NOISE_TAGS = (
    "script", "style", "noscript", "template", "svg", "nav", "header",
    "footer", "aside", "form", "button", "iframe", "link", "meta",
)


def looks_like_markdown(content: str, content_type: str = "") -> bool:
    """Heuristic: is this already markdown/plain text (skip extraction)?

    True for ``text/markdown`` / ``text/plain`` content types, or bodies
    that have no ``<html``/``<body`` and few angle-bracket tags relative
    to length (GitHub raw ``.md`` files, README dumps).
    """
    ct = content_type.lower()
    if "markdown" in ct or "text/plain" in ct:
        return True
    head = content[:4000].lower()
    if "<html" in head or "<body" in head or "<!doctype html" in head:
        return False
    # Few tags => treat as already-text.
    tagish = content.count("<")
    return tagish < max(20, len(content) // 2000)


def html_to_markdown(html: str) -> str:
    """Strip noise tags, convert the rest to markdown.

    Returns the cleaned markdown, or — if BeautifulSoup/markdownify are
    unavailable or the parse fails — a best-effort tag-stripped text so
    the caller always gets *something* usable rather than raw HTML.
    """
    if not html:
        return ""
    try:
        from bs4 import BeautifulSoup
        from markdownify import markdownify as _md

        soup = BeautifulSoup(html, "html.parser")
        for tag in soup(list(_NOISE_TAGS)):
            tag.decompose()
        # Prefer the main content region when the page marks one.
        root = (
            soup.find("main")
            or soup.find("article")
            or soup.body
            or soup
        )
        md = _md(str(root), heading_style="ATX", code_language="")
    except Exception:
        # Fallback: crude tag strip (keeps text, loses structure).
        md = re.sub(r"<[^>]+>", " ", html)

    # Collapse the runaway blank lines markdownify leaves behind.
    md = re.sub(r"\n{3,}", "\n\n", md)
    md = re.sub(r"[ \t]+\n", "\n", md)
    return md.strip()


def extract_markdown(content: str, content_type: str = "") -> str:
    """Top-level: return markdown for a crawled body.

    Passes already-markdown content through untouched; converts HTML.
    """
    if looks_like_markdown(content, content_type):
        return content.strip()
    return html_to_markdown(content)
