"""Web crawler tool — raw HTTP first, Playwright browser fallback.

Ported (not selectively copied) from the chaindeal TypeScript scraper:
- ``data-discovery/scraping/http.service.ts``
- ``data-discovery/scraping/puppeteer.service.ts``
- ``data-discovery/scraping/scraper-orchestrator.service.ts``
- ``data-discovery/data-discovery.options.ts``

Every browser-mimicking header, URL variation rule, binary-content filter,
duplicate language-path fallback, redirect classification, and root-domain
extraction from the original is preserved here.

Python substitutions for the TS stack:
- ``axios`` + ``https.Agent`` pooling → ``httpx.AsyncClient`` (HTTP/2,
  keep-alive, configurable limits).
- ``puppeteer`` → ``playwright.async_api`` (python port; puppeteer has
  no maintained python binding).
- NestJS DI classes → plain module-level async functions.

The public entry points are :func:`crawl` and :func:`crawl_many`. They
return :class:`CrawlResult` (or a list of them) matching the shape of
the TS ``UnifiedScrapeResult``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse, urlunparse

import httpx

from src.graph import budgets

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Options (ported from data-discovery.options.ts — DEFAULT_SCRAPING_OPTIONS)
# ---------------------------------------------------------------------------


@dataclass
class CrawlerOptions:
    """Shared configuration for all crawling strategies.

    Mirrors the TS ``ScrapingOptions`` type exactly. The timeout is kept
    at 300s — the original note was that slow (25 Mbps) connections
    with many concurrent requests can take > 60s, and we'd rather wait
    than drop a real result.
    """

    timeout_ms: int = field(default_factory=lambda: budgets.tool_crawler_timeout_ms)
    max_redirects: int = 5
    ignore_ssl_errors: bool = True
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
    generate_url_variations: bool = True


DEFAULT_OPTIONS = CrawlerOptions()


# ---------------------------------------------------------------------------
# Result types (ported from UnifiedScrapeResult / ScrapeBatchResult)
# ---------------------------------------------------------------------------


RedirectType = Literal["none", "trailing-slash", "real"]
Method = Literal["http", "playwright"]


@dataclass
class CrawlResult:
    """Single-URL crawl result."""

    url: str
    content: str
    success: bool
    error: str | None = None
    method: Method | None = None
    final_url: str | None = None
    redirect_type: RedirectType | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BatchStats:
    http_success: int = 0
    playwright_success: int = 0
    total_failed: int = 0
    total_success: int = 0


@dataclass
class CrawlBatchResult:
    results: list[CrawlResult] = field(default_factory=list)
    stats: BatchStats = field(default_factory=BatchStats)


# ---------------------------------------------------------------------------
# URL helpers (ported from scraper-orchestrator.service.ts)
# ---------------------------------------------------------------------------

# From fileExtensions[] — the full list that classifies a URL as pointing
# to a binary/file instead of scrapable HTML.
_FILE_EXTENSIONS: tuple[str, ...] = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".bmp",
    ".tiff", ".tif", ".ico",
    ".css", ".js", ".json", ".xml",
    ".mp4", ".avi", ".mov", ".wmv", ".webm", ".mkv", ".flv",
    ".m4v", ".ogv",
    ".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma", ".m4a",
    ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".app", ".bin",
    ".iso", ".csv", ".icc", ".eps",
)

# From the HTTP service's binaryContentTypes[] list — rejected content-types.
_BINARY_CONTENT_TYPES: tuple[str, ...] = (
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-msdos-program",
    "application/x-exe",
    "application/x-winexe",
    "application/x-ms-wim",
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/x-tar",
    "application/gzip",
    "image/",
    "video/",
    "audio/",
    "application/x-shockwave-flash",
    "application/java-archive",
)

# Common language codes (used for duplicate-language-path normalization,
# e.g. "/de/de/" → "/de/").
_LANGUAGE_CODES: tuple[str, ...] = (
    "de", "en", "fr", "es", "it", "nl", "pl", "pt", "ru", "zh",
    "ja", "ko", "ar", "sv", "da", "fi", "no", "cs", "hu", "ro",
    "tr", "el", "he", "th", "vi",
)

# Download-path heuristics that typically serve binary files.
_DOWNLOAD_PATH_PATTERNS: tuple[str, ...] = (
    "/download/", "/downloads/", "/file/", "/files/", "/get/",
    "/getfile/", "/wp-content/uploads/", "/media/", "/assets/",
    "/static/",
)


def generate_url_variations(url: str) -> list[str]:
    """Produce [original, switch-protocol, toggle-www, switch+toggle].

    Handles sites that only answer on a specific variant (e.g. require
    ``www`` or only accept ``https``). Duplicates are removed.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return [url]

    if not parsed.scheme or not parsed.netloc:
        return [url]

    hostname = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"{hostname}{port}"
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment

    has_www = hostname.startswith("www.")
    hostname_no_www = hostname[4:] if has_www else hostname
    netloc_no_www = f"{hostname_no_www}{port}"

    is_https = parsed.scheme == "https"
    alt_scheme = "http" if is_https else "https"

    def _build(scheme: str, net: str) -> str:
        return urlunparse((scheme, net, path, "", query, fragment))

    variations = [
        url,
        _build(alt_scheme, netloc),
        _build(parsed.scheme, netloc_no_www),
        _build(alt_scheme, netloc_no_www),
    ]
    # Dedupe preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for v in variations:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique


def _is_file_url(url: str) -> bool:
    try:
        path = (urlparse(url).path or "").lower()
    except ValueError:
        return False
    return any(path.endswith(ext) for ext in _FILE_EXTENSIONS)


def _has_pdf_in_query(url: str) -> bool:
    """Catch download endpoints that serve PDFs via query params.

    Matches patterns like ``?file=document.pdf``, WordPress's
    ``/download/?wpdmdl=227``, and generic ``download?pdf=...``.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    search = (parsed.query or "").lower()
    path = (parsed.path or "").lower()
    url_lower = url.lower()

    if ".pdf" in search or ".pdf" in path or "pdf" in search:
        return True
    if "download" in path and (
        "wpdmdl" in search or "file" in search or "pdf" in search
    ):
        return True
    if "pdf" in url_lower and (
        "download" in url_lower
        or "file" in url_lower
        or "document" in url_lower
    ):
        return True
    return False


def is_binary_file_url(url: str) -> bool:
    """Block URLs that point at non-scrapable binary content.

    Applied before any request is made — saves a round-trip plus
    avoids fetching megabytes of binary data we'd throw away.
    """
    if _is_file_url(url):
        return True
    if _has_pdf_in_query(url):
        return True

    try:
        path = (urlparse(url).path or "").lower()
    except ValueError:
        return False

    if any(p in path for p in _DOWNLOAD_PATH_PATTERNS):
        # HTML-ish paths inside download dirs are still allowed.
        if (
            path.endswith(".html")
            or path.endswith(".htm")
            or path.endswith("/")
            or path == ""
        ):
            return False
        return True
    return False


def _extract_root_domain(url: str) -> str:
    """If a redirect lands on a file or deep path, snap back to root.

    Example: ``https://flgruppe.de/wp-content/uploads/file.pdf``
    becomes ``https://flgruppe.de``. Stops us from recording a PDF URL
    as the canonical site entry.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    path = parsed.path or ""
    segments = [s for s in path.split("/") if s]
    if _is_file_url(url) or len(segments) > 2:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url


def _is_trailing_slash_only_redirect(original: str, final: str) -> bool:
    return original.rstrip("/") == final.rstrip("/") and original != final


def _classify_redirect(original: str, final: str) -> RedirectType:
    if original == final:
        return "none"
    if _is_trailing_slash_only_redirect(original, final):
        return "trailing-slash"
    return "real"


def _normalize_redirected_url(
    original: str, final: str
) -> tuple[str, RedirectType]:
    if original == final:
        return final, "none"
    redirect_type = _classify_redirect(original, final)
    normalized = _extract_root_domain(final)
    if normalized != final:
        redirect_type = "real"
    return normalized, redirect_type


def _normalize_duplicate_language_path(url: str) -> tuple[str, bool]:
    """Collapse ``/de/de/`` → ``/de/`` patterns (and similar).

    Some CMSes accidentally build double-language URLs that 404 even
    though the single-language version works. Used as a last-resort
    fallback after every strategy has failed.
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return url, False
    path = parsed.path or ""
    import re

    for lang in _LANGUAGE_CODES:
        pattern = re.compile(rf"/{lang}/{lang}(?=/|$)", re.IGNORECASE)
        if pattern.search(path):
            new_path = pattern.sub(f"/{lang}", path)
            new_url = urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    new_path,
                    parsed.params,
                    parsed.query,
                    parsed.fragment,
                )
            )
            return new_url, True
    return url, False


# ---------------------------------------------------------------------------
# HTTP crawler (ported from http.service.ts)
# ---------------------------------------------------------------------------


# Browser-mimicking header set — copied verbatim from the TS version.
# The Sec-Fetch-* family is what trips up a lot of WAF fingerprinters
# when it's absent; most real Chrome requests include these so we
# include them too.
def _browser_headers(user_agent: str) -> dict[str, str]:
    return {
        "User-Agent": user_agent,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }


# Module-level async client — mirrors the TS connection-pooling agents.
# maxSockets=50 / maxFreeSockets=10 on the TS side become httpx's
# per-host connection limits below. Keep-alive is on by default.
_http_client: httpx.AsyncClient | None = None
_http_client_lock = asyncio.Lock()


async def _get_http_client(options: CrawlerOptions) -> httpx.AsyncClient:
    global _http_client
    if _http_client is not None:
        return _http_client
    async with _http_client_lock:
        if _http_client is not None:
            return _http_client
        _http_client = httpx.AsyncClient(
            http2=True,
            follow_redirects=True,
            max_redirects=options.max_redirects,
            timeout=httpx.Timeout(options.timeout_ms / 1000),
            verify=not options.ignore_ssl_errors,
            limits=httpx.Limits(
                max_connections=1000,
                max_keepalive_connections=500,
                keepalive_expiry=1.0,
            ),
            headers=_browser_headers(options.user_agent),
        )
    return _http_client


async def close_http_client() -> None:
    """Close the shared httpx client. Call on shutdown if needed."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


async def try_http_request(
    url: str, options: CrawlerOptions = DEFAULT_OPTIONS
) -> CrawlResult | None:
    """Single raw-HTTP attempt with browser headers + redirect following.

    Returns ``None`` on any failure or rejected content-type, so the
    orchestrator can fall back to the next strategy.
    """
    client = await _get_http_client(options)
    start = time.monotonic()
    try:
        response = await client.get(url)
        if response.status_code >= 400:
            logger.debug(
                "HTTP %d for %s", response.status_code, url
            )
            return None

        content_type = (
            response.headers.get("content-type") or ""
        ).lower()
        if any(bt in content_type for bt in _BINARY_CONTENT_TYPES):
            logger.debug(
                "Rejecting binary content type: %s for %s",
                content_type,
                url,
            )
            return None

        final_url = str(response.url)
        duration_ms = (time.monotonic() - start) * 1000
        if duration_ms > 5000:
            logger.debug(
                "Slow HTTP request: %s took %.0fms", url, duration_ms
            )

        return CrawlResult(
            url=url,
            content=response.text,
            success=True,
            method="http",
            final_url=final_url if final_url != url else url,
        )
    except httpx.HTTPError as e:
        duration_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "HTTP error for %s (%.0fms): %s", url, duration_ms, e
        )
        return None
    except Exception as e:  # noqa: BLE001
        duration_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "Unexpected HTTP error for %s (%.0fms): %s",
            url,
            duration_ms,
            e,
        )
        return None


# ---------------------------------------------------------------------------
# Playwright crawler (ported from puppeteer.service.ts)
# ---------------------------------------------------------------------------


# Singleton browser — mirrors the TS PuppeteerService lazy-init pattern.
# Created on first call, closed via close_playwright() on shutdown.
_pw_playwright: Any = None
_pw_browser: Any = None
_pw_lock = asyncio.Lock()

# Semaphore equivalent of MAX_CONCURRENT_PUPPETEER. Only a fraction of
# requests fall through to the browser, so 50 slots is plenty.
_PW_MAX_CONCURRENT = int(os.environ.get("MAX_CONCURRENT_PLAYWRIGHT", "50"))
_pw_semaphore: asyncio.Semaphore | None = None


def _get_pw_semaphore() -> asyncio.Semaphore:
    global _pw_semaphore
    if _pw_semaphore is None:
        _pw_semaphore = asyncio.Semaphore(_PW_MAX_CONCURRENT)
    return _pw_semaphore


async def _ensure_playwright_browser(options: CrawlerOptions) -> Any:
    global _pw_playwright, _pw_browser
    if _pw_browser is not None:
        return _pw_browser
    async with _pw_lock:
        if _pw_browser is not None:
            return _pw_browser
        try:
            from playwright.async_api import async_playwright
        except ImportError as e:
            raise RuntimeError(
                "playwright is not installed. Run "
                "`uv add playwright && uv run playwright install chromium` "
                "to enable the browser fallback."
            ) from e

        launch_args = [
            "--no-sandbox",
            "--disable-setuid-sandbox",
            "--disable-dev-shm-usage",
            "--disable-accelerated-2d-canvas",
            "--disable-gpu",
        ]
        if options.ignore_ssl_errors:
            launch_args.extend(
                [
                    "--ignore-certificate-errors",
                    "--ignore-ssl-errors",
                    "--ignore-certificate-errors-spki-list",
                ]
            )

        _pw_playwright = await async_playwright().start()
        _pw_browser = await _pw_playwright.chromium.launch(
            headless=True, args=launch_args
        )
        logger.debug("Playwright browser initialized (lazy)")
    return _pw_browser


async def close_playwright() -> None:
    """Close the shared Playwright browser. Call on shutdown."""
    global _pw_playwright, _pw_browser
    if _pw_browser is not None:
        try:
            await _pw_browser.close()
        except Exception:  # noqa: BLE001
            pass
        _pw_browser = None
    if _pw_playwright is not None:
        try:
            await _pw_playwright.stop()
        except Exception:  # noqa: BLE001
            pass
        _pw_playwright = None


async def try_playwright_request(
    url: str, options: CrawlerOptions = DEFAULT_OPTIONS
) -> CrawlResult | None:
    """Browser-based fetch for sites that need JS / set anti-bot cookies.

    Blocks images/CSS/fonts/media for speed — we only want HTML. Returns
    ``None`` on any error so the caller can treat it as a miss.
    """
    try:
        browser = await _ensure_playwright_browser(options)
    except Exception as e:  # noqa: BLE001
        logger.error("Failed to initialize Playwright browser: %s", e)
        return None

    start = time.monotonic()
    page = None
    context = None
    try:
        context = await browser.new_context(
            user_agent=options.user_agent,
            ignore_https_errors=options.ignore_ssl_errors,
        )
        page = await context.new_page()
        page.set_default_timeout(options.timeout_ms)

        async def _route_filter(route, request):  # type: ignore[no-untyped-def]
            if request.resource_type in (
                "image", "stylesheet", "font", "media"
            ):
                await route.abort()
            else:
                await route.continue_()

        await page.route("**/*", _route_filter)

        response = await page.goto(
            url, wait_until="domcontentloaded", timeout=options.timeout_ms
        )
        if response is None or not response.ok:
            return None

        final_url = response.url
        content = await page.content()

        duration_ms = (time.monotonic() - start) * 1000
        if duration_ms > 10_000:
            logger.debug(
                "Slow Playwright request: %s took %.0fms",
                url,
                duration_ms,
            )

        return CrawlResult(
            url=url,
            content=content,
            success=True,
            method="playwright",
            final_url=final_url if final_url != url else url,
        )
    except Exception as e:  # noqa: BLE001
        duration_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "Playwright error for %s (%.0fms): %s",
            url,
            duration_ms,
            e,
        )
        return None
    finally:
        if page is not None:
            try:
                await page.close()
            except Exception:  # noqa: BLE001
                pass
        if context is not None:
            try:
                await context.close()
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Orchestrator (ported from scraper-orchestrator.service.ts)
# ---------------------------------------------------------------------------


async def _try_url_with_variations(
    url: str,
    try_fn,  # type: ignore[no-untyped-def]
    service_name: str,
    options: CrawlerOptions,
) -> tuple[CrawlResult, str, RedirectType] | None:
    """Try the original URL, then up to 3 variations on failure.

    Returns (result, normalized_final_url, redirect_type) or None.
    """
    # Try original first.
    original_result = await try_fn(url, options)
    if original_result is not None:
        actual_final = original_result.final_url or url
        normalized, redirect_type = _normalize_redirected_url(
            url, actual_final
        )
        if actual_final != url:
            suffix = (
                f" → {normalized}" if actual_final != normalized else ""
            )
            logger.debug(
                "%s redirect detected: %s → %s%s",
                service_name,
                url,
                actual_final,
                suffix,
            )
        return original_result, normalized, redirect_type

    # Original failed — try variations.
    if not options.generate_url_variations:
        return None

    for variation in generate_url_variations(url):
        if variation == url:
            continue
        result = await try_fn(variation, options)
        if result is not None:
            actual_final = result.final_url or variation
            normalized, redirect_type = _normalize_redirected_url(
                url, actual_final
            )
            logger.debug(
                "%s succeeded with variation: %s (original: %s)",
                service_name,
                variation,
                url,
            )
            return result, normalized, redirect_type
    return None


async def _crawl_single(
    url: str,
    services: tuple[Method, ...],
    options: CrawlerOptions,
    skip_language_fallback: bool = False,
) -> CrawlResult:
    """Full strategy chain for one URL.

    Order: reject binary → for each strategy [HTTP, Playwright] try
    original + 3 variations → if all fail, collapse duplicate language
    path (e.g. /de/de/ → /de/) and retry once.
    """
    if is_binary_file_url(url):
        logger.debug("Rejecting binary file URL (not scrapable): %s", url)
        return CrawlResult(
            url=url,
            content="",
            success=False,
            error="URL points to a binary file that cannot be scraped",
            method=services[0] if services else None,
        )

    for service in services:
        service_start = time.monotonic()
        try:
            if service == "http":
                outcome = await _try_url_with_variations(
                    url, try_http_request, "HTTP", options
                )
            elif service == "playwright":
                # Semaphore gate matches the TS puppeteer limiter.
                sem = _get_pw_semaphore()
                async with sem:
                    logger.debug("🐌 Playwright starting for %s", url)
                    outcome = await _try_url_with_variations(
                        url,
                        try_playwright_request,
                        "Playwright",
                        options,
                    )
            else:  # pragma: no cover - defensive
                continue

            duration_ms = (time.monotonic() - service_start) * 1000
            if outcome is not None:
                result, normalized, redirect_type = outcome
                threshold = 5000 if service == "http" else 10_000
                if duration_ms > threshold:
                    logger.debug(
                        "⏱️  %s took %.0fms for %s",
                        service,
                        duration_ms,
                        url,
                    )
                return CrawlResult(
                    url=url,  # keep the caller's URL for consistency
                    content=result.content,
                    success=True,
                    method=service,
                    final_url=normalized,
                    redirect_type=redirect_type,
                )
            if service == "playwright":
                logger.debug(
                    "🐌 Playwright failed after %.0fms for %s",
                    duration_ms,
                    url,
                )
        except Exception as e:  # noqa: BLE001
            logger.debug(
                "%s failed for %s: %s", service, url, e
            )
            continue

    # Last-resort language-path normalization.
    if not skip_language_fallback:
        normalized_url, was_normalized = _normalize_duplicate_language_path(
            url
        )
        if was_normalized and normalized_url != url:
            logger.debug(
                "All services failed for %s, trying normalized URL: %s",
                url,
                normalized_url,
            )
            fallback = await _crawl_single(
                normalized_url, services, options, skip_language_fallback=True
            )
            if fallback.success:
                fallback.url = url  # keep the caller's URL
                return fallback

    return CrawlResult(
        url=url,
        content="",
        success=False,
        error=f"All crawl strategies failed: {', '.join(services)}",
        method=services[-1] if services else None,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def crawl(
    url: str,
    services: tuple[Method, ...] = ("http", "playwright"),
    options: CrawlerOptions = DEFAULT_OPTIONS,
) -> CrawlResult:
    """Crawl a single URL with HTTP-first, Playwright-fallback strategy.

    Tries each strategy in ``services`` order against the original URL
    and up to 3 URL variations, then falls back to language-path
    normalization. Returns a failed ``CrawlResult`` if everything misses.
    """
    return await _crawl_single(url, services, options)


async def crawl_many(
    urls: list[str],
    services: tuple[Method, ...] = ("http", "playwright"),
    options: CrawlerOptions = DEFAULT_OPTIONS,
    batch_size: int = 100,
    concurrent: bool = True,
) -> CrawlBatchResult:
    """Crawl many URLs, optionally concurrently, and return aggregate stats."""
    results: list[CrawlResult] = []
    stats = BatchStats()

    async def _record(result: CrawlResult) -> None:
        if result.success:
            stats.total_success += 1
            if result.method == "http":
                stats.http_success += 1
            elif result.method == "playwright":
                stats.playwright_success += 1
        else:
            stats.total_failed += 1
        results.append(result)

    if concurrent:
        for i in range(0, len(urls), batch_size):
            chunk = urls[i : i + batch_size]
            chunk_results = await asyncio.gather(
                *(_crawl_single(u, services, options) for u in chunk)
            )
            for r in chunk_results:
                await _record(r)
    else:
        for u in urls:
            r = await _crawl_single(u, services, options)
            await _record(r)

    return CrawlBatchResult(results=results, stats=stats)
