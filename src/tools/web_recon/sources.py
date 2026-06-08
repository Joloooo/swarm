"""Curated authoritative reference sources, keyed by vulnerability class.

Why: the richest references — HackTricks, PayloadsAllTheThings — either can't
be crawled (book.hacktricks.xyz is JS/bot-protected) or hide the payloads in
linked leaf files (PayloadsAllTheThings' per-dir README is an index).

So for known vuln classes we deep-fetch the canonical GitHub *raw markdown*
directly: the HackTricks-wiki mirror (full page, ~50k chars, crawlable over
plain HTTP) and the PayloadsAllTheThings leaf files (the engine-specific
payload dumps, not the index). All URLs were HTTP-200 verified on 2026-06-07.
These are markdown already, so the crawler's HTML→md extractor passes them
through untouched.

The web_search node passes this curated markdown to the Codex hosted
``web_search`` tool as context, so the model reads the payload-rich pages
alongside its own searches. For classes not in the map there is no curated
prepend — the Codex model's own web searches are the path.
"""

from __future__ import annotations

import re

_HT = "https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web"
_PA = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master"

# Canonical class -> ordered list of authoritative raw-markdown URLs.
# HackTricks first (broadest), then PayloadsAllTheThings leaf/README.
CURATED_SOURCES: dict[str, list[str]] = {
    "ssti": [
        f"{_HT}/ssti-server-side-template-injection/README.md",
        f"{_PA}/Server%20Side%20Template%20Injection/Python.md",
        f"{_PA}/Server%20Side%20Template%20Injection/README.md",
    ],
    "sqli": [
        f"{_HT}/sql-injection/README.md",
        f"{_PA}/SQL%20Injection/README.md",
    ],
    "xss": [
        f"{_HT}/xss-cross-site-scripting/README.md",
        f"{_PA}/XSS%20Injection/README.md",
    ],
    "xxe": [
        f"{_HT}/xxe-xee-xml-external-entity.md",
        f"{_PA}/XXE%20Injection/README.md",
    ],
    "lfi": [
        f"{_HT}/file-inclusion/README.md",
        f"{_PA}/File%20Inclusion/README.md",
        f"{_PA}/Directory%20Traversal/README.md",
    ],
    "cmdi": [
        f"{_HT}/command-injection.md",
        f"{_PA}/Command%20Injection/README.md",
    ],
    "ssrf": [
        f"{_HT}/ssrf-server-side-request-forgery/README.md",
        f"{_PA}/Server%20Side%20Request%20Forgery/README.md",
    ],
    "deserialization": [
        f"{_HT}/deserialization/README.md",
        f"{_PA}/Insecure%20Deserialization/README.md",
    ],
    "upload": [
        f"{_HT}/file-upload/README.md",
        f"{_PA}/Upload%20Insecure%20Files/README.md",
    ],
    "idor": [
        f"{_HT}/idor.md",
    ],
    "open-redirect": [
        f"{_HT}/open-redirect.md",
        f"{_PA}/Open%20Redirect/README.md",
    ],
    "jwt": [
        f"{_HT}/hacking-jwt-json-web-tokens.md",
        f"{_PA}/JSON%20Web%20Token/README.md",
    ],
    "graphql": [
        f"{_PA}/GraphQL%20Injection/README.md",
    ],
    "nosql": [
        f"{_PA}/NoSQL%20Injection/README.md",
    ],
    "csrf": [
        f"{_HT}/csrf-cross-site-request-forgery.md",
        f"{_PA}/Cross-Site%20Request%20Forgery/README.md",
    ],
}

# Aliases — map the many names a class travels under (benchmark tags, skill
# agent_ids, planner phrasing) onto the canonical key above.
_ALIASES: dict[str, str] = {
    "server-side-template-injection": "ssti",
    "template-injection": "ssti",
    "sql-injection": "sqli", "sql_injection": "sqli", "sqlinjection": "sqli",
    "cross-site-scripting": "xss",
    "xml-external-entity": "xxe", "xml_external_entity": "xxe",
    "file-inclusion": "lfi", "file_inclusion": "lfi",
    "path-traversal": "lfi", "path_traversal": "lfi",
    "directory-traversal": "lfi", "directory_traversal": "lfi",
    "rfi": "lfi",
    "command-injection": "cmdi", "command_injection": "cmdi", "rce": "cmdi",
    "os-command-injection": "cmdi",
    "server-side-request-forgery": "ssrf",
    "insecure-deserialization": "deserialization", "deserialisation": "deserialization",
    "file-upload": "upload", "insecure-file-uploads": "upload",
    "insecure-direct-object-reference": "idor",
    "open_redirect": "open-redirect", "openredirect": "open-redirect",
    "json-web-token": "jwt", "jsonwebtoken": "jwt",
    "graphql-injection": "graphql",
    "nosql-injection": "nosql", "nosqli": "nosql",
    "cross-site-request-forgery": "csrf",
}


def normalize_class(vuln_class: str) -> str | None:
    """Resolve any spelling/tag/alias to a canonical CURATED_SOURCES key."""
    if not vuln_class:
        return None
    key = vuln_class.strip().lower().replace(" ", "-")
    if key in CURATED_SOURCES:
        return key
    if key in _ALIASES:
        return _ALIASES[key]
    # last resort: try the underscore form
    key2 = key.replace("-", "_")
    return _ALIASES.get(key2)


def sources_for(vuln_class: str) -> list[str]:
    """Canonical reference URLs for a vuln class, or [] if unknown."""
    key = normalize_class(vuln_class)
    return list(CURATED_SOURCES.get(key, [])) if key else []


def infer_class(text: str) -> str | None:
    """Best-effort: detect the vuln class named in free text (a search query).

    Matches canonical keys and aliases as whole words (after collapsing
    punctuation to spaces), longest-first so ``sql injection`` wins over a
    stray ``sql`` and ``ssti`` is found inside ``django ssti payload``.
    """
    if not text:
        return None
    haystack = " " + re.sub(r"[^a-z0-9]+", " ", text.lower()).strip() + " "
    candidates = sorted(
        list(CURATED_SOURCES.keys()) + list(_ALIASES.keys()),
        key=len, reverse=True,
    )
    for cand in candidates:
        needle = " " + re.sub(r"[^a-z0-9]+", " ", cand.lower()).strip() + " "
        if needle in haystack:
            return normalize_class(cand)
    return None
