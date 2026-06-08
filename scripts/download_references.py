"""Vendor the curated web-recon references to local files (stage 1).

Fetches every URL in ``CURATED_SOURCES`` (the HackTricks mirror +
PayloadsAllTheThings leaf files) and saves each as local markdown under
``src/tools/web_recon/corpus/<class>/``, plus a ``SOURCES.json`` manifest
recording the URL, byte size, sha256, and fetch date of each file.

Why: the runtime currently HTTP-fetches these from raw.githubusercontent.com
on every web_search call, so a moved/renamed page (HackTricks restructures
often) silently yields empty curated content. A committed local snapshot
can't 404, is instant to read, works offline, and — for the thesis — pins
the knowledge base to a known date so experiments are reproducible.

This stage ONLY downloads + saves. Wiring these files into the per-skill
``references/`` dirs and switching the web_search node to read them locally
is a later stage.

Run:  uv run python scripts/download_references.py
Out:  src/tools/web_recon/corpus/<class>/*.md  +  corpus/SOURCES.json
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

import httpx

from src.tools.web_recon.sources import CURATED_SOURCES

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "tools" / "web_recon" / "corpus"


def _slug_for(url: str) -> str:
    """A readable, deterministic filename for a curated URL.

    ``.../pentesting-web/ssti.../README.md`` → ``hacktricks-ssti....md``;
    ``.../Server Side Template Injection/Python.md`` → ``payloadsallthethings-python.md``.
    """
    lower = url.lower()
    if "hacktricks" in lower:
        prefix = "hacktricks"
    elif "payloadsallthethings" in lower:
        prefix = "payloadsallthethings"
    else:
        prefix = "ref"
    parts = [seg for seg in unquote(urlparse(url).path).split("/") if seg and seg != "master"]
    leaf = parts[-1].replace(".md", "") if parts else "index"
    # A bare README is the directory index — name it after its parent dir.
    if leaf.lower() == "readme" and len(parts) >= 2:
        leaf = parts[-2]
    name = f"{prefix}-{leaf}".lower()
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in name) + ".md"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    total = sum(len(v) for v in CURATED_SOURCES.values())
    n = 0
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with httpx.Client(
        timeout=30.0, follow_redirects=True,
        headers={"User-Agent": "swarm-references/1.0"},
    ) as client:
        for vuln_class, urls in CURATED_SOURCES.items():
            cls_dir = OUT / vuln_class
            for url in urls:
                n += 1
                fname = _slug_for(url)
                try:
                    r = client.get(url)
                    body = r.text if r.status_code == 200 else ""
                    ok = bool(body.strip())
                    status: object = r.status_code
                except Exception as e:  # network / DNS / TLS failure
                    body, ok, status = "", False, f"ERR:{type(e).__name__}"

                if ok:
                    cls_dir.mkdir(parents=True, exist_ok=True)
                    dest = cls_dir / fname
                    dest.write_text(body, encoding="utf-8")
                    manifest.append({
                        "class": vuln_class, "url": url,
                        "file": str(dest.relative_to(ROOT)),
                        "bytes": len(body),
                        "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
                        "status": 200,
                    })
                    print(f"[{n:>2}/{total}] OK   {vuln_class:<16} {fname:<40} {len(body):>7} B")
                else:
                    manifest.append({
                        "class": vuln_class, "url": url, "file": None,
                        "bytes": 0, "sha256": None, "status": status,
                    })
                    print(f"[{n:>2}/{total}] DEAD {vuln_class:<16} {fname:<40} <- {status}  {url}")

    (OUT / "SOURCES.json").write_text(
        json.dumps({"fetched_at": fetched_at, "sources": manifest}, indent=2),
        encoding="utf-8",
    )

    dead = [m for m in manifest if m["status"] != 200]
    total_bytes = sum(m["bytes"] for m in manifest)
    print(
        f"\nDone: {len(manifest) - len(dead)}/{len(manifest)} fetched "
        f"({total_bytes / 1024:.0f} KB total) → {OUT.relative_to(ROOT)}"
    )
    if dead:
        print(f"\n⚠ {len(dead)} DEAD source(s) — these silently returned empty at runtime:")
        for m in dead:
            print(f"  [{m['status']}] {m['class']}: {m['url']}")


if __name__ == "__main__":
    main()
