"""Experience persistence — guide storage (PentAGI-style).

Stores successful attack strategies and findings from past runs so that
future runs against similar targets can skip dead ends and reuse proven
techniques.

This is a simple JSON-based implementation. Each "guide" records:
- Target fingerprint (technology stack, features detected)
- What worked (successful payloads, vulnerable endpoints)
- What didn't work (failed strategies, WAF bypass attempts)
- Timing information (how long each phase took)

Guides are matched by technology fingerprint similarity, not exact URL,
so knowledge transfers across targets with similar stacks.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from src.state import Finding, Severity


@dataclass
class AttackGuide:
    """A recorded experience from a past pentesting run."""

    # Target fingerprint (for matching)
    technologies: list[str] = field(default_factory=list)  # e.g. ["php", "mysql", "apache"]
    features: list[str] = field(default_factory=list)  # e.g. ["login", "file-upload", "api"]

    # What worked
    successful_payloads: list[dict[str, str]] = field(default_factory=list)
    # e.g. [{"category": "sqli", "payload": "' OR 1=1--", "context": "login form"}]

    vulnerable_endpoints: list[str] = field(default_factory=list)
    # e.g. ["/api/users?id=", "/upload.php"]

    # What didn't work
    failed_strategies: list[str] = field(default_factory=list)
    # e.g. ["SSTI: no template engine detected", "SSRF: all URL params filtered"]

    # Metadata
    target_url: str = ""
    timestamp: str = ""
    total_findings: int = 0
    duration_seconds: float = 0.0


class ExperienceStore:
    """Persistent store for attack guides."""

    def __init__(self, store_path: str = ".experience"):
        self._path = Path(store_path)
        self._path.mkdir(exist_ok=True)
        self._guides: list[AttackGuide] = []
        self._load()

    def _load(self) -> None:
        """Load all guides from disk."""
        index_path = self._path / "index.json"
        if not index_path.exists():
            return

        with open(index_path) as f:
            data = json.load(f)

        for entry in data.get("guides", []):
            self._guides.append(AttackGuide(**entry))

    def _save(self) -> None:
        """Persist guides to disk."""
        index_path = self._path / "index.json"
        data = {
            "guides": [self._to_dict(g) for g in self._guides],
            "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(index_path, "w") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def _to_dict(guide: AttackGuide) -> dict:
        """Convert guide to a JSON-serializable dict."""
        return {
            "technologies": guide.technologies,
            "features": guide.features,
            "successful_payloads": guide.successful_payloads,
            "vulnerable_endpoints": guide.vulnerable_endpoints,
            "failed_strategies": guide.failed_strategies,
            "target_url": guide.target_url,
            "timestamp": guide.timestamp,
            "total_findings": guide.total_findings,
            "duration_seconds": guide.duration_seconds,
        }

    def record(
        self,
        target_url: str,
        technologies: list[str],
        features: list[str],
        findings: list[Finding],
        failed_strategies: list[str] | None = None,
        duration_seconds: float = 0.0,
    ) -> AttackGuide:
        """Record a new experience from a completed run."""
        guide = AttackGuide(
            target_url=target_url,
            technologies=technologies,
            features=features,
            successful_payloads=[
                {
                    "category": f.category,
                    "title": f.title,
                    "evidence": f.evidence[:200],
                }
                for f in findings
            ],
            vulnerable_endpoints=[f.url for f in findings if f.url],
            failed_strategies=failed_strategies or [],
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            total_findings=len(findings),
            duration_seconds=duration_seconds,
        )

        self._guides.append(guide)
        self._save()
        return guide

    def find_relevant(
        self,
        technologies: list[str],
        features: list[str],
        top_k: int = 3,
    ) -> list[AttackGuide]:
        """Find guides with similar technology/feature fingerprints.

        Uses Jaccard similarity on the tech+feature sets.
        """
        if not self._guides:
            return []

        query_set = set(t.lower() for t in technologies + features)

        scored = []
        for guide in self._guides:
            guide_set = set(
                t.lower() for t in guide.technologies + guide.features
            )
            if not query_set or not guide_set:
                continue
            jaccard = len(query_set & guide_set) / len(query_set | guide_set)
            scored.append((jaccard, guide))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [guide for _, guide in scored[:top_k] if _ > 0.1]

    def format_for_prompt(self, guides: list[AttackGuide]) -> str:
        """Format relevant guides as context for agent prompts."""
        if not guides:
            return ""

        parts = ["\n--- Past Experience (from similar targets) ---"]
        for i, guide in enumerate(guides, 1):
            parts.append(f"\n**Experience {i}** (target: {guide.target_url})")
            parts.append(f"Technologies: {', '.join(guide.technologies)}")

            if guide.successful_payloads:
                parts.append("What worked:")
                for p in guide.successful_payloads[:5]:
                    parts.append(f"  - [{p.get('category')}] {p.get('title')}")

            if guide.failed_strategies:
                parts.append("What didn't work:")
                for s in guide.failed_strategies[:5]:
                    parts.append(f"  - {s}")

        return "\n".join(parts)

    @property
    def guide_count(self) -> int:
        return len(self._guides)
