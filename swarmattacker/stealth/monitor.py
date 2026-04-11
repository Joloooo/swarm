"""WAF/IDS detection and evasion — stealth monitor.

Watches tool output from all agents for signs of WAF/IDS blocking:
- HTTP 403/406/429 responses
- Known WAF signatures (Cloudflare, ModSecurity, AWS WAF, etc.)
- Connection resets or timeouts after specific payloads
- CAPTCHA pages

When detected, adjusts stealth_level in the shared state, which
agents read to modify their behavior (timing, payload encoding, etc.).

Phase 4 will implement the full system. This module provides the
interface and basic WAF signature detection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


WAF_SIGNATURES = [
    # Cloudflare
    (r"cloudflare", "Cloudflare"),
    (r"cf-ray", "Cloudflare"),
    # ModSecurity
    (r"mod_security", "ModSecurity"),
    (r"NOYB", "ModSecurity"),
    # AWS WAF
    (r"awselb", "AWS WAF"),
    (r"x-amzn-requestid", "AWS WAF"),
    # Generic
    (r"403 Forbidden", "Generic WAF/Firewall"),
    (r"406 Not Acceptable", "Generic WAF/Firewall"),
    (r"Request blocked", "Generic WAF/Firewall"),
    (r"Access Denied", "Generic WAF/Firewall"),
]

RATE_LIMIT_SIGNATURES = [
    (r"429 Too Many Requests", "Rate limiting"),
    (r"rate limit", "Rate limiting"),
    (r"retry-after", "Rate limiting"),
]


@dataclass
class StealthAlert:
    detected: bool
    waf_name: str = ""
    alert_type: str = ""  # "waf", "rate_limit", "captcha"
    recommended_level: int = 0  # 0=none, 1=cautious, 2=evasive


class StealthMonitor:
    """Analyzes tool output for WAF/IDS signals."""

    def __init__(self):
        self._alerts: list[StealthAlert] = []

    def analyze_output(self, output: str) -> StealthAlert:
        """Check tool output for WAF/IDS indicators."""
        output_lower = output.lower()

        # Check WAF signatures
        for pattern, name in WAF_SIGNATURES:
            if re.search(pattern, output_lower):
                alert = StealthAlert(
                    detected=True,
                    waf_name=name,
                    alert_type="waf",
                    recommended_level=2,
                )
                self._alerts.append(alert)
                return alert

        # Check rate limiting
        for pattern, name in RATE_LIMIT_SIGNATURES:
            if re.search(pattern, output_lower):
                alert = StealthAlert(
                    detected=True,
                    waf_name=name,
                    alert_type="rate_limit",
                    recommended_level=1,
                )
                self._alerts.append(alert)
                return alert

        return StealthAlert(detected=False)

    @property
    def max_stealth_level(self) -> int:
        """Highest stealth level recommended by any alert so far."""
        if not self._alerts:
            return 0
        return max(a.recommended_level for a in self._alerts)
