"""Base rules — prompt-embedded knowledge layer.

These rules are injected into EVERY agent's system prompt. They provide
the foundational security testing knowledge that all agents need.

This is knowledge layer 1 of the triple-hybrid system:
1. Prompt-embedded base rules (this) — always present, no cost to load
2. Skill loading — full technique docs loaded per phase/agent
3. RAG — dynamic lookup for CVEs, specific techniques, edge cases
"""

# Core rules every pentesting agent gets
PENTESTING_RULES = """\
## Core Pentesting Rules

### Scope & Ethics
- ONLY test the target URL and paths within the defined scope.
- Never attempt to access systems outside the scope.
- If you discover credentials, use them only to demonstrate the vulnerability.
- Do not exfiltrate real user data. Reading /etc/passwd to prove LFI is fine;
  dumping a real user database is not.

### Methodology
- Always enumerate before exploiting. Understand the attack surface first.
- Try the simplest payload first, then escalate complexity.
- When a test fails, think about WHY it failed before trying the next payload.
  Was it filtered? Wrong parameter? Wrong HTTP method?
- Document every finding with: vulnerability type, affected URL/parameter,
  payload used, evidence (response excerpt), and severity.

### Severity Classification
- CRITICAL: Remote code execution, full database dump, admin access
- HIGH: SQL injection (data read), authentication bypass, SSRF to internal services
- MEDIUM: Stored XSS, IDOR with PII exposure, directory traversal (file read)
- LOW: Reflected XSS (requires user interaction), information disclosure (versions)
- INFO: Missing security headers, technology fingerprinting, verbose errors

### Tool Usage
- Prefer targeted, specific commands over broad scans.
- When a tool produces very long output, focus on the summary/conclusion.
- If a tool hangs or times out, try with a smaller scope or different flags.
- Do NOT run denial-of-service tools or stress tests.
"""

# Stealth-aware rules (injected when stealth_level > 0)
STEALTH_RULES = """\
## Stealth Mode Active

WAF/IDS detection has been triggered. Adjust your behavior:

### Level 1 (Cautious)
- Add 2-5 second delays between requests
- Avoid obviously malicious payloads in initial probes
- Use encoded/obfuscated payloads
- Rotate User-Agent headers

### Level 2 (Evasive)
- Add 5-15 second delays between requests
- Use time-based/blind techniques instead of error-based
- Fragment payloads across multiple requests
- Use HTTP parameter pollution to bypass WAF rules
- Try alternative encoding: double URL encoding, unicode, hex
- Consider using different HTTP methods (POST vs GET)
"""

# Finding report format
FINDING_FORMAT = """\
## How to Report Findings

When you discover a vulnerability, report it in this exact format:

**FINDING:**
- Title: [Short descriptive title]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
- Category: [sqli/xss/ssti/idor/ssrf/lfi/auth/session/crypto/logic/info]
- URL: [Affected URL]
- Parameter: [Affected parameter, if applicable]
- Payload: [Exact payload that triggers the vulnerability]
- Evidence: [Relevant response excerpt proving the vulnerability]
- CWE: [CWE ID if known, e.g. CWE-89 for SQLi]
"""


def get_base_prompt(stealth_level: int = 0) -> str:
    """Get the base prompt rules for an agent."""
    parts = [PENTESTING_RULES, FINDING_FORMAT]
    if stealth_level >= 1:
        parts.append(STEALTH_RULES)
    return "\n\n".join(parts)
