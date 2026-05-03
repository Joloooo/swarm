---
name: scan-mode-quick
description: Use when the engagement is time-boxed and the goal is fast feedback on critical, high-impact vulnerabilities. Covers the breadth-over-depth methodology — rapid orientation (recent git changes for whitebox, critical user-flow mapping for blackbox), priority order for testing (auth bypass → broken access control → RCE → SQLi → SSRF → exposed secrets), what to consciously skip (exhaustive enum, full directory brute-force, low-severity info disclosure), and the chain-on-find rule (turn a primitive into one high-impact pivot before reporting). Reference-only methodology preset that planner agents consult before dispatching attack skills.
---

# Quick Scan Mode

Time-boxed assessment focused on high-impact vulnerabilities.
Prioritize breadth over depth.

This skill is **reference-only** — it has no `agent_id` and is not
dispatched as an attack agent. The planner consults it (and reads
the methodology below) when it wants to decide *how* to approach an
engagement, not *what* to attack.

## When to pick this mode

- Engagement window measured in hours, not days.
- The user explicitly asked for a "quick scan" or "first-pass triage".
- The target is a single small app and a deeper scan is planned later.
- Bug-bounty triage where speed-to-finding matters.

## Approach

Optimize for fast feedback on critical security issues. Skip
exhaustive enumeration in favor of targeted testing on high-value
attack surfaces.

## Phase 1: Rapid orientation

**Whitebox (source available)**:
- Focus on recent changes — git diffs, new commits, modified files.
  Fresh code is where fresh bugs live.
- Identify security-sensitive patterns in changed code — auth
  checks, input handling, database queries, file operations.
- Trace user input through modified code paths.
- Check if security controls were modified or bypassed.

**Blackbox (no source)**:
- Map authentication and critical user flows.
- Identify exposed endpoints and entry points.
- Skip deep content discovery — test what's immediately accessible.

## Phase 2: High-impact targets (priority order)

Test in this order — the first ones yield the most impact per minute:

1. **Authentication bypass** — login flaws, session issues, token
   weaknesses (dispatch `auth-testing`).
2. **Broken access control** — IDOR, privilege escalation, missing
   authorization (dispatch `idor`, `bfla`).
3. **Remote code execution** — command injection, deserialization,
   SSTI (dispatch `rce`).
4. **SQL injection** — authentication endpoints, search, filters
   (dispatch `sqli`).
5. **SSRF** — URL parameters, webhooks, integrations (dispatch
   `ssrf`).
6. **Exposed secrets** — hardcoded credentials, API keys, config
   files (dispatch `information-disclosure`).

### What to skip for quick scans
- Exhaustive subdomain enumeration.
- Full directory brute-forcing.
- Low-severity information disclosure without an exploit chain.
- Theoretical issues without a working PoC.
- Extensive fuzzing — use targeted payloads only.

## Phase 3: Validation

- Confirm exploitability with a minimal proof-of-concept.
- Demonstrate real impact, not theoretical risk.
- Report findings immediately as discovered.

## Chaining (the key rule for quick mode)

When a strong primitive is found (auth weakness, injection point,
internal access), **immediately attempt one high-impact pivot** to
demonstrate maximum severity. Don't stop at a low-context "maybe" —
turn it into a concrete exploit sequence that reaches privileged
action or sensitive data.

## Operational guidelines

- Use the browser tool for quick manual testing of critical flows.
- Use the terminal for targeted scans with fast presets (e.g.,
  nuclei with critical/high templates only).
- Use proxy to inspect traffic on key endpoints.
- Skip extensive fuzzing — use targeted payloads only.
- Spawn subagents only for parallel high-priority tasks.

## Mindset

Think like a time-boxed bug-bounty hunter going for quick wins.
Prioritize breadth over depth on critical areas. If something looks
exploitable, validate quickly and move on. Don't get stuck — if an
attack vector isn't yielding results quickly, pivot.
