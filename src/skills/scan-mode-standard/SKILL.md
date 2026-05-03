---
name: scan-mode-standard
description: Use when the engagement allows a balanced, systematic assessment — full attack-surface coverage with structured methodology, but without exhaustive deep-dives. Covers the standard five-phase flow (reconnaissance → business-logic analysis → systematic testing → exploitation/PoC → reporting), per-surface checklists (input validation / auth & session / access control / business logic), and the always-chain rule (when a pivot exists, follow it before reporting). Reference-only methodology preset that planner agents consult before dispatching attack skills.
---

# Standard Scan Mode

Balanced security assessment with structured methodology. Thorough
coverage without exhaustive depth.

This skill is **reference-only** — it has no `agent_id` and is not
dispatched as an attack agent. The planner consults it when it needs
the default phased methodology.

## When to pick this mode

- Default for most engagements.
- The user gave no time constraint.
- The target has been seen before but a fresh end-to-end pass is
  warranted.

## Approach

Systematic testing across the full attack surface. Understand the
application before exploiting it.

## Phase 1: Reconnaissance

**Whitebox (source available)**:
- Map codebase structure — modules, entry points, routing.
- Identify architecture pattern (MVC, microservices, monolith).
- Trace input vectors — forms, APIs, file uploads, headers, cookies.
- Review authentication and authorization flows.
- Analyze database interactions and ORM usage.
- Check dependencies for known CVEs.
- Understand the data model and sensitive-data locations.

**Blackbox (no source)**:
- Crawl application thoroughly; interact with every feature.
- Enumerate endpoints, parameters, functionality.
- Fingerprint technology stack.
- Map user roles and access levels.
- Capture traffic with a proxy to understand request / response
  patterns.

## Phase 2: Business-logic analysis

Before testing for vulnerabilities, understand the application:

- **Critical flows** — payments, registration, data access, admin
  functions.
- **Role boundaries** — what actions are restricted to which users.
- **Data-access rules** — what data should be isolated between users.
- **State transitions** — order lifecycle, account-status changes.
- **Trust boundaries** — where privilege or sensitive data flows.

## Phase 3: Systematic testing

Test each attack surface methodically. Spawn focused sub-agents for
different areas.

**Input validation** (dispatch `sqli`, `xss`, `lfi`, `ssti`,
`rce`, `xxe`):
- Injection testing on all input fields (SQL, XSS, command,
  template).
- File-upload bypass attempts (dispatch `insecure-file-uploads`).
- Search and filter parameter manipulation.
- Redirect and URL parameter handling (dispatch `open-redirect`).

**Authentication & session** (dispatch `auth-testing`,
`session-mgmt`, `csrf`):
- Brute-force protection.
- Session-token entropy and handling.
- Password-reset flow analysis.
- Logout session invalidation.
- Authentication-bypass techniques.

**Access control** (dispatch `idor`, `bfla`):
- Horizontal — user A accessing user B's resources.
- Vertical — unprivileged user accessing admin functions.
- API endpoints vs. UI access-control consistency.
- Direct object-reference manipulation.

**Business logic** (dispatch `business-logic`, `race-conditions`):
- Multi-step process bypass (skip steps, reorder).
- Race conditions on state-changing operations.
- Boundary conditions — negative values, zero, extremes.
- Transaction replay and manipulation.

## Phase 4: Exploitation

- Every finding requires a working proof-of-concept.
- Demonstrate actual impact, not theoretical risk.
- Chain vulnerabilities to show maximum severity.
- Document full attack path from entry to impact.

## Phase 5: Reporting

- Document all confirmed vulnerabilities with reproduction steps.
- Severity based on exploitability and business impact.
- Remediation recommendations.
- Note areas requiring further investigation.

## Chaining (the always-chain rule)

Always ask: "If I can do X, what does that enable next?" Keep
pivoting until reaching maximum privilege or data exposure.

Prefer complete end-to-end paths (entry point → pivot →
privileged action / data) over isolated findings. Use the
application as a real user would — the exploit must survive actual
workflow and state transitions.

When you discover a useful pivot (info leak, weak boundary, partial
access), immediately pursue the next step rather than stopping at
the first win.

## Mindset

Methodical and systematic. Document as you go. Validate everything
— no assumptions about exploitability. Think about business impact,
not just technical severity.
