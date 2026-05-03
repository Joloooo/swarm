---
name: scan-mode-deep
description: Use when the engagement justifies maximum coverage and depth — exhaustive enumeration, every parameter / endpoint / edge case, business-logic deep-dives, advanced techniques (HTTP request smuggling, cache poisoning, prototype pollution, subdomain takeover, GraphQL-specific attacks), vulnerability chaining for amplified impact, persistent retry of failed paths, and patient end-to-end exploitation-path discovery. Reference-only methodology preset that planner agents consult before dispatching attack skills, with hierarchical horizontal-fan-out agent strategy (component → feature → vulnerability).
---

# Deep Scan Mode

Exhaustive security assessment. Maximum coverage, maximum depth.
Finding what others miss is the goal.

This skill is **reference-only** — it has no `agent_id` and is not
dispatched as an attack agent. The planner consults it when the
engagement allows for extended runtime and maximum thoroughness.

## When to pick this mode

- Engagement window measured in days, not hours.
- High-value target — financial, healthcare, identity, critical
  infrastructure.
- Bug-bounty-style assessment where novelty / chaining matters.

## Approach

Thorough understanding before exploitation. Test every parameter,
every endpoint, every edge case. Chain findings for maximum impact.

## Phase 1: Exhaustive reconnaissance

**Whitebox (source available)**:
- Map every file, module, and code path in the repository.
- Trace all entry points from HTTP handlers to database queries.
- Document all authentication mechanisms and implementations.
- Map authorization checks and access-control model.
- Identify all external service integrations and API calls.
- Analyze configuration for secrets and misconfigurations.
- Review database schemas and data relationships.
- Map background jobs, cron tasks, async processing.
- Identify all serialization / deserialization points.
- Review file handling — upload, download, processing.
- Understand the deployment model and infrastructure assumptions.
- Check all dependency versions against CVE databases.

**Blackbox (no source)**:
- Exhaustive subdomain enumeration with multiple sources and tools.
- Full port scanning across all services.
- Complete content discovery with multiple wordlists.
- Technology fingerprinting on all assets.
- API discovery via docs, JavaScript analysis, fuzzing.
- Identify all parameters — including hidden and rarely-used ones.
- Map all user roles with different account types.
- Document rate limiting, WAF rules, security controls.
- Document complete application architecture as understood from
  outside.

## Phase 2: Business-logic deep dive

Create a complete storyboard of the application:

- **User flows** — document every step of every workflow.
- **State machines** — map all transitions (Created → Paid →
  Shipped → Delivered).
- **Trust boundaries** — identify where privilege changes hands.
- **Invariants** — what rules should the application always
  enforce.
- **Implicit assumptions** — what does the code assume that might
  be violated.
- **Multi-step attack surfaces** — where can normal functionality
  be abused.
- **Third-party integrations** — map all external service
  dependencies.

Use the application extensively as every user type to understand
the full data lifecycle.

## Phase 3: Comprehensive attack-surface testing

Test every input vector with every applicable technique.

**Input handling** (dispatch `sqli`, `xss`, `lfi`, `ssti`, `rce`,
`xxe`, `input-validation`):
- Multiple injection types — SQL, NoSQL, LDAP, XPath, command,
  template.
- Encoding bypasses — double encoding, Unicode, null bytes.
- Boundary conditions and type confusion.
- Large payloads and buffer-related issues.

**Authentication & session** (dispatch `auth-testing`,
`session-mgmt`, `csrf`):
- Exhaustive brute-force protection testing.
- Session fixation, hijacking, prediction.
- JWT / token manipulation.
- OAuth flow abuse scenarios.
- Password-reset vulnerabilities — token leakage, reuse, timing.
- MFA bypass techniques.
- Account enumeration through all channels.

**Access control** (dispatch `idor`, `bfla`):
- Test every endpoint for horizontal and vertical access control.
- Parameter tampering on all object references.
- Forced browsing to all discovered resources.
- HTTP method tampering (GET vs. POST vs. PUT vs. DELETE).
- Access control after session-state changes (logout, role change).

**File operations** (dispatch `insecure-file-uploads`, `lfi`,
`xxe`):
- Exhaustive file-upload bypass — extension, content-type, magic
  bytes.
- Path traversal on all file parameters.
- SSRF through file inclusion.
- XXE through all XML parsing points.

**Business logic** (dispatch `business-logic`, `race-conditions`):
- Race conditions on all state-changing operations.
- Workflow bypass on every multi-step process.
- Price / quantity manipulation in transactions.
- Parallel-execution attacks.
- TOCTOU (time-of-check / time-of-use) vulnerabilities.

**Advanced techniques** (custom skills as needed):
- HTTP request smuggling (multiple proxies / servers).
- Cache poisoning and cache deception.
- Subdomain takeover (dispatch `subdomain-takeover`).
- Prototype pollution (JavaScript applications).
- CORS misconfiguration exploitation.
- WebSocket security testing.
- GraphQL-specific attacks (introspection, batching, nested
  queries).

## Phase 4: Vulnerability chaining

Individual bugs are starting points. Chain them for maximum impact:

- Combine information disclosure with access-control bypass.
- Chain SSRF to reach internal services.
- Use low-severity findings to enable high-impact attacks.
- Build multi-step attack paths that automated tools miss.
- Cross component boundaries: user → admin, external → internal,
  read → write, single-tenant → cross-tenant.

**Chaining principles**:
- Treat every finding as a pivot point — ask "what does this unlock
  next?"
- Continue until reaching maximum privilege / data exposure /
  control.
- Prefer end-to-end exploit paths — initial foothold → pivot →
  privilege gain → sensitive action / data.
- Validate chains by executing the full sequence.
- When a pivot is found, spawn focused agents to continue the
  chain in the next component.

## Phase 5: Persistent testing

When initial attempts fail:

- Research technology-specific bypasses.
- Try alternative exploitation techniques.
- Test edge cases and unusual functionality.
- Test with different client contexts.
- Revisit areas with new information from other findings.
- Consider timing-based and blind exploitation.
- Look for logic flaws that require deep application understanding.

## Phase 6: Comprehensive reporting

- Document every confirmed vulnerability with full details.
- Include all severity levels — low findings may enable chains.
- Complete reproduction steps and working PoC.
- Remediation recommendations with specific guidance.
- Note areas requiring additional review beyond current scope.

## Agent strategy (deep mode specific)

After reconnaissance, decompose the application hierarchically and
fan out aggressively:

1. **Component level** — Auth System, Payment Gateway, User
   Profile, Admin Panel.
2. **Feature level** — Login Form, Registration API, Password
   Reset.
3. **Vulnerability level** — SQLi Agent, XSS Agent, Auth Bypass
   Agent.

Spawn specialized agents at each level. Scale horizontally to
maximum parallelization:
- Do NOT overload a single agent with multiple vulnerability types.
- Each agent focuses on one specific area or vulnerability type.
- Creates a massive parallel swarm covering every angle.

## Mindset

Relentless. Creative. Patient. Thorough. Persistent.

This is about finding what others miss. Test every parameter, every
endpoint, every edge case. If one approach fails, try ten more.
Understand how components interact to find systemic issues.
