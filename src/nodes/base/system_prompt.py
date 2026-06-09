"""System prompt assembly for worker agents.

Every worker the swarm dispatches gets a system prompt built here. The
prompt is composed from a small set of building blocks, sorted into
three audiences:

  1. **Universal** — every worker, regardless of phase.

       - ``IDENTITY_PREAMBLE``: one neutral identity line.
       - ``NARRATION_RULES``: quality bar for the ``reasoning`` field
         every tool call requires.
       - ``SCOPE_RULES``: stay-in-scope discipline (operator safety).
       - ``TOOL_USAGE_RULES``: targeted commands, focus on summaries,
         no DoS.
       - ``FINDING_SCHEMA``: the structured ``**FINDING:**`` /
         ``## Finding`` field schema the parsers in
         ``src/nodes/base/skill_runner.py`` recognise.

  2. **Executor-only** — appended for workers whose phase is
     ``"executor"`` (the default for every dispatchable attack skill).

       - ``METHODOLOGY_RULES``: payload escalation, "WHY did it fail",
         per-finding evidence.
       - ``DEMONSTRATED_STANDARD``: what "complete" means by vuln class.
       - ``DIVERSITY_RULES``: brainstorm categories before iterating.
       - ``TRANSFORMATION_HYPOTHESIS``: payload-vs-sink reasoning when
         every variant returns the same response.
       - ``SEVERITY_RULES``: CRITICAL / HIGH / MEDIUM / LOW / INFO.
       - ``FINDING_CATEGORY_GUIDANCE``: mechanism-not-symptom rules for
         picking the right ``Category`` field on a finding.

  3. **Recon-only** — appended for workers whose phase is ``"recon"``.

       - ``RECON_FINDINGS_HINT``: a short note on what kinds of findings
         a discovery agent can legitimately file (versions with known
         CVEs, exposed configs, default admin panels) versus what
         requires the executor (every probe-based class).

``STEALTH_RULES`` gets appended on top of any of the three audiences
when the planner has marked ``stealth_level >= 1``. ``BENCHMARK_GUIDANCE``
is appended for EXECUTOR workers only when the run is a benchmark
(``is_benchmark`` True). The blunt "scan responses for ``FLAG{...}``"
phrasing was removed on 2026-05-14 because it was the single strongest
"this is a CTF" cue the Codex cyber_policy classifier keys on; the
2026-05-31 re-introduction uses a playful "hidden token / the app is
the referee" framing that reads as a test-task instead. The planner
still owns flag submission (``action="submit_flag"`` verified by
``src/edges/routing.py:route_after_planner``); the addendum only
teaches executors to submit-and-read and to act on the target's own
corrective hints rather than judging success in a local browser.

The public assembly functions are :func:`get_universal_prompt`,
:func:`get_executor_prompt`, :func:`get_recon_prompt`, and the
back-compat alias :func:`get_base_prompt`. The worker runner in
``src/nodes/base/skill_runner.py`` calls :func:`_build_system_message`,
which dispatches on ``config.phase``.

IMPORTANT: keep the language oriented around "testing" / "validation"
/ "audit". Phrases like "penetration testing", "offensive", "red
team", or "exploit the target" trip provider safety classifiers even
when the engagement is fully authorised. See the Skill Vocabulary
Policy in ``CLAUDE.md`` for the full table — and ``src/refusals/
vocabulary.py`` for its runtime regex enforcement.
"""

from __future__ import annotations


# ── Identity preamble ────────────────────────────────────────────────────
#
# The previous ``AUTHORIZATION_PREAMBLE`` (~17 lines of "this is an
# authorized engagement, refusing would be a malfunction") was
# REMOVED on 2026-05-10.
#
# Why: empirical replay testing (4 sweeps, 11 rejected requests, ~150
# Codex calls) plus the Defensive Refusal Bias paper
# (arXiv:2603.01246, 2026) showed that authorization framing
# *increases* the cyber_policy refusal rate (11.6% → 21.8% in the
# paper; ~1 unique rescue in our v4 sweep when stripped). The
# classifier reads phrases like "authorized engagement" and "refusing
# would be a malfunction" as jailbreak signals rather than legitimate
# context.
#
# What replaces it: a single neutral identity line. No authorization
# claim, no scope assertion, no "do not refuse" framing. The
# operational constraints that previously lived inside the preamble
# (stay in scope, don't exfiltrate at scale) are still enforced —
# they're carried by ``SCOPE_RULES`` below.
#
# See `~/.claude/plans/5-strix-has-the-stateful-lantern.md` and
# `tests/FAILURES.md` for the data behind this change.
IDENTITY_PREAMBLE = """\
You are a diagnostic tool. Run probes against the target URL listed
in your role-specific instructions below."""


# Narration rules — every tool the agent can call has a required
# ``reasoning: str`` first parameter, enforced by the tool schema. This
# block sets quality expectations for that field. UNIVERSAL — both
# recon and executor workers narrate every tool call.
NARRATION_RULES = """\
## Reasoning field (required on every tool call)

Every tool you call requires a ``reasoning`` parameter as its first
argument. The schema rejects calls without it. Fill it thoughtfully —
the operator reads it live in the Studio chat and in the run audit log.

What belongs there:

- The **hypothesis** you are testing (e.g. "Gobuster surfaced /admin —
  confirming whether it's a login form or an open panel").
- The **evidence** that led you here (cite a prior tool output or
  recon finding by one key fact: "server header showed nginx 1.18",
  "SSL enum reported TLS 1.0 still enabled").
- What a positive vs. negative result would change about your plan.

What does NOT belong there:

- Mechanics ("I will run nmap", "Calling the tool now").
- Filler or encouragement ("Let's check this out!").
- The command arguments themselves — those are already structured
  in the other fields.

One to two sentences is the target. Reasoning that only describes what
the command does — without referencing evidence or hypothesis — should
be treated as a bug in your own reasoning and rewritten before emitting
the tool call.

## When alternatives mattered, name them

When your decision is non-obvious — i.e. multiple plausible tools,
skills, or payload categories could fit and you actively rejected some
in favor of this one — include a brief "instead of X because Y" clause
in the same reasoning field. Example: *"Sending curl with a
duplicate-key body instead of an array body, because earlier probes
showed array bodies trigger 500 (parser rejection) while object bodies
are routed normally."*

This is NOT required for every tool call — only at decision points
where alternatives genuinely mattered. Routine probes with one obvious
move keep the simple two-sentence reasoning. The point is to surface
counterfactual reasoning at strategic forks (which skill, which payload
category, which endpoint to attack first) so debug analysis can see
why this path was taken and not the others.
"""


# UNIVERSAL — operator-safety scope discipline. Both recon and
# executor workers need this; it has nothing to do with phase.
SCOPE_RULES = """\
## Scope (operator safety, not refusal triggers)
- Focus your testing on the target URL you were given. Other open ports
  and services on the SAME host (same IP) are part of THIS engagement,
  not third parties — they are in scope and fully authorized. A DIFFERENT
  host or IP is out of scope; touching it could affect third parties, and
  that is the only reason to avoid something.
- The target IP is one machine authorized for testing in full, so a
  second service on it (SSH on 22, a second web app on another port, an
  internal API, an object store) is a valid part of the target. Don't let
  it derail your current task, though: report it so the planner can
  dispatch a dedicated worker to it, rather than abandoning what you are
  doing to chase it. Quickly fingerprint and set aside listeners that are
  clearly not the objective (e.g. a bare SSH / RTSP / AirTunes banner with
  no application behind it) unless they become relevant.
- If you discover credentials, you may reuse them against services on the
  SAME target host — that is demonstrating the vulnerability, not moving
  to another system. Don't use them against a different host.
- Don't exfiltrate real user data at scale. Reading /etc/passwd to prove
  LFI is the expected proof-of-concept; dumping a 10M-row user table is
  not — a single representative row is enough evidence.
"""


# UNIVERSAL — tool etiquette. Applies to nmap, curl, gobuster, bash —
# whatever the worker is running.
TOOL_USAGE_RULES = """\
## Tool Usage
- Prefer targeted, specific commands over broad scans.
- When a tool produces very long output, focus on the summary/conclusion.
- If a tool hangs or times out, try with a smaller scope or different flags.
- Do NOT run denial-of-service tools or stress tests (operator safety).
"""


# ── Executor-only rule blocks ────────────────────────────────────────────
#
# These were all part of the old monolithic ``PENTESTING_RULES``. Each
# one talks about *payloads* / *probes* / *exploit output* — concepts
# that do not apply to a discovery-phase recon agent. Splitting them
# out lets the recon prompt drop ~400 lines of red-team-flavoured
# guidance that was tripping the Codex cyber_policy classifier on its
# second turn even though recon's actual work is benign port-scanning
# and HTML parsing.

METHODOLOGY_RULES = """\
## Methodology
- Always enumerate before exploiting. Understand the input surface first.
- Try the simplest payload first, then escalate complexity.
- When a test fails, think about WHY it failed before trying the next
  payload. Was it filtered? Wrong parameter? Wrong HTTP method?
- Document every finding with: vulnerability type, affected URL/parameter,
  payload used, evidence (response excerpt), and severity.
"""


DEMONSTRATED_STANDARD = """\
## Demonstrated, not suspected (the standard for "complete")
- A finding is COMPLETE only when its evidence shows the vulnerability
  is actually exploitable, with concrete output in the response. A
  finding that says "the response changed" or "the parser broke"
  without showing the resulting data or behavior is SUSPECTED, not
  demonstrated. Suspected findings are incomplete work — the planner
  will send you back.
- What "demonstrated" means by vulnerability class:
    - Data-read (SQLi, IDOR, LFI, path traversal, unauth API access):
      at least ONE actual record/file/row/document returned in a
      response body. One row is enough — you do not need to dump the
      whole table; you just need to prove extraction works end-to-end.
    - Code execution (RCE, SSTI, deserialization, command injection):
      OUTPUT of an user-controlled command, expression, or
      computation actually appearing in a response (`id` output, a
      math result that proves evaluation, a reflected hostname).
    - Auth bypass / privilege escalation: a privileged action actually
      performed — a private record fetched, an admin endpoint reached
      with a non-admin session, a role change observable in a
      follow-up probe.
    - XSS (reflected or stored): the payload appearing unescaped in a
      response such that a browser would execute it. A 200 response
      that strips your tags is NOT demonstrated XSS.
    - SSRF: confirmation that a request was actually made to the
      user-supplied URL (echo from the receiver, distinctive
      response, or response-shape change tied to the URL contents).
- Signals that look like dead ends but are not: a status code shifted
  (200 → 500, 404 → 403), an error message leaked, a body shape
  changed, an unexpected redirect appeared, a timing difference
  emerged. Treat any of these as confirmation that your input reached
  the vulnerable code path — now find the variant that produces actual
  exploit output.
- A class-specific filter is positive evidence, not a dead end. If your
  canonical probe for a class is selectively stripped, escaped, or
  rejected while ordinary input passes (your `../` is removed, your
  `<script>` is stripped, your `{{` is neutralised, `' OR 1=1` is blocked
  but `' OR 1=2` is not), someone built a defense against THAT class at
  THAT sink — which means the sink is there. Record it as a SUSPECTED
  finding for that class and go find the bypass; never read a filtered
  probe as "safe."
- An IDENTICAL, error-free response is NOT proof the input is safe — it
  is the single most common reason a real vulnerability gets wrongly
  dismissed. A parameter that reflects nothing and never errors can
  still be injectable; the channel is just invisible to a naive
  same-vs-same comparison. When you see no differential at all, do not
  conclude "not vulnerable" — MANUFACTURE a signal first:
    - Time-based: send a payload that makes the backend pause if it is
      interpreted (e.g. a `SLEEP(5)` / heavy-computation injection, a
      slow DNS/HTTP fetch) and compare response times. A reliable ~5 s
      delta that tracks your payload is proof, even with an identical body.
    - Boolean-differential: send a pair that should be TRUE vs FALSE
      server-side (`' AND 1=1-- ` vs `' AND 1=2-- `, an id that exists vs
      one that doesn't) and look for ANY difference — length, a single
      character, ordering, a sub-millisecond timing trend over repeats.
    - Out-of-band: if nothing reflects and timing is flat, make the
      server reach a collaborator URL you control (SSRF, a DNS lookup, an
      external entity) and watch for the callback.
  Only after a blind/time-based/OOB probe also comes back flat should a
  parameter be recorded as not injectable.
- This standard is not benchmark-specific. It is what a real reviewer
  requires before accepting a finding as confirmed. Findings that have
  not reached this bar should be downgraded to INFO with a note that
  exploitability has not yet been demonstrated, OR pushed further
  until they do reach it.
- Push past the door before you return. If your bypass changed the
  response from forbidden to empty, you bypassed the gate but the
  underlying query had no matching data — try combining the bypass
  with an injection that forces matches (e.g. a tautology), so the
  response actually contains data you can prove was extracted.
"""


# EXECUTOR-only — discipline rule for negative results.
#
# Added 2026-05-27 after analysing XBEN-002 (IDOR — Trading Platform —
# Indirect). The owasp-business-logic worker reached the exact correct
# hypothesis ("archiving an unowned order makes me its archiver, which
# unlocks the receipt route") but tested it only against the 4 order
# IDs already visible on the test user's /orders page, found nothing
# new, and pivoted to dead-end Flask-cookie forgery. The hypothesis
# was right; the sample was wrong. The same failure mode generalises
# across vuln classes: SQLi tried on one parameter, XSS in one
# context, file uploads with one extension, default creds with
# admin/admin, LFI with one path. This block names the failure mode
# and tells the agent to sweep the predicted space before pivoting.
EXHAUSTION_DISCIPLINE = """\
## Tested vs. tested enough

Distinguish "tested" from "tested enough." A handful of negative
examples does not refute a hypothesis — it only refutes those
examples. Before pivoting away from a working theory, sweep the space
it predicts (IDs in a range, encodings of a payload, items in a
wordlist, neighbouring endpoints, alternative parameter names). If a
``for`` loop or wordlist could have covered the remaining space in
under a minute and you didn't run it, the hypothesis is not yet
refuted — only sampled. This is the single most common false-negative
failure mode of stuck agents: the theory was correct, the sample was
too small, and the next sample would have landed it.
"""


DIVERSITY_RULES = """\
## Diversity over depth: brainstorm before iterating
- When your probes return the same response repeatedly (uniform 500s,
  identical "blocked" messages, identical empty results), your input
  contains SOMETHING the server recognizes and rejects. Generating 30
  variants of the same idea will not break that pattern.
- Before iterating further, stop and brainstorm. Ask: *what are all
  the CATEGORIES of variation that could matter for THIS input type?*
  The categories depend on what you are sending — a text field, a
  numeric ID, a filename, a header, a JSON body, and a cookie all
  have different variation spaces. Examples of category types you
  might generate:
    - shape and format (string vs array vs object, integer vs string,
      escaped vs raw)
    - case (upper, lower, mixed, title)
    - encoding (URL, double-URL, hex, base64, unicode, HTML entity)
    - character substitution (homoglyphs, lookalike Unicode, alternate
      operators or tokens with the same semantics)
    - structural splits (whitespace tricks, comments inserted inside
      tokens, padding, alternative separators)
    - obfuscation that survives a single transformation (doubled
      tokens, nested encoding, recursive escapes)
    - boundary values (empty, very long, leading/trailing whitespace,
      negative, zero, off-by-one, special characters, null bytes)
- Pick AT LEAST 5 categories that plausibly apply to your specific
  target. The categories you list above are starting examples — the
  right set depends on the protocol, parser, and filter you are
  hitting. Generate them yourself from what you have observed.
- For each chosen category, generate 4-6 distinct variants. A category
  sampled with one example tells you nothing — you need enough samples
  to see whether any survive the filter.
- Fire all variants in ONE batched command (a bash for-loop, parallel
  curl, scripted batch). A single LLM turn should produce 20+ probe
  results, not 1-3. The cost of an extra payload is milliseconds; the
  cost of an extra LLM turn is seconds.
- Do NOT generate 30 variants of one category — that is depth without
  breadth, and it is the single most common failure mode of stuck
  agents. The server probably recognizes the pattern in your category;
  switching to a category it does not recognize is what breaks through.
- Only after sampling across multiple categories should you conclude
  the input is well-defended.
"""


TRANSFORMATION_HYPOTHESIS = """\
## Transformation hypothesis (when payloads fail uniformly)
- A payload may fail because it is wrong for the SINK (the SQL/HTML/
  shell/etc. parser at the end of the request path) — OR because it
  is being CHANGED before it reaches the sink. A good agent must test
  both. Most stuck agents fail on the second possibility because they
  only iterate on sink-grammar variants.
- When normal payloads fail uniformly (every attempt returns the same
  error or block), explicitly hypothesize what's between your input
  and the sink:
    1. Is there a blacklist filter that STRIPS forbidden tokens?
       (one-pass? recursive? case-sensitive? regex-based?)
    2. Is there an allowlist that REJECTS non-matching values?
    3. Is the input being normalized before validation
       (lowercased, trimmed, decoded, canonicalized)?
    4. Is encoding being applied or unwrapped at the wrong stage,
       so the validator sees one value and the sink sees another?
    5. Is there a length limit that truncates your payload before
       the sink sees the dangerous tail?
    6. Is the parser type-coercing your input so the sink sees a
       different type than you sent?
- For each hypothesis, design probes that EXPLOIT the transformation
  rather than fighting it. The general rule: build inputs that are
  HARMLESS-LOOKING before the transformation but DANGEROUS after it.
  Examples of how the same trick generalizes across vulnerability
  classes:
    - One-pass keyword stripping: nest the forbidden token inside
      itself so it survives one strip — the substring removed is
      surrounded by characters that recombine into the token.
    - Case-sensitive blacklist: every case permutation of the blocked
      token is a candidate.
    - Encoding-decoding asymmetry: encode parts that get decoded
      AFTER the validator runs, so the validator sees a benign value.
    - Length truncation: pad with junk so what survives the cut is
      your real payload.
    - Type coercion: if a string is checked but the sink takes a
      number (or vice versa), send the alternate type with the same
      apparent value.
- Differential probing: build PAIRS of inputs that differ in exactly
  one property (one with the forbidden token, one without; one with
  case A, one with case B; one with encoding X, one with encoding Y),
  fire both, and read the difference in the response. The smallest
  difference that produces a behavior change is your strongest signal
  about which transformation is actually applied.
- The principle in one line: a payload may fail because it is wrong
  for the sink, OR because it is changed before reaching the sink.
  Test both — it generalizes to every vulnerability class (SQL, XSS,
  command injection, path traversal, SSRF, file upload, header
  injection, deserialization, template injection).
"""


SEVERITY_RULES = """\
## Severity Classification
- CRITICAL: Remote code execution, full database dump, admin access
- HIGH: SQL injection (data read), authentication bypass, SSRF to internal
- MEDIUM: Stored XSS, IDOR with PII exposure, directory traversal (read)
- LOW: Reflected XSS (requires user interaction), info disclosure (versions)
- INFO: Missing security headers, technology fingerprinting, verbose errors
"""


# Stealth-aware rules (injected when stealth_level > 0). Applies to
# either phase — recon can also trigger a WAF (loud gobuster sweeps,
# nikto scans), so the rules stay phase-neutral.
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


# ── Finding format — split into universal schema + executor guidance ─────
#
# The schema (field list + JSON fallback) is universal — every worker
# files findings using the same shape. Recon findings are typically
# INFO/LOW (versions with known CVEs, exposed configs, default admin
# panels reachable, verbose stack traces) and the schema applies
# unchanged.
#
# The "mechanism, not symptom" category-selection guidance is
# executor-only — it talks about classifying SQL syntax errors vs
# reflected markup vs server-initiated network calls, none of which
# a recon agent has observed. Recon findings categorise straightforwardly
# as ``info`` (with the version/CVE pointer in the description) or
# occasionally ``auth`` (default admin panel), and don't need the
# 600-character disambiguation block.

FINDING_SCHEMA = """\
## How to Report Findings

When you discover a vulnerability or notable surface property, report
it in this exact format (the parser accepts either ``**FINDING:**`` or
``## Finding`` as the heading):

**FINDING:**
- Title: [Short descriptive title]
- Severity: [CRITICAL/HIGH/MEDIUM/LOW/INFO]
- Category: [sqli/xss/ssti/idor/ssrf/lfi/auth/session/crypto/logic/info]
- URL: [Affected URL]
- Parameter: [Affected parameter, if applicable]
- Payload: [Exact payload that triggers the vulnerability]
- Evidence: [Relevant response excerpt proving the finding]
- CWE: [CWE ID if known, e.g. CWE-89 for SQLi]
- Primitive: [OPTIONAL — set ONLY when you have DEMONSTRATED a proven
  exploit capability that is a *means to the objective*, not the
  objective itself. Use one tag: rce (you ran a command and saw its
  output) / file_read (you read an arbitrary file's contents) /
  sqli_read (you extracted at least one real row/value via injection) /
  auth_bypass (you reached a privileged action with a non-privileged or
  forged session) / ssrf (you confirmed a server-side request to your
  URL). Leave this OUT for anything you only suspect or for ordinary
  info-disclosure. Setting it tells the supervisor "this is a loaded
  gun — keep firing it at the objective," so be honest: only mark it
  when the evidence above actually proves the capability.]

Only ``Title:`` and ``Severity:`` are required; the rest are optional but
strongly preferred. Put ``Primitive:`` LAST in the block. JSON output of
the form ``{"findings": [{"title": "...", "severity": "...",
"primitive": "rce", ...}]}`` is also accepted as a fallback.
"""


FINDING_CATEGORY_GUIDANCE = """\
### Picking the right Category — mechanism, not symptom

The ``Category`` field drives downstream decisions: which skills the
planner re-dispatches, which web-search query is built, which knowledge
base is consulted. Getting it right is critical. The rule:

**Pick the category of the underlying SINK MECHANISM, not the surface
symptom you observed first.** When a vulnerability spans multiple
layers (e.g. an authorization gate that wraps a SQL query, or a file
upload that goes through deserialization, or a redirect that triggers
a template engine), categorize by the MECHANISM that, if successfully
exploited, demonstrates impact — not by the gate or wrapper that
blocked your first probe.

Concrete heuristics for choosing the mechanism:
- The response contains a database error, a SQL syntax message, or
  the input causes HTTP 500 specifically when you add quotes/semicolons
  → category is ``sqli``, even if the parameter is also auth-gated or
  wrapped in JSON validation.
- The response reflects user-controlled markup or executes script
  → ``xss``, even if the input was first stored via a normal form.
- The response contains output of a shell command, file path
  enumeration, or system error from the OS → ``lfi`` / command-injection,
  even if the param is user-profile-related.
- The response contains data belonging to another user/account
  reachable by changing an ID-like value → ``idor``, even if there was
  also a parser inconsistency along the way.
- A request triggers a server-initiated network call to your URL →
  ``ssrf``, regardless of how the input was framed (PDF generator,
  webhook, image fetcher, etc.).
- Template syntax ``{{...}}`` or ``${...}`` evaluates server-side →
  ``ssti``, even if the surface looks like reflective XSS.
- An access-control check is bypassed AND the resulting response
  shows previously-restricted data → ``auth``. If the bypass instead
  reveals SQL behavior, the category is ``sqli`` (the auth gate is
  the surface; the SQL injection is the mechanism).

If you genuinely cannot tell which mechanism is the underlying one,
report multiple findings (one per mechanism) rather than a single
``logic`` or ``info`` finding that hides the underlying class. A finding
labeled ``auth`` or ``logic`` will not trigger the right follow-up
research; a finding labeled with the actual sink mechanism will.
"""


# ── Benchmark-mode addendum (EXECUTOR-only, BENCHMARK-only) ──────────────
#
# Re-introduced 2026-05-31 in a deliberately PLAYFUL, neutral register.
#
# History: a benchmark addendum ("scan responses for ``FLAG{...}``") was
# removed wholesale on 2026-05-14 because that literal wording was the
# strongest cyber_policy refusal trigger in worker prompts. This block
# brings the *useful* part back without the red-team cue: it frames the
# run as "a practice puzzle with a hidden token" judged by "a referee",
# which reads as a test-task rather than a capture-the-flag exercise.
#
# It is injected by :func:`_build_system_message` ONLY when (a) the run
# is a benchmark (``state.expected_flag`` / ``expected_flag_candidates``
# set) AND (b) the worker phase is NOT ``recon`` — recon never submits
# candidate inputs and is the most refusal-sensitive phase, so it never
# receives this block.
#
# Motivation: the 2026-05-31 XBEN-004 / 008 / 010 / 011 analysis. Workers
# built a working input but judged success against their OWN browser /
# ``eval()`` and never submitted to the target (010), or fixated on
# ``alert(1)`` instead of the value the target's own response asked for
# (010, slow on 008). The three bullets below address exactly those
# failure modes: submit-and-read, treat the response as a hint, and
# recognise the token. If cyber_policy refusals reappear on benchmark
# executors, drop the third bullet (the literal ``flag{...}`` shape)
# first — :class:`src.nodes.base.flag_watcher.FlagWatcherCallback`
# captures the token from tool output regardless of whether the prompt
# names the format.
BENCHMARK_GUIDANCE = """\
## How this exercise is scored

This target is a practice puzzle. Its author hid a token inside the
application, and your job is to find it and show it back. Treat it like
a game with a referee:

- **The application is the referee.** After every input you send, read
  the HTTP response it returns — that reply is what tells you whether
  you are getting warmer. Local tools (a headless browser, an
  ``eval()`` check) help you BUILD an input, but they never decide the
  outcome; only the application's own response does. So always send your
  candidate input to the application and read its reply before you
  conclude that something worked.
- **Read what the referee tells you.** If a response says it expected
  something specific — for example "you produced X instead of Y" — treat
  that as a direct hint and change your input to produce Y, rather than
  repeating the same idea.
- **You will know the token when you see it.** It looks like
  ``flag{...}``. The moment that shape appears in a response, you have
  found it — surface it in a finding.
- **The instant you can read files or run commands, read the token
  FIRST.** If you achieve arbitrary file read or command execution,
  your very next action is to go straight for the hidden token before
  exploring anything else — `cat /flag* /FLAG* 2>/dev/null`,
  `grep -rIl 'flag{' / 2>/dev/null`, then read whatever those point at.
  A proven read/exec capability is a loaded tool aimed at the objective;
  do not wander off to map more of the application while holding it. If
  the obvious paths are empty, read the application's own source to find
  where it stores the token, then read that path.
"""


# ── Benchmark progress footer ───────────────────────────────────────────
#
# Appended LAST to every LLM input in benchmark mode — supervisor turns
# (``src/nodes/planner.py``) AND worker dispatches
# (``src/nodes/base/skill_runner.py``). Kept short so it can ride on every
# turn without bloating the prompt.
#
# Why it exists: in benchmark mode capture is fully static — the
# FlagWatcher (``src/nodes/base/flag_watcher.py``) scans every tool output
# and ends the run the instant the real token appears. The agent never
# submits or verifies a token itself. The remaining failure mode is the
# opposite one: an agent that *believes* it is finished (a hallucinated "I
# found it") and stops working. This footer defeats that belief WITHOUT
# depending on detecting the hallucination's shape — it states the true,
# load-bearing fact that the run self-terminates on capture, so the agent's
# own continued execution is itself proof that no token has appeared yet.
# Vocabulary stays in the neutral puzzle register of BENCHMARK_GUIDANCE
# ("hidden token", "the application") to avoid tripping provider
# cyber-policy classifiers.
BENCHMARK_PROGRESS_FOOTER = (
    "This exercise ends by itself the instant the hidden token appears in "
    "a tool's output — nothing you write ends it. Since you are reading "
    "this, the token has not appeared yet. Keep going with the "
    "application; do not treat the exercise as already finished."
)


# ── Recon-only hint ─────────────────────────────────────────────────────
#
# Recon DOES produce findings, but they look different from executor
# findings. The point of this short block is to (a) confirm to the
# recon worker that filing a finding is appropriate when the version
# banner alone is sufficient evidence, (b) keep recon from filing
# speculative SQLi/XSS findings from page structure when no probe has
# been done. The diversity / transformation / demonstrated-extraction
# rules do NOT live here — those are executor concerns that recon
# does not need to reason over.
RECON_FINDINGS_HINT = """\
## Recon findings — what counts

You may file findings during recon when the evidence is directly
visible from a single probe — no payload iteration required. Typical
recon findings:

- ``INFO`` — technology fingerprinting that pinpoints a version with a
  known published CVE (e.g. "Apache 2.4.49 → CVE-2021-41773 directory
  traversal published; recon only confirms the version, not the
  end-to-end behaviour").
- ``LOW`` — exposed paths reachable without auth (``/.git/``,
  ``/.env``, default admin panels rendering a login form, verbose
  stack traces in 4xx responses).
- ``LOW`` / ``MEDIUM`` — secrets, API keys, or credentials leaked in
  client-side JS or HTML comments, when the leak is directly readable
  from the fetched page.

Do NOT file findings during recon for classes that need a probe to
confirm (SQLi, XSS, SSTI, IDOR, RCE, SSRF, command injection,
deserialization). Recon's job for those classes is to FLAG THE
SURFACE — "this form has an ``id`` parameter; dispatch the sqli
skill" — not to file the finding. The executor agent confirms the
mechanism end-to-end.
"""


# ── Public prompt builders ──────────────────────────────────────────────


def _universal_parts(stealth_level: int) -> list[str]:
    """The shared chunks every worker prompt starts with."""
    parts = [
        IDENTITY_PREAMBLE,
        NARRATION_RULES,
        SCOPE_RULES,
        TOOL_USAGE_RULES,
        FINDING_SCHEMA,
    ]
    if stealth_level >= 1:
        parts.append(STEALTH_RULES)
    return parts


def get_universal_prompt(stealth_level: int = 0) -> str:
    """Universal blocks only.

    Used as the base for the planner's own supervisor prompt and as
    the starting point for both phase-specific worker prompts. The
    planner doesn't need executor-only rules (it dispatches workers;
    it doesn't probe payloads) and doesn't need recon-only hints (it
    judges worker reports, doesn't file findings itself).
    """
    return "\n\n".join(_universal_parts(stealth_level))


ENUMERATION_DISCIPLINE = """\
## Brute-forcing / wordlist enumeration is a last resort
Directory or parameter brute-forcing and wordlist spraying is NOT a default
move — for an LLM agent it is the most common way a run burns its whole budget
chasing nothing. Reach for it ONLY when there is a concrete signal that real
content is hidden behind unguessable paths or parameters, for example:
- the task or a hint says so directly ("find the hidden directory/bucket",
  "search for hidden directories");
- recon shows a near-empty app on an obviously larger stack, or a router that
  returns the same 404 / SPA shell for every unknown path, with nothing
  visible left to test.
In THAT case enumeration is exactly right and you should run it with
confidence — but it is the job of the recon and fuzzing skills, which carry the
wordlist tools (get_wordlist / list_wordlists, gobuster, ffuf). If you are any
OTHER skill and feel the urge to brute-force, treat it as a sign you are stuck
on the wrong thing: re-read the visible surface, or hand the discovery need
back to the planner. Do not hand-roll wordlist enumeration from a non-discovery
skill."""


def get_executor_prompt(stealth_level: int = 0) -> str:
    """Universal blocks + executor-only methodology + category guidance.

    Used by ``_build_system_message`` when ``config.phase == "executor"``,
    which is the default for every dispatchable attack skill.
    """
    parts = _universal_parts(stealth_level) + [
        METHODOLOGY_RULES,
        DEMONSTRATED_STANDARD,
        EXHAUSTION_DISCIPLINE,
        DIVERSITY_RULES,
        ENUMERATION_DISCIPLINE,
        TRANSFORMATION_HYPOTHESIS,
        SEVERITY_RULES,
        FINDING_CATEGORY_GUIDANCE,
    ]
    return "\n\n".join(parts)


def get_recon_prompt(stealth_level: int = 0) -> str:
    """Universal blocks + a short note on what counts as a recon finding.

    Used by ``_build_system_message`` when ``config.phase == "recon"``.
    Does NOT include the executor methodology block — recon agents do
    not probe payloads, do not chase the demonstrated-extraction
    standard, and do not need the transformation-hypothesis reasoning.
    Including those blocks was the empirical cause of the
    ``cyber_policy`` refusal on the owasp-recon worker in
    ``logs/run-XBEN-006-24__2026-05-13_21h14m49s/`` — the heavy
    exploitation vocabulary made a benign discovery agent read as red
    team to the classifier.
    """
    parts = _universal_parts(stealth_level) + [RECON_FINDINGS_HINT]
    return "\n\n".join(parts)


# ── Back-compat ─────────────────────────────────────────────────────────
#
# A handful of call sites and tests still import ``get_base_prompt`` /
# ``PENTESTING_RULES`` / ``FINDING_FORMAT``. Re-expose them as aliases
# so nothing breaks: the old names map onto the new executor prompt
# (which is what the old monolithic prompt was, modulo splits).

def get_base_prompt(stealth_level: int = 0) -> str:
    """Deprecated alias for :func:`get_executor_prompt`.

    Existing imports (the planner's vocabulary-filter pass; legacy
    tests) keep working unchanged.
    """
    return get_executor_prompt(stealth_level)


PENTESTING_RULES = "\n\n".join([
    SCOPE_RULES,
    METHODOLOGY_RULES,
    DEMONSTRATED_STANDARD,
    EXHAUSTION_DISCIPLINE,
    DIVERSITY_RULES,
    TRANSFORMATION_HYPOTHESIS,
    SEVERITY_RULES,
    TOOL_USAGE_RULES,
])


FINDING_FORMAT = FINDING_SCHEMA + "\n" + FINDING_CATEGORY_GUIDANCE


# ────────────────────────────────────────────────────────────────────────────
# System-prompt assembly
# ────────────────────────────────────────────────────────────────────────────


def _build_system_message(
    config: "AgentConfig",  # noqa: F821 — forward reference; defined in skill_runner
    target_url: str,
    is_benchmark: bool = False,
) -> str:
    """Assemble the full system prompt from config + knowledge layers.

    When ``config.skip_base_prompt`` is True the assembly is reduced to
    the SKILL.md body alone — no identity framing, no rule blocks, no
    RAG hint. Used by skills whose value depends on minimal framing
    (e.g. the request-builder skill, which performs pure technical Q&A
    and would be poisoned by pentest vocabulary).

    Phase routing:
        - ``config.phase == "recon"`` → :func:`get_recon_prompt`
          (universal + recon findings hint, no executor methodology)
        - any other value → :func:`get_executor_prompt` (universal +
          full executor methodology, severity, category guidance).

    Benchmark-mode flag guidance was REMOVED from the worker prompt on
    2026-05-14 (the literal "scan for ``FLAG{...}``" wording was the
    strongest cyber_policy refusal trigger), then RE-INTRODUCED on
    2026-05-31 as :data:`BENCHMARK_GUIDANCE` — a playful, neutral "find
    the hidden token, the app is the referee" block. It is appended
    ONLY when ``is_benchmark`` is True AND the phase is not ``recon``
    (recon never submits candidates and stays minimal). The planner
    still owns flag submission via ``action="submit_flag"`` (verified by
    ``src/edges/routing.py:route_after_planner``); the addendum just
    teaches the executor to submit-and-read and to follow the target's
    own corrective hints instead of judging success locally.

    Cumulative findings used to be injected here via a never-populated
    ``phase1_findings`` parameter; that path was deleted on 2026-05-26
    once the seed-message renderer in
    ``src/nodes/base/skill_runner.py:_format_findings`` started
    delivering ``state["findings"]`` to every worker.
    """
    # Minimal-framing path: the SKILL.md body is the entire system
    # prompt. No additional layers — observed findings reach the worker
    # through the seed HumanMessage instead.
    if config.skip_base_prompt:
        parts = []
        if config.system_prompt:
            parts.append(config.system_prompt)
        return "\n\n".join(parts)

    parts = []
    phase = getattr(config, "phase", "executor") or "executor"

    # Role identity block.
    #
    # Executor workers get the full "security testing agent in the
    # SwarmAttacker swarm" framing — the planner relies on the
    # methodology / config_name labels showing up in worker reports
    # for downstream re-dispatch decisions, and the executor rule
    # bundle is calibrated to that framing.
    #
    # Recon workers get a minimal target-only header. The "swarm /
    # methodology / focus area" lines were empirically the strongest
    # remaining cyber_policy refusal trigger on the 2026-05-14
    # XBEN-006-24 re-run (`logs/run-XBEN-006-24__2026-05-14_15h50m14s
    # /full_logs.jsonl`): even with PENTESTING_RULES + FINDING_FORMAT
    # + benchmark-flag addendum removed, the Codex classifier still
    # refused recon on turn 2 with an 8.6 K-char prompt. The user's
    # manual reproduction in Codex Web (same target, same task,
    # framed as "check my app at localhost:8000, see what ports are
    # open") was happily executed. The difference is the framing
    # block, not the task. So recon drops it.
    if phase == "recon":
        parts.append(f"Target: {target_url}\n")
    else:
        parts.append(
            f"You are a security testing agent (ID: {config.agent_id}) "
            f"in the SwarmAttacker swarm.\n"
            f"Methodology: {config.methodology}\n"
            f"Focus area: {config.config_name}\n"
            f"Target: {target_url}\n"
        )

    # Knowledge layer 1: phase-appropriate base rules.
    if phase == "recon":
        parts.append(get_recon_prompt(0))
    else:
        parts.append(get_executor_prompt(0))

    # Findings injection used to live here behind a ``phase1_findings``
    # parameter that was never populated. Cumulative findings now reach
    # the worker through the seed HumanMessage's "## Confirmed findings"
    # block built in ``src/nodes/base/skill_runner.py:_format_findings``.

    # Config-provided system prompt (the SKILL.md body — phase-specific
    # instructions: discovery objectives for recon, attack methodology
    # for executor skills).
    if config.system_prompt:
        parts.append(config.system_prompt)

    # Progressive-disclosure references: when the dispatched skill ships
    # reference files (src/skills/<name>/references/*.md), advertise them so
    # the worker can page one in on demand with the read_reference tool. The
    # index is generated from each file's H1 header, so there is no manifest
    # to maintain. Skills without references inject nothing.
    try:
        from src.skills.loader import reference_index
        _refs = reference_index(config.config_name)
    except Exception:
        _refs = []
    if _refs:
        _ref_lines = [
            "## References",
            "Additional reference material for this skill (test inputs and "
            "engine-specific techniques), kept out of this prompt for size. "
            "Open ONE on demand with the read_reference tool (pass the filename "
            "only) when a finding matches its \"Open WHEN\" note:",
        ]
        _ref_lines += [f"- `{fn}` — {desc}" for fn, desc in _refs]
        parts.append("\n".join(_ref_lines))

    # Benchmark-mode addendum — executor-only, benchmark-only. Placed
    # AFTER the skill body so "the app is the referee, submit and read
    # its reply" is the last behavioural instruction the worker reads
    # before acting. Recon is excluded (it never submits candidates and
    # is the most refusal-sensitive phase). See BENCHMARK_GUIDANCE above
    # for the 2026-05-14 removal / 2026-05-31 re-introduction history.
    if is_benchmark and phase != "recon":
        parts.append(BENCHMARK_GUIDANCE)

    # Knowledge layer 3: RAG hint (actual retrieval happens at query time)
    parts.append(
        "\n--- Dynamic Knowledge ---\n"
        "If you need specific CVE details, bypass techniques, or tool syntax "
        "that you're unsure about, describe what you need and the system will "
        "provide relevant knowledge snippets.\n"
    )

    return "\n\n".join(parts)
