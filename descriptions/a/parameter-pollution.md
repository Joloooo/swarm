# parameter-pollution — when to use

This skill is the home for **request-shape manipulation that defeats an access or
filter check** — its core is HTTP Parameter Pollution (duplicate query/body/header
params, scalar-vs-array shape, JSON duplicate keys, parser-precedence differentials
between WAF/gateway and app), and it is also the right route for the sibling case of
**HTTP method / verb tampering**, where the security check is bound to one request
verb (usually `GET`) and the app serves the protected content under a different verb.

The one concrete lesson the runs give us is sharp and worth stating up front: **a
single resource that answers `401`/`403` to `GET` but `200` to `OPTIONS` (or `HEAD`,
`POST`, `PUT`) is an access-control gate tied to the verb, not to the resource.** In
XBEN-054 the entire challenge was won the instant an `OPTIONS /` request returned the
protected page (flag inline) while `GET /` was still behind HTTP Basic auth. The tell
is observable in recon, before any "real" exploitation — fire on the *discrepancy
between request shapes*, not on a confirmed bypass.

## Trigger signals (dispatch this skill the moment you observe…)

- **A resource returns `401`/`403` to `GET` but `200` to a different HTTP method.**
  `GET /` → `401 Authorization Required` with `WWW-Authenticate: Basic realm="..."`,
  yet `OPTIONS /` (or `HEAD` / `POST` / `PUT` / a made-up verb like `FOO`) returns the
  real page body. The auth check is wired to the verb → method-tamper, route here.
  This is the exact XBEN-054 signal.
- **Recon "every path returns the same `401`" + a uniform body length.** When gobuster
  reports *"the server returns a status code that matches the provided options for non
  existing urls … 401 (Length: 401)"*, the front gate is a blanket auth filter. A
  blanket filter on one verb is the prime candidate for verb-tampering or for a
  parameter that flips the check. Probe alternate methods immediately.
- **A login / auth gate framed as "bypass the login form" with no obvious creds path.**
  The benchmark goal is to get *past* an authentication boundary (not to read a
  neighbouring object). When the gate looks monolithic — Basic auth, a single login
  POST — and there is no IDOR-style id to walk, test whether the gate is shape-bound
  (verb, duplicate param, array vs scalar) before assuming sqli/brute force.
- **An old/permissive server banner sitting in front of the gate.** `Server: Apache/2.2.34
  (Unix) … DAV/2` (XBEN-054). DAV-enabled and legacy Apache configs frequently scope an
  `<Limit GET POST>` directive to named methods only, leaving every other verb
  unprotected — the textbook method-tamper misconfiguration.
- **Duplicate-parameter or shape sensitivity (inferred — HPP core).** Sending
  `p=A&p=B` and the app acts on a different copy than the WAF; `id=1&id=2` returns
  *another* user's data; `p[]=a&p[]=b` is accepted where `p=a` was rejected; a JSON body
  with two identical keys changes behaviour. Any disagreement about "which copy wins"
  routes here. *(inferred — not observed in these logs; from the skill's HPP scope.)*
- **A WAF/filter that blocks a payload only in its canonical shape (inferred).** A
  rule fires on `?q=<sqli>` but not on `?q=benign&q=<sqli>` (last-wins backend), or on
  a single header but not a duplicated one (`X-Forwarded-For: a` vs two copies). *(inferred.)*

## Use-case scenarios

- **Login-bypass / "get past the auth gate" challenges where the gate is monolithic.**
  This is the validated XBEN-054 situation: a Basic-auth wall (or single login form)
  with no creds, no leaked id, no injectable field on the GET surface. The cheapest,
  highest-value first move is to ask whether the gate cares about the *verb* — replay
  the request as `OPTIONS`, `HEAD`, `POST`, `PUT`, `DELETE`, `TRACE`, and a nonsense
  method, and watch for a status drop from `401`/`403` to `200`. The protected content
  (and, in CTF/benchmark targets, the flag) is often served verbatim under the
  unguarded verb.
- **Legacy Apache / IIS / nginx fronting protected content.** When recon fingerprints an
  old server (Apache 2.2.x, DAV modules, IIS with WebDAV) guarding a directory, the auth
  is commonly enforced by a method-scoped directive (`<Limit GET>`, `<LimitExcept>`)
  that an author got backwards. Verb tampering is the canonical exploit; this skill owns it.
- **Right after recon reveals a blanket `401`/`403` on a single verb.** Do not pivot
  straight to brute-forcing credentials or to gobuster-with-auth. The "all paths 401,
  identical length" recon shape is itself the signal — it means the filter is generic
  and probably verb-bound. Spend two requests on method tampering first.
- **Parser-precedence / WAF-evasion contexts (inferred, HPP core).** Multi-layer stacks
  (CDN → WAF → gateway → framework) where you suspect two parsers disagree: smuggle an
  injection past the WAF by duplicating the parameter, override an authorization `id`
  by sending it twice, or trigger mass assignment via duplicate/array-shaped fields.
  These are the skill's primary designed use; they were not exercised in the logs read here.

## Concrete tells (request → response examples)

- **The validated method-tamper tell (XBEN-054):**
  - `curl -v http://target/` → `HTTP/1.1 401 Authorization Required`,
    `WWW-Authenticate: Basic realm="Protected Area"`, `Server: Apache/2.2.34 (Unix) … DAV/2`.
  - `curl -i -X OPTIONS http://target/` → `HTTP/1.1 200`, full HTML page
    (`<title>AUTH 07</title> … Welcome Admin … here is the flag: FLAG{...}`).
  - The status flip on the *same URL* under a *different method* is the confirmation. No
    further exploitation was needed — the protected body came back inline.
- **Recon shape that precedes it (XBEN-054):** gobuster aborts with *"the server returns
  a status code that matches the provided options for non existing urls. … => 401
  (Length: 401)"* — a uniform `401` on every path is the "blanket verb-bound filter"
  fingerprint. Follow it with method tampering, not deeper directory busting.
- **A general scan tool can stumble into it.** In one XBEN-054 run the flag was captured
  not by a hand-written `OPTIONS` probe but by `nikto`, which issues non-GET methods as
  part of its checks and surfaced the `200` page. If a generic scanner returns protected
  content the GET-based crawl never saw, that is the same verb-tamper signal — route here.
- **HPP tells (inferred):** `?id=1&id=2` returns user 2's record while logs show the
  auth check ran against user 1; `q=1' OR '1'='1` blocked but `q=x&q=1' OR '1'='1` passes;
  a JSON body `{"role":"user","role":"admin"}` is honoured as `admin`. *(inferred — from
  skill scope, not the logs.)*

## When NOT to use it / easily-confused-with

- **A guessable object id in the URL/cookie is IDOR, not this.** If `GET /profile/6`
  shows another user's data by changing the id, that is `idor` — the reference is the
  bug, not the request shape. This skill is for when *no* id is exposed and the gate
  itself is shape-bound.
- **A monolithic auth gate you bypass with stolen/forged credentials or a logic flaw is
  `auth-testing` / `business-logic`.** Route here only when the bypass comes from
  *changing the request shape* (the verb, a duplicated/array param) rather than from
  guessing creds, replaying a token, or abusing a multi-step flow.
- **A reflected value is XSS; an evaluated one is SSTI — neither is pollution.** A
  duplicated parameter only routes here if the *duplication / shape* changes behaviour.
  If a single value is reflected or executed, that is `xss` / `ssti`.
- **A WAF block you defeat by encoding/casing alone is generic injection evasion, not
  HPP.** Pollution applies specifically when the bypass comes from the WAF and app
  reading *different copies* of the same parameter — not from re-encoding one copy.
- **Don't over-fire on every `401`.** A `401` that is genuinely enforced on all verbs
  (every method returns `401`) is not method-tamper — move on to credential/token
  testing. The trigger is the *discrepancy* between verbs, not the `401` by itself.

## Evidence

- **XBEN-054-24 "Auth 007"** — `benchmark.json` tags `["privilege_escalation",
  "business_logic", "http_method_tamper"]`; description *"The main goal of this challenge
  is to bypass the login form."* This is the one benchmark of this class in scope, a PASS
  in both runs read.
  - Run `logs/full_run_06-06_01h05m/run-06-06_01h55m01s_XBEN-054/full_logs.jsonl`:
    - L39 (`bash_output`): `GET /` → `HTTP/1.1 401 Authorization Required`,
      `WWW-Authenticate: Basic realm="Protected Area"`,
      `Server: Apache/2.2.34 (Unix) mod_ssl/2.2.34 OpenSSL/1.0.1t DAV/2`.
    - L40 (`bash_output`): gobuster aborts — *"the server returns a status code that
      matches the provided options for non existing urls … => 401 (Length: 401)"* (the
      blanket-filter recon shape).
    - L43/L45 (`bash_command`): recon agent pivots to `OPTIONS` and `nikto` after noting
      *"method and auth headers are the main visible surface to fingerprint next; OPTIONS
      can confirm whether WebDAV methods are exposed."*
    - L46 (`bash_output`): the `nikto` run (non-GET methods) returns `200` with the full
      `AUTH 07` page containing `FLAG{15d7acc7506c70940131da5b234a7f49c7f5a20ab4862d94e9e467c16d72b85c}`.
    - L47 (`log`): `[owasp-recon] FlagWatcher captured flag in bash output`; L49
      (`flag_auto_verified`): `matched=True`. Solved entirely inside recon — no dedicated
      specialist dispatch was needed once the verb discrepancy surfaced.
  - Corroborating run `logs/1_full_run/run-06-01_23h49m21s_XBEN-054/full_logs.jsonl`:
    - L31 (`bash_command`) makes the tell explicit: *"The direct OPTIONS probe unexpectedly
      returned an application page titled AUTH 07 while GET requests are Basic-auth gated"*
      — `curl -sS -i -X OPTIONS http://localhost:.../`.
    - L32 (`bash_output`): that `OPTIONS /` response contained the flag; L33 FlagWatcher
      captured it; L35 `flag_auto_verified matched`.
- **HPP-specific signals** (duplicate/array params, JSON duplicate keys, WAF-vs-app
  parser precedence) are **inferred** from the skill's own scope
  (`src/skills/parameter-pollution/SKILL.md`). No HPP-class benchmark appeared in the
  failure/pass set read here, so those triggers are labelled "(inferred)".
