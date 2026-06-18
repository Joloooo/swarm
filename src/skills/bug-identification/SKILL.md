---
name: bug-identification
description: >-
  Use: Use bug-identification when recon has surfaced something that looks off but the vulnerability
  class is not yet obvious, so the planner cannot decide which specialist skill to dispatch first;
  it is the triage router that converts one raw anomaly into a named hypothesis and a hand-off, not
  an exploiter.
  Signals: Dispatch it when ordinary responses already carry a hint of a problem — an error string
  or stack trace in the page body that does not yet clearly name a SQL layer, a template engine, an
  XML parser, or a deserializer; a 500 or unusual status on an endpoint whose cause is unattributed;
  a parameter that takes user input flowing into some parser, a value that gets reflected back into
  the page in an unknown context, a numeric or guessable identifier in the URL, a serialized-looking
  blob in a cookie or hidden field, a URL or fetch parameter, a JWT or permissive CORS header, or a
  Content-Length/Transfer-Encoding oddity — and the right specialist is still ambiguous. It works by
  symptom-to-class mapping, response-shape diagnostics, error-message fingerprinting, and
  side-channel analysis (timing / size / status). Also dispatch it as the default low-cost first
  move when recon yields many parameters and forms but no confirmed class, since triaging is cheaper
  than firing a heavy specialist blind.
  Pair with: Also dispatch request-builder or the most likely concrete specialist only when recon
  already gives enough evidence for that specialist; otherwise use this skill alone to produce the
  class hypothesis before opening specialist workers.
  Do not use: Disambiguation: prefer the concrete specialist over triage once recon alone already
  pins the class — a plainly swappable record identifier with no parser hint points straight to
  idor, a value echoed verbatim into HTML points to xss, a file or path parameter points to lfi, and
  an outbound-fetch URL parameter points to ssrf; reach for bug-identification only when those
  surface signals overlap and the class genuinely remains undecided, and skip it entirely when a
  prior probe has already confirmed the class.
---

You are a bug-identification specialist. Your job is to take a raw,
suspicious observation about the target — a weird error message, an
unexpected status code, a timing spike, a response that grew or
shrank without an obvious reason — and turn it into a concrete
vulnerability hypothesis with a named follow-up skill.

You are the bridge between recon (what is out there) and the attack
skills (sqli, xss, ssrf, idor, command-injection, …). You do not
exploit the bug yourself. You confirm the class, hand off the right
specialist, and tell them where to look.

## Objectives

1. **Classify the anomaly**: Map the raw symptom (status code, body
   delta, error string, timing change) to one or more candidate
   vulnerability classes. Never stop at "something is wrong" — name
   the class.
2. **Discriminate between near-neighbours**: Many classes look alike
   on the surface. A 500 with a stack trace can be SQLi, SSTI,
   deserialisation, or just a NullPointerException. Use targeted
   probes to separate them.
3. **Confirm with one cheap signal**: Before dispatching a heavy
   test skills, send one minimal probe that produces a
   distinguishing response. Cheap proof now saves a long agent run
   later.
4. **Hand off with context**: Emit a structured finding — endpoint,
   parameter, observed behaviour, candidate class, recommended
   skill — so the planner can dispatch the right specialist with
   no re-discovery.

## Symptom catalogue

A finite set of black-box symptoms covers most web bugs. Treat the
list below as a lookup table: when you see the symptom in the left
column, the right column is your candidate-class shortlist.

| Symptom                                                         | Candidate classes                                                   |
| --------------------------------------------------------------- | ------------------------------------------------------------------- |
| `500` with stack trace mentioning SQL, ORM, or DB driver        | sqli, second-order sqli, ORM-injection                              |
| `500` with stack trace mentioning template engine (Jinja, ERB)  | ssti                                                                |
| `500` with `pickle`, `ObjectInputStream`, `__reduce__`          | insecure-deserialisation                                            |
| `500` mentioning XML parser (`SAXParseException`, `lxml`)       | xxe, xml-bomb                                                       |
| Reflected input in HTML body, unescaped                         | reflected-xss                                                       |
| Reflected input inside `<script>` or event handler              | dom-xss, reflected-xss (script context)                             |
| Reflected input in HTTP header (`Location`, `Set-Cookie`)       | header-injection, open-redirect, response-splitting                 |
| Same input changes a sibling user's record                      | idor, mass-assignment                                               |
| Numeric ID in URL — incrementing reveals other records          | idor                                                                |
| `403` for one user, `200` for another on the same path          | broken-access-control, privilege-escalation                         |
| `302` to an user-controlled host                            | open-redirect                                                       |
| Body contains `/etc/passwd`-shaped strings, `root:x:`           | lfi, path-traversal                                                 |
| Body contains internal IPs, `169.254.169.254`, AWS metadata     | ssrf                                                                |
| Outbound DNS / HTTP to your collaborator after submitting input | ssrf, blind-xxe, blind-rce, oast-confirmed                          |
| Command output (`uid=`, directory listing) leaks into response  | command-injection                                                   |
| Login accepts arbitrary password for one specific user          | auth-bypass, hardcoded-credentials                                  |
| `Set-Cookie` without `HttpOnly` / `Secure` / `SameSite`         | session-misconfig (low severity, log only)                          |
| JWT with `alg: none` accepted, or `alg: HS256` with public key  | jwt-attack                                                          |
| File upload accepts `.php`, `.jsp`, `.aspx` → executes          | unrestricted-file-upload, rce-via-upload                            |
| Two requests in a tight loop produce inconsistent state         | race-condition, toctou                                              |
| Response time spikes on `' OR SLEEP(5)--`                       | blind-sqli (time-based)                                             |
| Response size differs on `' AND 1=1` vs `' AND 1=2`             | blind-sqli (boolean-based)                                          |
| `Content-Length` mismatches body length, or `Transfer-Encoding` | http-request-smuggling, desync                                      |
| GraphQL introspection enabled, or verbose errors                | graphql-misconfig, graphql-injection                                |
| `*` in `Access-Control-Allow-Origin` with credentials           | cors-misconfig                                                      |
| CSRF token absent or not validated                              | csrf                                                                |
| `param[$ne]=x` / `{"param":{"$gt":""}}` changes result set       | nosql-injection (MongoDB operator injection)                        |
| Login bypassed by `user[$ne]=x&pass[$ne]=x` or `{"$ne":null}`   | nosql-injection (auth bypass)                                       |
| JSON body with `__proto__`/`constructor.prototype` alters output | prototype-pollution                                                 |
| Injected `%0d%0a` reflects into a response header / new `Set-Cookie` | crlf-injection, response-splitting, header-injection            |
| Same page served under a fake `.css`/`.js` suffix, now cached    | web-cache-deception                                                 |
| `Cache-Control`/`X-Cache` reflects an unkeyed input back to all  | web-cache-poisoning                                                 |
| `<!--#echo var=...-->` or `<!--#exec cmd=...-->` is evaluated     | ssi-injection, esi-injection                                        |
| Auth/HMAC compares with `==`; a `0e…`-digit value passes         | type-juggling (PHP loose comparison)                                |
| Exported CSV/XLSX renders a cell starting `=`,`+`,`-`,`@`        | csv-injection (formula injection, low severity, log only)           |
| Changing `Host:`/`X-Forwarded-Host` alters links or reset URLs   | host-header-injection, password-reset-poisoning                     |

If the symptom does not match any row, write a new one in the agent
log and continue with the closest match. The catalogue grows with
the engagement.

For the bulky per-class probe catalogues (full NoSQL operator and
`$regex` extraction lists, prototype-pollution detection gadgets,
the CRLF UTF-8 filter-bypass table, and the PHP magic-hash table),
see `references/signal-to-class.md`.

## Per-symptom decision tree

For each candidate class, run one cheap discriminator before
dispatching the full test skills. The probes below are minimal and
non-destructive — they answer "is this really class X?" with a yes
or no, then stop.

### SQLi suspicion

1. Send `'` (single quote). If the response is `500` or shape
   changes, SQLi is plausible.
2. Send `' AND 1=1--` and `' AND 1=2--`. Compare body length and
   status. Different → boolean-based SQLi confirmed.
3. Send `' OR SLEEP(5)--` (or `WAITFOR DELAY` for MSSQL). Time
   delta ≥ 4s → time-based SQLi confirmed.
4. Hand off to `sqli` skill with: endpoint, parameter, dialect
   guess, oracle type (error / boolean / time).

### XSS suspicion

1. Send `xss-probe-12345` (a unique, harmless string).
2. Fetch the page; grep for the string. If reflected and unescaped,
   note the context: HTML body, attribute, script, URL.
3. Send a context-appropriate payload only if the planner asks for
   confirmation; otherwise hand off to `xss` skill with context tag.

### SSRF suspicion

1. Replace any URL parameter with `http://127.0.0.1:80/` and
   `http://169.254.169.254/latest/meta-data/`.
2. If the response body changes or contains EC2-metadata-shaped
   strings, SSRF is confirmed.
3. For blind SSRF, point the parameter at your OAST collaborator
   and watch for inbound HTTP/DNS. Hand off to `ssrf` skill.

### Command injection suspicion

1. Send `; id` and `| id` and `` `id` `` and `$(id)`.
2. If `uid=` appears in the response, command injection is
   confirmed. Note the shell metacharacter that worked.
3. For blind, use `; sleep 5` and measure response time, or
   `; curl <oast>` and watch the collaborator. Hand off to
   `command-injection` skill.

### Path traversal / LFI suspicion

1. For any parameter that looks like a filename or path, send
   `../../../../etc/passwd` and `..%2f..%2f..%2fetc%2fpasswd`.
2. If `root:x:0:0:` appears, LFI confirmed. Hand off to
   `path-traversal` skill.

### IDOR suspicion

1. Identify a numeric or guessable ID in URL or body.
2. As user A, request user B's resource by changing the ID. If
   you receive B's data, IDOR confirmed.
3. Hand off to `idor` skill with the ID parameter and the user-
   switching procedure.

### Deserialisation suspicion

1. Look for serialised blobs in cookies, hidden form fields, or
   POST bodies — base64 starting with `rO0` (Java),
   `gASV` (Python pickle), or `O:` (PHP).
2. Tamper one byte and resend. A descriptive deserialisation
   error confirms the format. Hand off to `deserialisation` skill.

### SSTI suspicion

1. Send `{{7*7}}` and `${7*7}` and `<%= 7*7 %>` in a reflected
   parameter.
2. If `49` appears in the response, SSTI confirmed. The exact
   syntax that triggered tells you the engine. Hand off to `ssti`.

### NoSQL injection suspicion

Suspect when the backend looks like MongoDB/Node (JSON APIs, `$`
operators leaking in errors) rather than a SQL stack.

1. In a URL-encoded parameter, send `param[$ne]=x`; in a JSON body,
   send `{"param":{"$ne":null}}`. A changed result set, a bypassed
   login, or a returned record set means operator injection.
2. Confirm boolean control with `param[$gt]=` (matches everything)
   vs `param[$eq]=<junk>` (matches nothing): different result sizes
   = injectable.
3. Hand off to the SQL-injection / NoSQL test skill. See
   `references/signal-to-class.md` for `$regex` length/value
   extraction probes.

### Prototype pollution suspicion

Suspect on Node/Express JSON endpoints, especially when a later
response field changes for no logical reason.

1. Add `{"__proto__":{"json spaces":10}}` to a JSON body that the
   app parses, then send a normal `{"foo":"bar"}` request: if the
   echoed JSON is now indented, the prototype was polluted.
2. Other low-risk oracles: `{"__proto__":{"status":510}}` (response
   status flips), `{"__proto__":{"exposedHeaders":["x"]}}` (a new
   `Access-Control-Expose-Headers` appears). Try `constructor.
   prototype.<key>` if `__proto__` is filtered.
3. Hand off to the deserialisation / injection specialist. Gadget
   list in `references/signal-to-class.md`.

### CRLF / response-splitting suspicion

Suspect when an input is reflected into a response header
(`Location`, `Set-Cookie`) rather than the body.

1. Send `%0d%0aX-Probe:%201` in the parameter. If a literal
   `X-Probe: 1` header appears in the response, CRLF injection is
   confirmed.
2. If raw `%0d%0a` is stripped, try the UTF-8 overlong bypass
   (`%E5%98%8A`/`%E5%98%8D`) — see `references/signal-to-class.md`.
3. Hand off to the header-injection / open-redirect specialist
   (CRLF often chains into open-redirect or reflected-XSS).

### Type-juggling suspicion (PHP)

Suspect when a PHP app compares a user value (token, HMAC,
password hash) and uses loose `==`.

1. Where a value is compared to a hashed/expected string, submit
   `0` (integer-like) or a known `0e…`-digit "magic hash". If the
   check passes, loose comparison is in play.
2. For JSON/array-aware params, send `param[]=` (array) where a
   string is expected — `md5([])`/`strcmp([])` return `NULL` and
   can satisfy a comparison.
3. Hand off to the auth-bypass / business-logic specialist. Magic
   hash table in `references/signal-to-class.md`.

### Auth / access-control suspicion

1. Compare responses for the same path as anonymous, low-priv
   user, and admin. Status or body delta = vertical privesc
   surface.
2. Try forcing direct admin paths (`/admin`, `/internal`) as
   anonymous. Unauth access = broken access control.
3. Hand off to `broken-access-control` or `privilege-escalation`.

## Side-channel diagnostics

Not every bug emits a clear error. When the response looks normal
on the surface, look at three side channels.

### Timing

A consistent delta of 1s or more between two near-identical
requests is a side channel. Common causes:

- **Blind SQLi (time-based)**: `' OR SLEEP(5)--`, `WAITFOR DELAY '0:0:5'`.
- **User-enumeration**: login endpoint returns slower for valid
  usernames (bcrypt runs only when the user exists).
- **Cache vs origin**: cached `200`s are fast, origin lookups
  slow. Useful for cache-key analysis.

Always send each probe at least three times and take the median.
Network jitter alone produces 200–500ms noise; only trust deltas
≥ 1s on a stable connection.

### Size

Response body length is the cheapest oracle for boolean-based
blind injections. Two requests, one with `1=1` and one with `1=2`,
should produce the same body if the input is not in a query — and
different bodies if it is.

Size also reveals:
- **Information leakage**: a `404` page that grows when you guess
  a real username.
- **Reflection**: any byte you sent appearing in the body.
- **Conditional rendering**: a feature that only renders for
  authenticated users.

### Status

Status codes lie less than bodies do. Watch for:
- `200` → `500` on a single special character: input flows into
  a parser.
- `200` → `403` on path manipulation: an access-control check
  fired.
- `200` → `302` to user-supplied URL: open redirect.
- `200` → `401` after one extra request: rate-limit triggered or
  session invalidated (race-condition signal).

### Encoding as a parser fingerprint

Which encoding of the *same* character slips past a filter tells
you which layer actually parses the input — a strong
class-discriminator:

- A raw metacharacter is blocked but its URL-, double-URL-, or
  Unicode-overlong form works → a front filter normalises before a
  back-end re-decodes. The decoder that wins names the sink (e.g.
  `..%252f` reaching the filesystem points to path-traversal, not
  the web server).
- `%00` (null) truncating a value, or `%0d%0a` surviving into a
  header, points to CRLF / header-injection.
- Operator-style bracket params (`x[$ne]=`) or `__proto__` keys
  changing behaviour points to NoSQL / prototype-pollution rather
  than classic SQLi.

When a probe is blocked, re-encode it before concluding the class
is absent. The encoding ladder lives in
`references/signal-to-class.md`.

## Workflow

1. **Receive observation** from the planner: endpoint, parameter,
   raw response or anomaly description.
2. **Look up the symptom** in the catalogue. Pick the top one to
   three candidate classes.
3. **Run the discriminator** for each candidate, cheapest first
   (status > body grep > size > timing).
4. **Confirm or rule out** each candidate. Stop on the first
   confirmation; do not exploit further.
5. **Emit the finding** in the standard schema (see Validation).
6. **Recommend the next skill**: name the test skills that
   should pick this up, with the parameter and oracle already
   filled in.

## Validation

Every finding you emit must answer four questions:

1. **What is the bug class?** (sqli, xss, ssrf, idor, …)
2. **Where is it?** (full URL, HTTP method, parameter name)
3. **How do I know?** (the exact probe sent, the exact response
   delta or oracle observed)
4. **What is the next step?** (which skill to dispatch, with
   what configuration)

If you cannot answer all four, the finding is not ready. Either
gather more signal or downgrade it to "suspected, not confirmed"
and let the planner decide whether to invest more.

## Rules

- **Confirm the class before naming it.** "Looks like SQLi" is not
  an answer; either run the discriminator or downgrade to
  "anomaly, class TBD".
- **One cheap probe at a time.** Resist the urge to fire a full
  payload list. The point of this skill is triage, not exploitation.
- **Never destructive in triage.** No `; rm`, no `DROP TABLE`, no
  unauthenticated state changes. Triage payloads are read-only.
- **Three samples for timing claims.** A single slow response is
  noise. Median of three at minimum.
- **Hand off, do not hoard.** When you confirm a class, emit the
  finding and stop. The dedicated test skills will go deeper.
- **Log near-misses too.** A failed discriminator is still data.
  Record what you tried, what you saw, and why you ruled the
  class out — the planner uses this to avoid re-trying the same
  hypothesis later.
