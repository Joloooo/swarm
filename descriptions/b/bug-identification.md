# bug-identification — when to use

This skill is the **triage router**, not an exploiter. Dispatch it whenever
you are holding a raw, suspicious observation but cannot yet name the
vulnerability class — when you can see that *something* is off but the next
specialist skill (sqli, xss, ssrf, idor, ssti, …) is not yet obvious. It
takes one anomaly and turns it into a named hypothesis plus a hand-off to the
right specialist. Reach for it the moment a probe comes back "weird" and you
need to decide *which* attack skill to call next.

## Trigger signals (dispatch this skill the moment you observe…)

- **A status code flips on a single special character.** If a path/parameter
  returns `200` normally but `500` after you append one `'`, `"`, `\`, `{`,
  `<`, `;`, `|`, or `../` → input is flowing into a parser/interpreter and the
  class is undetermined → dispatch this skill to discriminate.
- **A 500 carries a stack trace or framework error you can't yet attribute.**
  If the body leaks a stack trace but you don't know whether it's SQL, a
  template engine, a deserialiser, an XML parser, or just a null-pointer →
  dispatch here to fingerprint the engine before committing to a heavy skill.
- **A response changed shape with no obvious reason.** If body length, word
  count, or structure differs between two near-identical requests (and you
  didn't change anything user-visible) → there is a hidden oracle; this skill
  finds out what kind.
- **A timing delta you can't explain.** If one request is consistently ≥ 1s
  slower than a near-twin (median of 3+ samples, not jitter) → side-channel
  present; dispatch here to decide if it's time-based blind SQLi, user
  enumeration, or cache-vs-origin.
- **Reflected input, context unknown.** If a unique marker you sent comes
  back in the response but you haven't yet determined whether it's HTML body,
  an attribute, a `<script>` block, a header, or an *evaluated* expression →
  dispatch this skill to classify the context (it decides xss vs ssti vs
  header-injection vs harmless echo).
- **An identifier in the URL/body looks guessable.** If you see a numeric or
  sequential ID, a UUID, a filename, or a username embedded in the request and
  you suspect tampering matters → this skill runs the cheap discriminator
  (increment / swap) before handing to idor or access-control.
- **An auth/authorization asymmetry.** If the *same* path returns `200` for
  one principal and `403`/`401` for another, or `/admin`-style paths respond
  at all to an anonymous client → dispatch here to confirm it's a real
  access-control delta vs. expected behaviour.
- **A serialized-looking blob in a controllable spot.** If a cookie, hidden
  field, or POST body holds base64 starting `rO0` (Java), `gASV` (Python
  pickle), or a `O:N:"…"` PHP string → this skill confirms the format with a
  one-byte tamper before calling deserialisation.
- **Any out-of-band callback after you submitted input.** If your collaborator
  (OAST) records inbound DNS/HTTP correlated to a request → a blind sink
  exists; dispatch here to attribute it (ssrf vs blind-xxe vs blind-rce).
- **A protocol-level oddity.** If `Content-Length` disagrees with the body,
  `Transfer-Encoding` shows up, CORS reflects `*` with credentials, or a JWT
  with `alg:none`/weak signing is accepted → dispatch here to slot the anomaly
  into the right class.
- **You have a pile of recon output and no clear "next move."** When the
  planner has anomalies but no confirmed class, this is the default routing
  skill: it's cheaper to triage than to fire a full exploit skill blind.

## Use-case scenarios

- **Right after recon, before any exploit skill.** Recon produces endpoints,
  parameters, error pages, and odd status codes. This skill is the natural
  next step: it converts that raw inventory into prioritized, named
  hypotheses so the planner dispatches the *correct* specialist on the first
  try instead of spraying every attack skill at every parameter.
- **Disambiguating near-neighbour classes.** A `500` with a stack trace is
  the classic ambiguous signal — it could be SQLi, SSTI, insecure
  deserialisation, XXE, or a benign bug. This skill's whole purpose is the
  one-cheap-probe discriminator that separates them, so you don't waste a long
  agent run on the wrong specialist.
- **When a value is reflected but you're unsure it's exploitable.** Reflection
  alone is not a vulnerability. This skill classifies the *context* (HTML vs
  attribute vs script vs header vs evaluated) and only then routes — preventing
  a "reflected string" from being mis-filed as XSS when it's actually SSTI, or
  as SSTI when it's just an inert echo.
- **Triaging blind/side-channel-only behaviour.** When nothing useful appears
  in the body, this skill is the right tool to interrogate the three side
  channels (timing, size, status) and decide whether there's a real oracle and
  which blind technique owns it.
- **Building a hand-off package for the planner.** When you want a structured
  finding (class, location, evidence, recommended next skill with parameter
  and oracle pre-filled) rather than a vague "something looks off," this skill
  produces exactly that.
- **Low-cost gatekeeping on a large surface.** On a target with many
  parameters, running this triage first is far cheaper than dispatching full
  exploit skills everywhere; it lets the planner spend its budget only where a
  discriminator already returned a positive.

## Concrete tells (request → response examples)

- **SQLi family:** `GET /item?id=5'` → `200` becomes `500` with
  `You have an error in your SQL syntax` / `ORA-01756` / `SQLSTATE`. Then
  `id=5 AND 1=1` vs `id=5 AND 1=2` → identical vs different body length
  (boolean oracle), or `id=5' OR SLEEP(5)-- -` → response stalls ≥ 4s
  (time oracle). → route to **sqli**.
- **SSTI:** parameter echoed, then `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` →
  body contains literal `49` (not `7*7`). The arithmetic was *evaluated*,
  which is the line that separates SSTI from plain reflection. → route to
  **ssti**.
- **Reflected XSS:** send marker `zqx-probe-12345`, fetch page → marker
  appears verbatim and *unescaped* in HTML/attribute/script context
  (`<`/`>`/`"` not entity-encoded). Reflected and unencoded → **xss**;
  reflected but entity-encoded → not XSS, log and move on.
- **Command injection:** `?host=127.0.0.1; id` / `|id` / `` `id` `` /
  `$(id)` → body contains `uid=0(root) gid=0(root)`. The literal `uid=`
  string is the confirmer. → route to **command-injection**.
- **LFI / path traversal:** `?file=../../../../etc/passwd` or
  `..%2f..%2f..%2fetc%2fpasswd` → body contains `root:x:0:0:`. → route to
  **path-traversal**.
- **SSRF:** `?url=http://169.254.169.254/latest/meta-data/` → body returns
  IAM/metadata-shaped text, or `?url=http://127.0.0.1:port/` returns content
  that differs from an external host. Blind variant: point at OAST →
  inbound hit. → route to **ssrf**.
- **IDOR:** as user A, change `?account=1001` → `1002` and receive user B's
  record without an error. → route to **idor**.
- **Deserialisation:** cookie value `rO0AB...` (Java) → flip one byte →
  response leaks `java.io.InvalidClassException` / `unable to find class`.
  The *descriptive* deserialiser error confirms the format. → route to
  **deserialisation**.
- **Access control:** `GET /admin/users` returns `200` for an authenticated
  low-priv session (or even anonymous) when it should be `403`. → route to
  **broken-access-control**.
- **Open redirect:** `?next=http://evil.example` → `302 Location: http://evil.example`
  reflecting your host. → route to **open-redirect**.

## When NOT to use it / easily-confused-with

- **Don't use it to actually exploit.** This skill confirms the *class* with
  one minimal, read-only probe and hands off. Once the class is confirmed,
  the dedicated skill (sqli/xss/ssrf/…) does the depth. Routing here to "dump
  the database" is wrong — it stops at confirmation.
- **A reflected value is XSS, not SSTI — unless it is *evaluated*.** If
  `{{7*7}}` comes back as the literal `{{7*7}}`, that's reflection (XSS
  surface at most), not SSTI. SSTI requires the `49` — the engine doing math.
  This is the single most common mis-route; the discriminator exists precisely
  to prevent it.
- **A generic `500` is not automatically SQLi.** A stack trace must actually
  name a SQL/ORM/DB layer. A `NullPointerException`, a missing-template error,
  or an unhandled type error is a benign bug or a *different* class — don't
  let any 500 default to sqli.
- **Already confident in the class?** If recon or a prior probe already
  proved the class (e.g. you've seen `uid=0(root)` echoed), skip triage and
  dispatch the specialist directly — re-confirming wastes budget.
- **Single slow response ≠ timing oracle.** Network jitter routinely adds
  200–500ms. Don't treat a one-off slow reply as a side channel; this skill
  takes the median of three. If you can't reproduce the delta, it's not a
  finding.
- **Pure config hygiene is low/log-only, not a dispatch.** Missing
  `HttpOnly`/`Secure`/`SameSite`, verbose headers, etc. are recorded, not
  routed to an exploit skill. Don't spin up a heavy specialist for cookie
  flags.
- **Not for known-target, scripted exploitation.** If the engagement already
  has a confirmed endpoint+oracle+payload, you don't need triage — go
  straight to the exploit skill. This skill earns its keep on *unclassified*
  anomalies, not on a settled plan.
