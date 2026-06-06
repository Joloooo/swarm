# bug-identification

The **triage router**, not an exploiter. It takes one raw, suspicious observation that you cannot yet name and turns it into a named vulnerability-class hypothesis plus a hand-off to the right specialist skill (sqli, xss, ssrf, idor, ssti, deserialisation, …). Use it the moment a probe comes back "weird" and you must decide *which* specialist to call next. It confirms the class with one minimal, read-only discriminator probe and stops — it never goes for depth.

## Dispatch when you observe

- **A status code flips on a single special character.** A path/parameter returns `200` normally but `500` after you append one `'`, `"`, `\`, `{`, `<`, `;`, `|`, or `../` → input is flowing into a parser/interpreter; class undetermined.
- **A 500 carries a stack trace or framework error you can't yet attribute** — don't know whether it's SQL, a template engine, a deserialiser, an XML parser, or just a null-pointer. Fingerprint the engine before committing to a heavy skill.
- **A response changed shape with no obvious reason.** Body length, word count, or structure differs between two near-identical requests though nothing user-visible changed → there is a hidden oracle.
- **A timing delta you can't explain.** One request is consistently ≥ 1s slower than a near-twin (median of 3+ samples, not jitter) → side channel present; decide if it's time-based blind SQLi, user enumeration, or cache-vs-origin.
- **Reflected input, context unknown.** A unique marker you sent comes back but you haven't determined whether it's HTML body, an attribute, a `<script>` block, a header, or an *evaluated* expression. Classifies xss vs ssti vs header-injection vs harmless echo.
- **An identifier in the URL/body looks guessable** — numeric/sequential ID, UUID, filename, or username. Runs the cheap increment/swap discriminator before handing to idor or access-control.
- **An auth/authorization asymmetry.** The *same* path returns `200` for one principal and `403`/`401` for another, or `/admin`-style paths respond at all to an anonymous client.
- **A serialized-looking blob in a controllable spot** — a cookie, hidden field, or POST body holding base64 starting `rO0` (Java), `gASV` (Python pickle), or a `O:N:"…"` PHP string. Confirms the format with a one-byte tamper before calling deserialisation.
- **Any out-of-band callback after you submitted input.** Your OAST collaborator records inbound DNS/HTTP correlated to a request → a blind sink exists; attribute it (ssrf vs blind-xxe vs blind-rce).
- **A protocol-level oddity** — `Content-Length` disagrees with the body, `Transfer-Encoding` appears, CORS reflects `*` with credentials, or a JWT with `alg:none`/weak signing is accepted.
- **A pile of recon output and no clear next move.** When the planner has anomalies but no confirmed class, this is the default routing skill — cheaper to triage than to fire a full exploit skill blind, and it lets the planner spend budget only where a discriminator already returned a positive.

## Recognition tells (request → response → route)

- **SQLi family:** `GET /item?id=5'` → `200` becomes `500` with `You have an error in your SQL syntax` / `ORA-01756` / `SQLSTATE`. Then `id=5 AND 1=1` vs `id=5 AND 1=2` → identical vs different body length (boolean oracle), or `id=5' OR SLEEP(5)-- -` → response stalls ≥ 4s (time oracle). → **sqli**.
- **SSTI:** parameter echoed, then `{{7*7}}` / `${7*7}` / `<%= 7*7 %>` → body contains literal `49` (not `7*7`). Evaluated arithmetic is the line separating SSTI from plain reflection. → **ssti**.
- **Reflected XSS:** send marker `zqx-probe-12345`, fetch page → marker appears verbatim and *unescaped* in HTML/attribute/script context (`<`/`>`/`"` not entity-encoded). Reflected and unencoded → **xss**; reflected but entity-encoded → not XSS, log and move on.
- **Command injection:** `?host=127.0.0.1; id` / `|id` / `` `id` `` / `$(id)` → body contains `uid=0(root) gid=0(root)`. The literal `uid=` string is the confirmer. → **command-injection**.
- **LFI / path traversal:** `?file=../../../../etc/passwd` or `..%2f..%2f..%2fetc%2fpasswd` → body contains `root:x:0:0:`. → **path-traversal**.
- **SSRF:** `?url=http://169.254.169.254/latest/meta-data/` → body returns IAM/metadata-shaped text, or `?url=http://127.0.0.1:port/` returns content differing from an external host. Blind variant: point at OAST → inbound hit. → **ssrf**.
- **IDOR:** as user A, change `?account=1001` → `1002` and receive user B's record without an error. → **idor**.
- **Deserialisation:** cookie value `rO0AB...` (Java) → flip one byte → response leaks `java.io.InvalidClassException` / `unable to find class`. The *descriptive* deserialiser error confirms the format. → **deserialisation**.
- **Access control:** `GET /admin/users` returns `200` for a low-priv (or anonymous) session when it should be `403`. → **broken-access-control**.
- **Open redirect:** `?next=http://evil.example` → `302 Location: http://evil.example` reflecting your host. → **open-redirect**.

## Output / hand-off

Produce a structured finding — class, location, evidence, and the recommended next skill with its parameter and oracle pre-filled — rather than a vague "something looks off."

## When NOT to use / easily confused with

- **Not for actual exploitation.** Confirm the class with one minimal read-only probe and hand off; the dedicated skill does the depth. Routing here to "dump the database" is wrong — it stops at confirmation.
- **A reflected value is XSS, not SSTI — unless it is *evaluated*.** If `{{7*7}}` comes back as literal `{{7*7}}`, that's reflection (XSS surface at most), not SSTI. SSTI requires the `49`. This is the single most common mis-route; the discriminator exists to prevent it.
- **A generic `500` is not automatically SQLi.** The stack trace must actually name a SQL/ORM/DB layer. A `NullPointerException`, a missing-template error, or an unhandled type error is a benign bug or a *different* class — don't let any 500 default to sqli.
- **Already confident in the class?** If recon or a prior probe already proved it (e.g. you've seen `uid=0(root)` echoed), skip triage and dispatch the specialist directly — re-confirming wastes budget.
- **Single slow response ≠ timing oracle.** Network jitter routinely adds 200–500ms. Take the median of three; if you can't reproduce the delta, it's not a finding.
- **Pure config hygiene is low/log-only, not a dispatch.** Missing `HttpOnly`/`Secure`/`SameSite`, verbose headers, etc. are recorded, not routed to an exploit skill.
- **Not for known-target, scripted exploitation.** If the engagement already has a confirmed endpoint+oracle+payload, skip triage and go straight to the exploit skill. This skill earns its keep on *unclassified* anomalies.
