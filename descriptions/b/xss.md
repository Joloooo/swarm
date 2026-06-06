# xss — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A value you sent comes back verbatim in the response body.** Send a unique nonce (e.g. `zqx9117`) in any parameter; if you grep the response and find `zqx9117` echoed unescaped (not as `&lt;`/`&gt;`/`&amp;` and not URL-encoded) → reflected XSS candidate, dispatch this skill.
- **Marker characters survive untransformed.** Probe with a benign canary like `'"<>(){}` and look at how each character returns. If `<`, `>`, `"`, or `'` come back as literal bytes rather than entity-encoded → the sink is not escaping; this skill applies.
- **The reflection sits inside an HTML attribute, a `<script>` block, an inline event handler, a `style=`, an `href`/`src`, or an SVG/`<svg>` region.** Any reflection at all routes here; the *context* it lands in only decides which payload, not whether to dispatch.
- **Input is stored and re-rendered.** Anything that takes user text and shows it back later to you or to someone else — comments, usernames/display names, profile bios, chat/message bodies, support tickets, reviews, filenames in a listing, audit/log viewers, "your last search was…" — is a stored-XSS surface. Dispatch when you can write text in one place and see it rendered in another.
- **Client-side templating or framework markers in the page.** If recon shows React/Vue/Angular/Svelte, a build bundle, `data-reactroot`, `ng-`, `v-` attributes, or hydration JSON → look for `dangerouslySetInnerHTML`, `v-html`, `$sce.trustAsHtml`, `{@html}`, `innerHTML`, `document.write`, `eval`. DOM-XSS lives here even when the server response looks clean.
- **The URL fragment/hash or query string is read by client JS and written into the page.** If `location.hash`/`location.search` content appears in the DOM after load (and not in the raw server response) → DOM-based XSS, dispatch this skill.
- **A `Content-Type: text/html` (or `image/svg+xml`) is returned for content you control** — e.g. an upload served inline, an error page that echoes the bad input, a redirect page printing the target URL.
- **Error/search/404 pages that print back your input.** "No results for *<your text>*", "Invalid value: *<your text>*", "Page *<your path>* not found" are classic reflected sinks.
- **A blind/asynchronous surface that an operator or headless checker will view later.** If you submit data you cannot see rendered (admin-only notes, ticket queues, log dashboards, push-notification bodies) → plant a blind-XSS callback payload and dispatch.
- **A grader/checker hints at a specific value.** If the target responds with something like "you alerted 1 instead of XSS" or names an expected token → that is the XSS oracle telling you the exact value the payload must produce; dispatch and tune the payload to emit that token.

## Use-case scenarios

- **Reflected XSS sweep on every input.** Whenever you have GET/POST parameters, path segments, headers (Referer, User-Agent, X-Forwarded-For), or cookies that show up in HTML, this skill systematically probes each, classifies the reflection context, and crafts a payload that fires in that exact context. The right move on any form, search box, filter, sort, pagination, or tracking parameter.
- **Stored XSS on persistence surfaces.** Multi-user apps where one user's input renders in another user's browser — the high-impact case. Comments, forums, messaging, profile fields, organization/team names, file/asset names, calendar event titles, anything an admin reviews. Dispatch here to inject-then-revisit and check execution on render.
- **DOM-based XSS in JS-heavy SPAs.** When the server returns a near-empty shell and JavaScript builds the page, server-side grepping finds nothing. This skill reads the JS for source→sink flows (`location.*`, `postMessage`, `document.referrer`, storage → `innerHTML`/`eval`/`document.write`) and proves execution via DOM evidence rather than response reflection.
- **Filter / sanitizer / WAF bypass.** When `<script>` is stripped but you still see partial reflection, this skill rotates through event-handler vectors (`onerror`, `onload`, `onfocus`, `ontoggle`), SVG/MathML active content, casing, encoding, double-encoding, nested-tag stripping, split identifiers, and tagged-template parentheses bypasses. The skill knows which handlers auto-fire (needed for headless/blind checkers where nobody clicks).
- **CSP / Trusted Types assessment.** When a `Content-Security-Policy` header is present, this skill evaluates whether it is actually protective (nonces/hashes/`strict-dynamic`) or bypassable (wildcards, `unsafe-inline`, allow-listed JSONP/script-gadget origins, user-controlled CSP). A reflection under a weak CSP is still exploitable; under a strict one it may be a false positive.
- **Active-content uploads and rich text.** SVG/HTML file uploads served inline, Markdown/WYSIWYG renderers that pass raw HTML through, PDF/email renderers. Dispatch when you can upload or author content that the server later serves with an executable content type.
- **Non-obvious channels.** `postMessage` handlers, WebSocket/SSE message rendering, prototype-pollution merges that turn later DOM writes into script execution, mobile WebView bridges. Use this skill whenever user-influenced data reaches a rendering or scripting sink across any of these channels.

## Concrete tells (request → response examples)

- **Plain reflected, unencoded:**
  - Request: `GET /search?q=zqx<b>9117</b>`
  - Response contains: `Results for zqx<b>9117</b>` (the `<b>` rendered as a tag, not `&lt;b&gt;`) → reflected XSS, HTML-body context. Confirm with `GET /search?q=<svg onload=alert(1)>`.
- **Reflected inside a quoted attribute:**
  - Request: `GET /page?ref="zqx9117`
  - Response contains: `<input value=""zqx9117">` (your `"` broke out of the attribute) → attribute-context XSS. Payload: `" autofocus onfocus=alert(1) x="`.
- **Reflected inside a JS string:**
  - Request: `GET /p?u=zqx9117`
  - Response contains: `<script>var u="zqx9117";</script>` and your `"`/backslash survive → JS-string context. Payload: `"-alert(1)-"` or `</script><svg onload=alert(1)>`.
- **Encoded (NOT this skill):**
  - Request: `GET /search?q=<b>`
  - Response contains: `Results for &lt;b&gt;` → safely HTML-encoded in HTML context; not exploitable here. Re-check other contexts before discarding.
- **DOM-based (server clean, JS dirty):**
  - Request: `GET /#name=zqx9117` — raw HTML response does NOT contain `zqx9117`, but after JS runs the rendered DOM shows it inside an element written via `innerHTML`. Payload: `#name=<img src=x onerror=alert(1)>`.
- **Stored:**
  - Request 1: `POST /comment` with body `comment=<img src=x onerror=alert(1)>`
  - Request 2: `GET /thread/123` later returns that `<img …onerror…>` inline → stored XSS; confirm execution on load.
- **WAF/filter present:**
  - `GET /q?x=<script>alert(1)</script>` → blocked / `403` / stripped, but `GET /q?x=<svg/onload=alert(1)//` or `<img src=x onerror=alert(1)>` reflects intact → filter bypassable, keep rotating vectors.
- **Checker-graded oracle:**
  - Submit `<script>alert(1)</script>`; response says "Failed — expected XSS, got 1" → switch to `alert('XSS')` / `alert(document.domain)` to emit the demanded token.

## When NOT to use it / easily-confused-with

- **A reflected value that is *evaluated*, not just rendered, is SSTI — not XSS.** If `{{7*7}}` returns `49`, or `${7*7}`/`<%= 7*7 %>` resolves, the server is executing a template expression → that is Server-Side Template Injection (route to the SSTI skill). XSS is when markup/JS is *parsed by a browser*, not arithmetic resolved by the server.
- **A reflected value that triggers a backend syscall/process is command injection**, and one that bends a database query is SQLi. If your `'` produces a SQL error or your `;id` runs a shell command, that is not XSS even though the input was reflected.
- **A user-controlled URL that the *server* fetches is SSRF, not XSS.** A user-controlled URL that the *browser* navigates to / executes (`javascript:`, `data:text/html`) is in scope here; one that the server-side requests on your behalf is not.
- **Open redirect is not XSS** unless the redirect target is a scriptable scheme. `Location: //evil.com` is an open redirect; `Location: javascript:alert(1)` or a `<meta>`/JS redirect into a `javascript:` URL crosses into XSS.
- **Safely encoded reflections are false positives.** If `< > " '` all come back entity-encoded *for the exact context they land in*, there is no XSS — do not dispatch on mere reflection alone; dispatch on reflection that survives unescaped.
- **Header injection / CRLF (response splitting)** can look adjacent (input lands in headers) but is its own class; only treat as XSS if you can land executable HTML in a body the browser parses.
- **CSP/Trusted-Types-protected reflections:** a payload that visibly reflects but is blocked at runtime by a strict CSP (nonce/hash, no `unsafe-inline`) is not a confirmed finding without a concrete bypass — keep this skill, but validate execution, don't report on reflection alone.
- **Don't route here for stored data that is only ever shown as plain text / inside `<textarea>` with proper encoding, or rendered by a strict sanitizer (DOMPurify default, framework auto-escaping with no `dangerouslySetInnerHTML`/`v-html`/`{@html}`).** Those are the designed-safe paths; the planner should only return when a raw-HTML pass-through or trust-bypass API is in play.

B:xss done

