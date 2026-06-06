# ssti — when to use

Server-side template injection: a user-controlled value reaches a template engine that **compiles and evaluates** it on the server before the response leaves. The confirmation probe (`{{7*7}}` → `49`) is trivial and almost never the hard part — recognising the real sink and carrying the escalation through is. Treat `49` as the **start** of the work, not the finish.

## Dispatch when you observe…
- **`{{7*7}}` comes back as `49`, not the literal `{{7*7}}`.** The definitive tell. If `?name={{7*7}}` renders `Hello, 49!` and `?name={{7+7}}` renders `Hello, 14!`, the engine is evaluating, not echoing. Works mid-string too: `param=abc{{7*7}}xyz` → `abc49xyz`.
- **A string-literal probe renders.** `{{'abc'}}` → `abc` (quotes stripped, value rendered) means the parameter sits inside a template expression even before arithmetic.
- **A template parser error in the response.** A probe like `{{7*'7'}}` or an unbalanced `{{7*7` returning `Could not parse the remainder: '*7' from '7*7'` (Django), `jinja2.exceptions.TemplateSyntaxError`, `Twig_Error_Syntax` / `Twig\Error\SyntaxError`, `freemarker.core.*`, `mako.exceptions`, `Liquid::SyntaxError`, `Smarty: Syntax error`, `org.thymeleaf.exceptions.*`, ERB `SyntaxError`, or Spring `SpelEvaluationException` means the input is being **compiled as template source** — that IS SSTI, even if that operator was rejected. Switch to engine-correct syntax.
- **A malformed polyglot** like `${{<%[%'"}}%\` triggers a 500 / template parse error (rather than literal echo or a generic 400) → some engine is parsing your input as a template.
- **A framework fingerprint plus any reflected parameter.** `Server: Werkzeug/… Python/…` (Flask/Jinja2), `Server: WSGIServer … CPython` (Django templates), `X-Powered-By: PHP` + `twig/twig` in `/vendor/composer/installed.json` (Twig), a Sinatra 404 (`Sinatra doesn't know this ditty` → Ruby/ERB), or any Flask/Django/Symfony/Laravel/Spring/Rails/Express/Next stack with a reflected param. Every one of these ships a template engine, so user input that reaches the renderer is a candidate.
- **Reflection inside a server-built JSON or JS body**, not just a `<title>`/`<h1>`. Input interpolated into a JSON field (`{ "loan_principal": "<your input>", … }`) or into a dynamically generated `.js` file was assembled by a server-side template — a prime sink.
- **Template markup leaking into rendered HTML.** Un-rendered literal `value="{{ user.email }}"` or `{% … %}` tags in the page source mean the app is template-driven and a nearby field is likely injectable.
- **A 400/blacklist rejection naming forbidden characters** on a parameter whose value still affects rendering (`GET parameter 'term' contains forbidden characters`) is positive evidence of a template sink **with a keyword/char filter** — wants a filter bypass or a blind technique, not a different vuln.
- **A "repeat / echo / preview" feature, often behind default creds.** A form that exists only to render your text back (reminder, greeting, "repeat me", loan-summary preview), email subject/body previews, generated PDFs/invoices/reports, custom error or 404 pages, profile bios, notification templates — the canonical SSTI sink. Many sit behind a trivial login (`test/test`, `user/user`, `admin/admin`); authenticate first, then probe the echo field.
- **A feature that lets users supply their own template syntax** — CMS/page editors, email-campaign and newsletter builders, report/invoice builders, signature editors, white-label/theming settings, merge-tag fields (`{{first_name}}`, `${customer.name}`, `%recipient%`). High-priority surface even before probing; the question is only whether the sandbox holds (Shopify Liquid, Smarty/Twig CMS, Handlebars/Nunjucks).
- **A value behaves differently across syntaxes.** If `{{7*7}}` reflects literally but `${7*7}` returns `49` (or vice-versa), the engine is identified by which delimiter evaluates.
- **A normally-reflected field blanks out / silently swallows** your `{{...}}` (consumed, not echoed) → the engine ate it as a directive; treat as blind SSTI.
- **A heavy gadget produces a measurable delay.** `{{ range(10000000) }}` or an equivalent loop causes a consistent multi-second delay (>5s) vs baseline while plain input does not → blind SSTI via timing.
- **A task description naming template rendering** ("dynamically include JINJA templates", "build JSON objects using JINJA templates", "dynamically generated JS with DjangoTemplates", "SSTI in Jinja2", "repeats the user input back to them", "potential SSTI in the … form") is itself a routing tell.
- **Whenever recon or another agent flags "input is reflected in the response,"** dispatch SSTI **in parallel** with XSS — the same reflection point tests both, and SSTI is far more severe.

## Engine fingerprinting (which delimiter returns `49`)
- `{{7*7}}` → `49` → Jinja2/Nunjucks/Twig/Handlebars family. `{{7*'7'}}` → `49` = Jinja2/Nunjucks (Python coercion); `7777777` = Twig (PHP string repeat).
- `${7*7}` → `49` → Freemarker / Thymeleaf / JSP-EL family.
- `<%= 7*7 %>` → `49` → ERB (Ruby) or EJS (Node).
- `#{7*7}` → `49` → Pug/Jade or Slim.
- `*{7*7}` → `49` → Thymeleaf.
- `@(7*7)` → `49` → Razor (.NET).
- Variable probes: `{{config}}` → Flask config dict = Jinja2; `{$smarty.version}` → version string = Smarty; `{{ dump(app) }}` → Symfony app dump = Twig.
- A polyglot sweep of all six syntaxes in one request is the efficient first move; see which returns `49`.

## Key exploitation techniques
- **Jinja2/Flask → RCE & config disclosure.** `{{config}}` / `{{config.items()}}` dumps the Flask config and any baked-in secret. Global-object gadgets give command execution and arbitrary file read:
  - `{{cycler.__init__.__globals__.os.popen('id').read()}}`
  - `{{lipsum.__globals__['os'].popen('cat /flag').read()}}`
  - `{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}`
- **Django templates — math is blocked, use tags/context.** Django does **not** evaluate `{{7*7}}` (you get `Could not parse the remainder`); that failing is **expected, not a dead end**. The win is template tags and context: `{% debug %}` dumps the entire template context (often containing the flag), `{{ request }}` and `{{ settings.SECRET_KEY }}` leak server state. "Check the context" = `{% debug %}`.
- **Twig (PHP) → RCE.** Confirm with `{{_self}}` (object error), then `{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}` for command execution.
- **ERB / Ruby (Sinatra) → RCE.** `<%= \`id\` %>` for commands, `<%= ENV.to_h %>` to dump env vars (flags often live there), `<%= File.read('app.rb') %>` for source read.
- **JSON-built-by-template sinks** (e.g. loan calculators). A form field flows into the Jinja that assembles the JSON response; the injected value lands inside the JSON and `{{config}}` / `cycler…os.popen` work as normal.
- **Blind / filtered SSTI.** When arithmetic is rejected (`forbidden characters`) or output isn't shown in place, the sink is still there — switch to error-based, timing, second-order (via a stored value), or include-chain techniques, and to filter/encoding bypasses.
- **Upload-then-include chain.** Where an upload writes a file the app later renders as a template, inject the payload into the uploaded file and trigger the include.
- **Non-obvious sinks** worth probing for second-order/blind: HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`), cookies, JSON values, XML bodies, uploaded filenames/content-types, search terms — anything logged-and-rendered or later reflected into an admin-rendered template.
- **After confirmation, also locate where the flag lives.** Reaching `49` and even RCE (`uid=33(www-data)`) is wasted if the flag is outside the reachable filesystem / behind a blacklist you didn't bypass. Carry the escalation through: engine-correct config dump → gadget RCE → file read → find the flag's real path.

## When NOT to use it / easily-confused-with
- **Value reflected *unchanged* is XSS/reflection, not SSTI.** If `{{7*7}}` comes back literal and `${7*7}`/`<%=7*7%>` also echo verbatim with no error, route to `xss`. SSTI requires the server to *change* the value — compute it, throw a parse error, or render an object. Confirm with `curl` (no JS engine): if the raw HTTP response already contains `49`, it is server-side.
- **Client-side template injection (CSTI).** AngularJS `{{constructor.constructor('alert(1)')()}}`, Vue, Mustache rendered in the browser are CSTI/XSS-class. Same delimiters; the difference is *where* it executes. If the math resolves only when JS runs in the DOM, it's the XSS skill's job.
- **WAF echoing your payload.** A block page that includes your `{{7*7}}` in an "attack detected" message is not evaluation — `49` must appear, not the raw payload.
- **A static endpoint echoing a fixed `{{7*7}}` string is a decoy.** A response that contains template syntax but does **not vary with your input** (returns the same body for every path/input) is bait, not confirmation.
- **Co-located non-HTTP services are decoys.** AirPlay/AirTunes (`Server: AirTunes/…` on `:5000`/`:7000`, `/pair-setup`, `/fp-setup`, bplist dumps), MikroTik bandwidth-test (`:49152`), SSRF oracles, raw TCP ports, mDNS/Bonjour. An unidentified open port is not a reason to leave the reflected parameter on the real web app. Keep this skill pointed at the template surface.
- **Django `{{7*7}}` failing is expected, not "not SSTI"** — pivot to `{% debug %}` / `{{ request }}` / context disclosure rather than concluding no template exists.
- **Expression Language without templating.** SpEL/OGNL/EL injection (Spring request params, Struts OGNL) overlaps in payloads but may have no template-rendering sink — a dedicated EL/OGNL path, not SSTI proper. Likewise `${jndi:...}` is Log4Shell/JNDI, not template `${...}` evaluation.
- **Format-string / printf-style injection** (`%s`, `%x`, shell `${}` expansion, logging format strings) is a different class — no template engine evaluating expressions into HTML.
- **Sandboxed-by-default engines** (Liquid, Go `html/template`) may cap at info-disclosure if every escalation is blocked and there are no unsafe custom filters/helpers — still SSTI, but don't over-promise RCE without a working escape.
- **No tool calls / only planner errors carries no signal about the vuln class.** An empty `AIMessage`, `429 usage_limit_reached`, or a crashed worker (`ModuleNotFoundError`) is an infrastructure failure, not "no SSTI" — re-run rather than concluding the surface is clean.
