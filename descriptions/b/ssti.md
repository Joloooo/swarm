# ssti — when to use

## Trigger signals (dispatch this skill the moment you observe…)
- If you submit a value containing template metacharacters (`{{ }}`, `${ }`, `<%= %>`, `#{ }`) and the response returns an *evaluated* result instead of the literal characters → SSTI applies. The classic tell: send `{{7*7}}` and the page shows `49`.
- If a reflected parameter shows arithmetic being computed server-side — e.g. you send `param=abc{{7*7}}xyz` and get back `abc49xyz` — dispatch here, not XSS.
- If an error page or stack trace names a template engine: `jinja2.exceptions.TemplateSyntaxError`, `freemarker.core.*`, `Twig\Error\SyntaxError`, `mako.exceptions`, `Liquid::SyntaxError`, `Smarty: Syntax error`, `org.thymeleaf.exceptions.*`, `ERB`/`SyntaxError`, or a Spring `SpelEvaluationException` → strong SSTI indicator.
- If a malformed polyglot like `${{<%[%'"}}%\` triggers a 500 / template parse error (rather than being echoed literally or producing a generic 400) → some engine is parsing your input as a template.
- If user input visibly drives a *rendered document*: name/greeting personalization, email subject/body previews, generated PDFs/invoices/reports, "preview your page" features, custom error messages, notification templates, or anything described as a "template" in the UI.
- If a feature lets users supply their *own template syntax* — CMS page editors, email-campaign template editors, "use {placeholders} here" merge-tag fields, report builders, signature editors → high-priority SSTI surface even before probing.
- If a reflected value behaves *differently* across syntaxes: `{{7*7}}` reflects literally but `${7*7}` returns `49` (or vice-versa) → the engine is identified by which delimiter evaluates; dispatch and fingerprint.
- If sending `{{7*'7'}}` returns `49` (Jinja2/Python coercion) or `7777777` (Twig/PHP string repeat) → that differential alone confirms SSTI and names the engine family.
- If a normally-reflected field suddenly *blanks out* or silently swallows your `{{...}}` payload (consumed, not echoed) → the template engine ate it as a directive; treat as blind SSTI.
- If a sleep/range gadget (`{{ range(10000000) }}`, `{{7*7}}` swapped for a heavy loop) produces a measurable response delay while plain input does not → blind SSTI via timing.

## Use-case scenarios
- **Server-rendered personalization on a framework stack.** Recon shows Flask/Django (Python), Symfony/Laravel (PHP), Spring (Java), Rails (Ruby), or Express/Next (Node), and a parameter is reflected into HTML that is generated server-side. Template engines ship with each of these, so any user input that reaches the renderer is a candidate. This is the canonical SSTI surface.
- **"Build/preview your own content" features.** Email template editors, newsletter/marketing-campaign builders, invoice and report generators, custom error or 404 pages, profile bios rendered into pages, signature blocks, and white-label/branding settings where a tenant supplies layout text. These often pass raw strings straight into `render_template_string`, `Template(...).render()`, or equivalent.
- **Merge-tag / placeholder systems.** Any UI that advertises tokens like `{{first_name}}`, `${customer.name}`, or `%recipient%` is *by design* feeding user text through a template engine. If the engine isn't locked to a whitelist, full SSTI is one payload away. This is one of the highest-yield surfaces in practice.
- **Multi-tenant SaaS theming/CMS.** Where customers can edit page templates, themes, or layouts (Shopify Liquid, Smarty/Twig CMS, Handlebars/Nunjucks front-ends), the whole point of the feature is to evaluate user-controlled template code — so the question is only whether the sandbox holds.
- **Non-obvious sinks worth probing.** Inject the polyglot into HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`), cookies, JSON values, XML bodies, uploaded filenames/content-types, and search terms — anything that might be logged-and-rendered or reflected into an admin-rendered template later (second-order/blind SSTI).
- **Escalation from a "reflection" finding.** Whenever recon or another agent flags "input is reflected in the response," dispatch SSTI *in parallel* with XSS: the same reflection point is the test for both, and SSTI is far more severe (usually RCE).

## Concrete tells (request → response examples)
- Probe `GET /?name={{7*7}}` → response body contains `49`. Confirms evaluation. (If it shows `{{7*7}}` literally, not this engine — try other delimiters.)
- Probe `name=${7*7}` → `49` → Freemarker / Thymeleaf / JSP-EL family.
- Probe `name=<%= 7*7 %>` → `49` → ERB (Ruby) or EJS (Node).
- Probe `name=#{7*7}` → `49` → Pug/Jade or Slim.
- Probe `name=@(7*7)` → `49` → Razor (.NET).
- Differential: `name={{7*'7'}}` → `49` means Jinja2/Nunjucks (Python-style); `7777777` means Twig (PHP string repetition). The exact output tells you the engine.
- Engine variable probe: `{{config}}` returns a Flask config dict → Jinja2; `{$smarty.version}` returns a version string → Smarty; `{{ dump(app) }}` dumps Symfony app → Twig.
- Error-trigger probe: send an unbalanced `{{7*7` or the polyglot `${{<%[%'"}}%\` → a 500 with a stack trace that *names the engine* (`jinja2.exceptions`, `freemarker.core`, `Twig\Error`, `mako.exceptions`). The stack trace both confirms SSTI and fingerprints the engine.
- Blind/timing: baseline a normal request, then send `{{ range(10000000) }}` (Jinja2) or an equivalent heavy loop; a consistent multi-second delay vs baseline (>5s) confirms server-side evaluation even with no visible output.
- Negative control: send `name={{7*7}}` AND `name=7*7` (plain). If only the templated form changes and the plain form is echoed verbatim, the `{{ }}` is being parsed — not just arithmetic in your head.

## When NOT to use it / easily-confused-with
- **Reflected XSS, not SSTI.** If `7*7` only "evaluates" when JavaScript runs in the *browser* (e.g. you injected `<script>` or the math happens client-side via a JS template like Vue/Angular/Mustache running in-page), it is XSS / client-side template injection — route to XSS. SSTI requires the arithmetic to resolve *before the response leaves the server*. Always confirm with `curl` (no JS engine): if the raw HTTP response already contains `49`, it is server-side.
- **Literal reflection with no evaluation.** If `{{7*7}}` comes back as the string `{{7*7}}` and no error fires, there is no template engine in that path — do not dispatch SSTI; it may simply be a reflection (consider XSS) or harmless echo.
- **WAF echoing your payload.** A WAF block page that includes your `{{7*7}}` in an "attack detected" message is *not* evaluation — `49` must appear, not the raw payload. Don't mistake the echo for a hit.
- **Client-side template injection (CSTI).** AngularJS `{{constructor.constructor('alert(1)')()}}`, Vue, or Mustache rendered in the browser are CSTI/XSS-class, not server-side. The delimiter looks identical; the difference is *where* it executes. If the evaluation is in the DOM, it's the XSS skill's job.
- **Expression Language without templating.** Some SpEL/OGNL/EL injection lives in non-template contexts (e.g. Spring request params, Struts OGNL). The payloads overlap, but if there is no template-rendering sink, that may be a dedicated EL/OGNL-injection path rather than SSTI proper — note the distinction so the planner doesn't assume a renderer exists.
- **Sandboxed-by-default engines with no escape surface.** Liquid and `html/template` (Go) are sandboxed; if probing only confirms fingerprint but every escalation is blocked and there are no unsafe custom filters/helpers, the finding may cap at info-disclosure — still SSTI, but don't over-promise RCE without a working escape.
- **Format-string / printf-style injection.** `%s`, `%x`, `${}` shell-style expansion, or logging format strings are a different class — they aren't a template engine evaluating expressions into HTML. Don't conflate `${jndi:...}` (Log4Shell / JNDI) with template `${...}` evaluation.
