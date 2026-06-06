# input-validation — when to use

This skill is the broad input-handling auditor. It fires whenever the target accepts a value the user controls and that value appears to be *acted upon* by the server — passed to a shell, used to build a filesystem path, written into a response header, parsed as a structured document (XML/JSON), or used to decide whether an uploaded file is accepted. It is the right call when you have an input vector but no specific proof yet of *which* sink it reaches; the skill's job is to send differential probes and find out.

## Trigger signals (dispatch this skill the moment you observe…)

- **A parameter whose name hints at a filesystem path** — `file`, `path`, `page`, `template`, `doc`, `download`, `dir`, `folder`, `include`, `view`, `lang`, `theme`, `img`, `pdf`, `attachment`. → dispatch (path-traversal / file-read leg).
- **A parameter whose name hints at a shell or system call** — `cmd`, `exec`, `ping`, `host`, `ip`, `domain`, `url` (when the app clearly runs a network tool), `dns`, `lookup`, `count`, `option`, `format`, `tool`, anything that looks like it maps to a CLI flag. → dispatch (command-injection leg).
- **The app's *function* implies it shells out** — a "ping this host", "traceroute", "nslookup", "whois", "convert this image", "generate PDF", "run report", "backup", or "diagnostics" feature. These wrap system binaries and the user value lands in `system()`/`exec()`/backticks. → dispatch.
- **A value you send is reflected into a response *header*** (not the body) — e.g. it appears in `Location:`, `Set-Cookie:`, a custom `X-*` header, or a redirect target. → dispatch (CRLF / header-injection leg).
- **A `Location:` redirect that echoes a parameter** (`?url=`, `?redirect=`, `?next=`, `?return=`, `?continue=`). → dispatch — test for CRLF splitting and header injection.
- **A file-upload form or endpoint** — `multipart/form-data`, an `<input type=file>`, an avatar/document/import upload, or a `Content-Type: multipart/...` accepting endpoint. → dispatch (upload-validation leg).
- **The request body is XML** — `Content-Type: application/xml` / `text/xml` / `application/soap+xml`, a SOAP envelope, a SAML response, an RSS/SVG/DOCX/XLSX ingest, or any `<?xml ...?>` payload the server consumes. → dispatch (XXE leg).
- **The request body is JSON that drives server behaviour** — values that look like they flow into a query, a path, a deserializer, or a command. → dispatch (structured-input leg).
- **A 500 / stack trace appears the instant you insert a metacharacter** — a single `'`, `"`, `;`, `|`, backtick, `<`, `&`, `../`, or NUL byte flips a 200 into a 500 or a parser error. → dispatch — the input reaches an unsanitised sink.
- **Differential timing on metacharacters** — a request with `; sleep 5` (or `| ping -c 5`) takes ~5s longer than baseline. → dispatch (blind command-injection signal).
- **Error strings that name a parser or shell** — `sh: 1:`, `/bin/sh`, `No such file or directory`, `failed to open stream`, `DOMDocument`, `SimpleXML`, `lxml`, `SAXParseException`, `java.io.FileNotFoundException`, `system cannot find the path`. → dispatch.
- **A WAF/filter that strips *one* encoding but not another** — `../` is blocked but `%2e%2e%2f` or `..%252f` passes, or `;` is blocked but `%0a`/`$()`/`{IFS}` is not. → dispatch; the validation is incomplete and the skill's multi-encoding strategy is exactly the right tool.

## Use-case scenarios

- **Black-box recon just enumerated parameters and you don't yet know the sinks.** You have a list of `GET`/`POST` params from crawling, `gobuster`, or form scraping, but no idea which ones are dangerous. This skill systematically baselines each one and sends marker characters to learn which reach a shell, a filesystem call, a header, or a parser — it is the natural *first* dispatch after parameter discovery.
- **A utility/diagnostic feature exists.** Anything that takes a hostname, IP, URL, filename, or "command option" and produces tool-like output (ping latency, DNS records, file conversion) is a prime command-injection surface. Dispatch here to inject shell metacharacters into that field.
- **File-download / file-viewer features.** Endpoints that serve a file named by a parameter (`/download?file=report.pdf`, `/static?path=...`, language/template loaders) are the canonical path-traversal surface — probe for `../../../../etc/passwd` and its encodings, and for absolute-path and NUL-byte tricks.
- **Open-redirect-shaped parameters and header echoes.** When a value lands in a response header, the same value may carry a CR/LF to inject a second header or split the response (response splitting, cookie injection, cache poisoning). This skill covers that leg.
- **Upload endpoints with apparent type restrictions.** When an app says "only images allowed", this skill tests the *enforcement*: extension vs. content-type vs. magic-byte checks, double extensions (`shell.php.jpg`), null-byte truncation, case tricks, and `Content-Type` spoofing — to find which check is missing.
- **XML/SOAP/SAML/Office-doc ingestion.** Any endpoint parsing XML is a candidate for external-entity processing (XXE) → local file read, SSRF, or DoS. Dispatch here to send entity-declaration probes and watch for file contents or out-of-band callbacks.
- **A filter is clearly present but leaky.** When you can see one encoding blocked and another allowed, this skill's "try URL-encode, double-encode, unicode, alternate separators" doctrine is purpose-built to find the bypass.

## Concrete tells (request → response examples)

- **Command injection (in-band):**
  Baseline `?host=127.0.0.1` → returns ping output for one host.
  Probe `?host=127.0.0.1;id` → response now also contains `uid=0(root) gid=0(root)` or `uid=33(www-data)`. The appended command ran. **Confirms.**
  Probe `?host=127.0.0.1|whoami` / `?host=$(id)` / `?host=\`id\`` → same — extra command output appears.

- **Command injection (blind/time-based):**
  Probe `?host=127.0.0.1;sleep 5` vs `?host=127.0.0.1;sleep 0` → the `sleep 5` request is ~5s slower while the response body is identical. **Confirms blind injection.**

- **Path traversal:**
  Baseline `?file=welcome.txt` → file contents, 200.
  Probe `?file=../../../../etc/passwd` → response body contains `root:x:0:0:` lines. **Confirms.**
  If `../` is filtered: `?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd` or `?file=..%252f..%252fetc%252fpasswd` (double-encode) succeeds → filter strips only one layer. On Windows, `..\..\windows\win.ini` → `[fonts]`/`[extensions]` section text.

- **CRLF / header injection:**
  Probe `?next=%0d%0aSet-Cookie:%20injected=1` against a parameter reflected into a header → response now carries `Set-Cookie: injected=1`. **Confirms response splitting.** A `Location:` value that echoes input with an added `%0d%0a` and a second header is the classic tell.

- **File-upload validation gap:**
  Upload `avatar.php` with `Content-Type: image/jpeg` → if accepted/stored and later reachable, the type check trusts the spoofed MIME. Or `shell.php.jpg` accepted where only `.jpg` should pass → extension check is suffix-only. **Suggests** missing/weak validation; confirm by retrieving and observing whether it executes or is served back.

- **XXE:**
  POST an XML body with `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` → the response echoes `root:x:0:0:`. **Confirms external-entity processing.** Blind variant: point the entity at an attacker-controlled URL and watch for an out-of-band HTTP/DNS hit.

- **Generic differential 500:**
  Baseline `?q=apple` → 200. Probe `?q=apple'` or `?q=apple<` or `?q=apple;` → 500 / parser error / truncated output. The metacharacter broke a downstream parser → an unsanitised sink exists; this skill narrows down which one.

## When NOT to use it / easily-confused-with

- **A value reflected into the HTML *body* (not a header) is XSS, not this skill.** If `?q=<script>` comes back unescaped inside the page, route to the XSS/client-side skill. This skill's reflection leg is specifically about reflection into *response headers* (CRLF) — body reflection is a different sink.
- **A value reflected and then *evaluated/rendered* by a template engine is SSTI, not command injection.** `{{7*7}}` → `49`, `${7*7}`, `#{7*7}` are template-evaluation tells; route to the template-injection skill. A raw value that merely shows up unchanged is not SSTI.
- **A SQL error (`You have an error in your SQL syntax`, `ORA-`, `SQLSTATE`, `unterminated quoted string`) is SQL injection, not generic input validation.** A lone `'` breaking the query routes to the SQLi skill, even though the trigger (a quote causing a 500) looks similar.
- **An LDAP / NoSQL / XPath sink** (`(`, `*`, `$where`, `[$ne]`, `' or '1'='1`) belongs to its specialised injection skill where one exists, not here.
- **`?url=`/`?redirect=` that fetches a server-side resource** (the server makes the request, not the browser) is SSRF, not header injection — route to the SSRF skill. Header injection is only when the value lands in the *response* headers, not when the server *dereferences* the URL.
- **Authorization/IDOR issues** (changing `?id=123` to `?id=124` and seeing another user's data) are access-control problems, not input-validation — different skill, even though both manipulate a parameter.
- **A path-looking parameter that only switches between a fixed allow-list** (e.g. `?lang=en` vs `?lang=de` with no traversal effect, and `../` is fully rejected after every encoding) is not a finding — don't keep grinding here; move on.
