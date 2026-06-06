# input-validation

The broad input-handling auditor. Fires when the target accepts a user-controlled value that appears to be *acted upon* by the server — passed to a shell, used to build a filesystem path, written into a response header, parsed as a structured document (XML/JSON), or used to decide whether an uploaded file is accepted. Use it when you have an input vector but no proof yet of *which* sink it reaches: the skill sends differential probes to find out. It is the natural first dispatch after parameter discovery (crawling, `gobuster`, form scraping) when the dangerous params are not yet known.

## Dispatch when:

- **A parameter name hints at a filesystem path** — `file`, `path`, `page`, `template`, `doc`, `download`, `dir`, `folder`, `include`, `view`, `lang`, `theme`, `img`, `pdf`, `attachment` → path-traversal / file-read leg.
- **A parameter name hints at a shell or system call** — `cmd`, `exec`, `ping`, `host`, `ip`, `domain`, `url` (when the app runs a network tool), `dns`, `lookup`, `count`, `option`, `format`, `tool`, or anything that looks like it maps to a CLI flag → command-injection leg.
- **The app's function implies it shells out** — "ping this host", traceroute, nslookup, whois, "convert this image", "generate PDF", "run report", "backup", "diagnostics". These wrap system binaries and the user value lands in `system()`/`exec()`/backticks.
- **A value you send is reflected into a response *header*** (not the body) — it appears in `Location:`, `Set-Cookie:`, a custom `X-*` header, or a redirect target → CRLF / header-injection leg.
- **A `Location:` redirect echoes a parameter** (`?url=`, `?redirect=`, `?next=`, `?return=`, `?continue=`) → test for CRLF splitting and header injection.
- **A file-upload form or endpoint** — `multipart/form-data`, `<input type=file>`, an avatar/document/import upload → upload-validation leg.
- **The request body is XML** — `Content-Type: application/xml` / `text/xml` / `application/soap+xml`, a SOAP envelope, a SAML response, an RSS/SVG/DOCX/XLSX ingest, or any `<?xml ...?>` payload the server consumes → XXE leg.
- **The request body is JSON that drives server behaviour** — values that look like they flow into a query, a path, a deserializer, or a command → structured-input leg.
- **A 500 / stack trace appears the instant you insert a metacharacter** — a single `'`, `"`, `;`, `|`, backtick, `<`, `&`, `../`, or NUL byte flips a 200 into a 500 or parser error → the input reaches an unsanitised sink.
- **Differential timing on metacharacters** — a request with `; sleep 5` (or `| ping -c 5`) takes ~5s longer than baseline → blind command-injection signal.
- **Error strings naming a parser or shell** — `sh: 1:`, `/bin/sh`, `No such file or directory`, `failed to open stream`, `DOMDocument`, `SimpleXML`, `lxml`, `SAXParseException`, `java.io.FileNotFoundException`, `system cannot find the path`.
- **A WAF/filter that strips one encoding but not another** — `../` blocked but `%2e%2e%2f` or `..%252f` passes; `;` blocked but `%0a` / `$()` / `{IFS}` is not. The validation is incomplete; the multi-encoding strategy is the right tool to find the bypass.

## Recognition tells (request → response):

- **Command injection (in-band):** Baseline `?host=127.0.0.1` → ping output for one host. Probe `?host=127.0.0.1;id` → response now also contains `uid=0(root) gid=0(root)` or `uid=33(www-data)`; the appended command ran. **Confirms.** Same with `?host=127.0.0.1|whoami`, `?host=$(id)`, `` ?host=`id` ``.
- **Command injection (blind/time-based):** `?host=127.0.0.1;sleep 5` vs `?host=127.0.0.1;sleep 0` → the `sleep 5` request is ~5s slower with an identical body. **Confirms blind injection.**
- **Path traversal:** Baseline `?file=welcome.txt` → file contents, 200. Probe `?file=../../../../etc/passwd` → body contains `root:x:0:0:` lines. **Confirms.** If `../` is filtered: `?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd` or double-encoded `?file=..%252f..%252fetc%252fpasswd` succeeds → filter strips only one layer. On Windows, `..\..\windows\win.ini` → `[fonts]`/`[extensions]` text. Also try absolute paths and NUL-byte truncation.
- **CRLF / header injection:** `?next=%0d%0aSet-Cookie:%20injected=1` against a header-reflected parameter → response now carries `Set-Cookie: injected=1`. **Confirms response splitting.** A `Location:` value that echoes input plus an added `%0d%0a` and a second header is the classic tell (response splitting, cookie injection, cache poisoning).
- **File-upload validation gap:** Upload `avatar.php` with `Content-Type: image/jpeg` → if accepted/stored and later reachable, the type check trusts the spoofed MIME. `shell.php.jpg` accepted where only `.jpg` should pass → extension check is suffix-only. Test which check is missing: extension vs. content-type vs. magic-byte, double extensions, null-byte truncation, case tricks, `Content-Type` spoofing. Confirm by retrieving the file and observing whether it executes or is served back.
- **XXE:** POST `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` → response echoes `root:x:0:0:`. **Confirms external-entity processing** (→ local file read, SSRF, or DoS). Blind variant: point the entity at an attacker-controlled URL and watch for an out-of-band HTTP/DNS hit.
- **Generic differential 500:** Baseline `?q=apple` → 200. Probe `?q=apple'`, `?q=apple<`, or `?q=apple;` → 500 / parser error / truncated output → an unsanitised sink exists; narrow down which one.

## Key techniques:

- Baseline each parameter, then send single marker metacharacters (`'`, `"`, `;`, `|`, backtick, `<`, `&`, `../`, NUL) to learn which reach a shell, filesystem call, header, or parser.
- For command injection, chain with `;`, `|`, `$()`, backticks; fall back to time-based `sleep`/`ping -c` when output is not reflected.
- For path traversal, escalate encodings: raw `../`, URL-encode (`%2e%2e%2f`), double-encode (`..%252f`), unicode, alternate separators, absolute paths, NUL truncation; target `/etc/passwd` and `windows\win.ini`.
- For filters, try every encoding and separator variant (`{IFS}`, `$()`, `%0a`, double-encode) to find the leaky one.
- For uploads, separately probe extension, content-type, and magic-byte checks; combine with double extensions and null bytes.
- For XML, send in-band entity declarations first; if no reflection, switch to out-of-band (OOB) entities for blind XXE.

## When NOT to use / easily confused with:

- **Reflection into the HTML *body*** (e.g. `?q=<script>` returns unescaped in the page) is XSS → client-side skill. This skill's reflection leg is only about reflection into *response headers* (CRLF).
- **A value evaluated/rendered by a template engine** (`{{7*7}}`→`49`, `${7*7}`, `#{7*7}`) is SSTI → template-injection skill. A raw value shown unchanged is not SSTI.
- **A SQL error** (`You have an error in your SQL syntax`, `ORA-`, `SQLSTATE`, `unterminated quoted string`) is SQL injection → SQLi skill, even though a lone `'` causing a 500 looks similar here.
- **LDAP / NoSQL / XPath sinks** (`(`, `*`, `$where`, `[$ne]`, `' or '1'='1`) belong to their specialised injection skill where one exists.
- **`?url=` / `?redirect=` that fetches a server-side resource** (server makes the request, not the browser) is SSRF → SSRF skill. Header injection is only when the value lands in the *response* headers, not when the server dereferences the URL.
- **Authorization/IDOR** (changing `?id=123` to `?id=124` and seeing another user's data) is access-control → different skill.
- **A path-looking parameter that only switches a fixed allow-list** (`?lang=en` vs `?lang=de`, no traversal effect, `../` rejected after every encoding) is not a finding — move on.
