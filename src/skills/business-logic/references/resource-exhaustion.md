# Application-level resource exhaustion (DoS-as-logic) — Open WHEN: an endpoint lets one cheap request force the server into expensive, unbounded work (parsing, recursion, allocation, account state), or the objective is to deny service to a victim through normal features

Treat these as **logic flaws**: the bug is the application accepting an
action whose cost or effect it should bound. They are HIGH severity but
**destructive** — test the *trigger* and prove unbounded growth, then
STOP. Do not actually flood production. A single proof-of-concept
request that demonstrably spikes CPU/memory, or a small bounded loop
that shows the lock/quota mechanism works against the victim, is enough.

## Account-lockout DoS (logic, not flooding)
If the app locks an account after N bad logins, an unauthenticated user
can lock *any* known username out — a denial of service against a
specific victim, with no need to guess the password.
- Oracle: after N wrong attempts the next *correct* login is rejected,
  or the response/timing changes to a "locked" state.
- Demonstrate with a **small** bounded loop, not 100 reqs:
  ```bash
  for i in $(seq 1 6); do
    curl -s -o /dev/null -w "%{http_code}\n" -X POST \
      -d 'username=victim&password=wrong' "$URL/login"
  done
  # then one correct attempt — if it is now refused, lockout DoS is real
  ```
- Related logic-DoS: password-reset / OTP flooding that throttles or
  locks the victim's real channel; "report/flag" features that
  auto-suspend a target account.

## Memory / CPU exhaustion by content (technology-related)
The server does expensive work proportional to user-supplied input.
Send ONE small malformed/over-nested input and watch for a slow,
errored, or timed-out response — that is the signal, do not scale it up.

- **XML bomb (billion laughs)** — entity expansion blows up memory. Any
  XML/SOAP/SVG/DOCX/SAML parser that resolves entities is a candidate:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE lolz [
   <!ENTITY lol "lol">
   <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
   <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
   <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
   <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  ]>
  <lolz>&lol4;</lolz>
  ```
  Keep the depth shallow (4 levels) for a non-destructive probe; if the
  parser already chokes there, deeper nesting confirms it. **SVG upload
  fields are XML** — the same bomb applies wherever SVGs are rendered or
  thumbnailed.
- **GraphQL query depth/breadth** — deeply nested or wide queries make
  the resolver fan out exponentially. Probe with a modest nest and check
  whether the server caps depth/complexity:
  ```graphql
  query { a(first:100){ nodes{ b(first:100){ nodes{ a(first:100){ nodes{ id } } } } } } }
  ```
  No depth limit, no complexity scoring, and no pagination cap = DoS.
  (Also a recon signal: introspection often reveals recursive types.)
- **ReDoS** — a regex with nested/overlapping quantifiers (`(a+)+$`,
  `(.*a){20}`) on a user-controlled field. Send a long string of the
  repeating char plus a non-matching tail and watch response time grow
  super-linearly with input length. Search field, email/URL validators,
  and `User-Agent` parsing are common sinks.
- **Image / media decompression bomb** — upload an image with a tiny
  file size but enormous declared dimensions, or a "pixel flood"
  (e.g. a 0.5MB PNG that decodes to gigapixels). Server-side resize /
  thumbnail / EXIF pipelines allocate width*height*channels bytes and
  OOM. Also: malformed headers with abnormal size fields.
- **Zip/archive bomb** — where the app extracts uploaded archives, a
  nested or highly-compressed zip expands to far more than its on-disk
  size. Confirm the extractor has no decompressed-size cap before
  scaling.
- **JSON / hash-collision / large-array** — a body with millions of keys
  or a deeply nested JSON document; arrays where the server does O(n²)
  work per element.

## Storage / quota exhaustion
The app writes user-supplied data with no cap, eventually filling the
disk, the table, or the inode count. Look for: unbounded log writes
triggered per request, unbounded row inserts (comments, events,
uploads), and SQLite/log files that can grow without rotation. Symptom
when the limit is hit: `No space left on device`, write errors, or the
feature silently failing for all users.

| Filesystem | Practical limit that matters |
| --- | --- |
| FAT32 | 4 GB max **file size** (hit this first on large uploads/logs) |
| EXT4  | ~4 billion inodes (file-count exhaustion) |
| NTFS  | ~4.2 billion MFT entries |
| XFS / BTRFS / ZFS | inode count is dynamic — file-size/disk exhaustion is the realistic vector |

For SwarmAttacker benchmarks: prove the *mechanism* (one oversized or
one over-nested input that errors or hangs the worker) and report it.
Never run an actual sustained flood — it breaks the target for every
later test and is out of scope by default.
