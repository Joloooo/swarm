# Leaked IIS machineKey → ViewState — Open WHEN: a leaked `web.config` / `machine.config` exposes a `<machineKey>`, or an ASP.NET app reflects a known/default key

A leaked ASP.NET `machineKey` (`validationKey` + `decryptionKey`) is a
Critical secret leak: it signs and encrypts `__VIEWSTATE` and forms-auth
cookies, so possession turns a disclosed config into a signed-object
deserialization sink. This belongs to information-disclosure because the
*leak of the key* is the finding; the chain note records the impact.

## Where the key leaks from

`<machineKey validationKey="..." decryptionKey="..." validation="SHA1"
decryption="AES" />` in a recovered `web.config`, or `machine.config` at:
```
C:\Windows\Microsoft.NET\Framework[64]\v{2.0.50727,4.0.30319}\config\machine.config
```
If the key is auto-generated it is in the registry
(`HKCU\Software\Microsoft\ASP.NET\...\AutoGenKey*`), not the file.

## When NO key is leaked — test for a KNOWN/default key

Many apps ship a hardcoded sample key copied from a blog/docs. Capture a
`__VIEWSTATE` + `__VIEWSTATEGENERATOR` from any page and match it against
public key lists:
- `blacklanternsecurity/badsecrets` (`blacklist3r.py --viewstate ... --generator ...`)
- `isclayton/viewstalker`, `0xacb/viewgen --guess`, `NotSoSecure/Blacklist3r`

A hit means the app's signing key is publicly known = same impact as a leak.

## ViewState format tells you what protection is on

Decode `__VIEWSTATE` first (`viewgen --decode`). Unencrypted ViewState
usually begins `/wEP`. Default before Sept 2014: MAC disabled.

| ViewState shape | Protection |
|---|---|
| Base64 only | no MAC, no encryption |
| Base64 + MAC | `EnableViewStateMac=True` |
| Base64 + encrypted | `ViewStateEncryptionMode=True` |

## Chain note (record as impact, do not run unless explicitly in scope)

With the validation/decryption keys, `ysoserial.net -p ViewState` forges a
signed `__VIEWSTATE` whose deserialization runs a command — a known RCE chain
(reference only; only the leak itself is this skill's finding):
```
ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --generator=<__VIEWSTATEGENERATOR> --validationalg=SHA1 \
  --validationkey=<validationKey> -c "<cmd>"
```
The same keys also decrypt/forge forms-auth cookies
(`aspnetCryptTools`, `--purpose=owin.cookie`).

## Reporting

Report as: "ASP.NET machineKey disclosed/known → ViewState and auth-cookie
integrity broken → signed-object deserialization RCE reachable." Proof = the
key value + a decoded ViewState confirming the key matches the app. Stop
before executing a forged-object command unless command execution is in scope.
