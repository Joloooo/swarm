# crypto — when to use

## Trigger signals (dispatch this skill the moment you observe…)
- If a service answers on **443, 8443, 9443, 4443, or any `https://`** URL → the TLS configuration is in scope; enumerate protocols, ciphers, and the certificate.
- If a login form, password-change form, or API endpoint **posts to `http://` (not `https://`)**, or the page is served over HTTP at all → sensitive data is travelling in cleartext; this skill applies.
- If an HTTPS response is **missing `Strict-Transport-Security`**, or HSTS is present but `max-age` is small / lacks `includeSubDomains` → weak transport hardening to report.
- If a session/CSRF/`Set-Cookie` value lacks the **`Secure`** flag (or lacks `HttpOnly`/`SameSite`) on an HTTPS site → insecure cookie transport.
- If you see **mixed content**: an HTTPS page that loads `http://` scripts, images, or form actions → downgrade exposure.
- If a token in a cookie, URL, or response body looks **short, sequential, time-based, or base64 of a guessable value** (e.g. decodes to `userid:timestamp`, or two consecutive sessions differ by a small delta) → predictable-token analysis.
- If you can read a **password hash or "verifier"** anywhere (DB dump, debug page, API leak) and it is **32 hex chars (MD5)** or **40 hex chars (SHA-1)**, or unsalted → weak hashing.
- If a **reset/verification/magic-link token** appears in a URL and looks like a hash of the email, a counter, or a UUIDv1 (timestamp-derived) → forge-the-token path.
- If recon surfaces **sensitive values in URLs, HTML comments, inline JS, `.js` bundles, or `localStorage`/`sessionStorage`** (API keys, JWT secrets, hardcoded creds, internal hostnames) → insecure-storage indicators.
- If a scanner (sslscan/testssl/nmap) flags **SSLv2/SSLv3, TLS 1.0/1.1, RC4, 3DES, EXPORT, NULL, anonymous DH, or a self-signed/expired/wildcard-mismatch cert** → classic weak-TLS findings.
- If a known TLS CVE fingerprint shows up — **Heartbleed (CVE-2014-0160), POODLE, BEAST, FREAK, Logjam, ROBOT, DROWN, CRIME** → escalate to the deep audit.

## Use-case scenarios
- **TLS posture audit on any HTTPS surface.** The moment recon shows port 443 (or any TLS port), run the protocol/cipher/cert enumeration. This is the default "always do it" pass on a black-box target with HTTPS — cheap, non-destructive, and it frequently turns up legacy protocol support or an expired/mismatched cert that chains into MITM or trust-bypass arguments later.
- **Cleartext credential transmission.** When a login or sensitive form is reachable over plain HTTP, or the site never redirects HTTP→HTTPS, this skill documents the exposure: credentials, session cookies, or API keys observable on the wire. Pair with the missing-HSTS / missing-Secure-flag findings for a full transport-security story.
- **Token randomness / predictability analysis.** When the app hands out session IDs, password-reset tokens, email-verification links, or API keys, collect several samples and look for structure. Sequential counters, timestamps, weak PRNG output, or base64/hex that decodes to guessable fields all mean an attacker can predict or forge another user's token — a path to account takeover that lives in the crypto domain.
- **Weak/again unsalted hashing.** Whenever a hash is exposed (verbose error, debug endpoint, accessible storage, or a value you exfiltrated through another bug), identify the algorithm by length and format. MD5/SHA-1/unsalted hashing is a reportable weakness on its own and tells you offline cracking is viable.
- **Insecure storage / secret leakage.** Sweep front-end artifacts — HTML comments, JS files, source maps, `localStorage`, query strings — for secrets that should never be client-side. This is the "data at rest in the wrong place" half of the crypto remit.
- **TLS-specific CVE confirmation.** When a quick cipher scan hints at an old OpenSSL or a vulnerable suite, the deep audit confirms Heartbleed/ROBOT/POODLE and similar, turning a "weak config" note into a concrete exploitable finding.

## Concrete tells (request → response examples)
- `curl -vkI https://target/` → response headers contain **no `Strict-Transport-Security`** line, or the cert section shows `subject: CN=localhost` / `expired` / `self-signed`. Confirms weak transport config.
- `sslscan target:443` → output lists `Accepted  TLSv1.0`, `Accepted  SSLv3`, `RC4`, `DES-CBC3-SHA`, or `Anonymous`/`NULL` ciphers. Confirms legacy-protocol / weak-cipher support.
- `testssl.sh https://target/` → a line like `Heartbleed (CVE-2014-0160): VULNERABLE` or `ROBOT: VULNERABLE`. Confirms an exploitable TLS CVE.
- Capture two sessions: `Set-Cookie: SESSION=1001` then a second login gives `SESSION=1002` → tokens are sequential → predictable-session takeover.
- `Set-Cookie: token=YWRtaW46MTcwMDAwMDAwMA==` → base64-decodes to `admin:1700000000` → forgeable token, weak construction.
- A reset link `https://target/reset?t=5f4dcc3b5aa765d61d8327deb882cf99` where the value is **MD5 of the email/username** → forge another user's reset token.
- Login form HTML shows `<form action="http://target/login" method="post">` on an otherwise-HTTPS page → credentials submitted in cleartext.
- `grep` of a downloaded `app.js` reveals `const API_KEY = "AKIA..."` or `jwtSecret = "..."` → secret leaked to the client → insecure storage.

## When NOT to use it / easily-confused-with
- **A reflected or stored value that is rendered, not transmitted-insecurely, is XSS — not crypto.** A token appearing in the page is only a crypto issue if its *value is predictable/forgeable* or it leaks a secret; merely being reflected is an injection concern.
- **A JWT with a tamperable signature** (`alg:none`, weak HMAC secret, key confusion) is primarily an **auth/JWT** problem; route there. Bring it here only when the finding is specifically that the *signing secret is weak/crackable* or the hashing algorithm itself is broken.
- **IDOR / broken-object-access** (changing `id=1` to `id=2` to read another user's data) is an authorization bug, not predictable-token crypto — unless the identifier you're tampering with is a *security token* that should have been unguessable.
- **Plain missing-authentication or default credentials** belong to auth/access skills, not crypto. Crypto is about *how* secrets and transport are protected, not whether a gate exists at all.
- **Don't dispatch on the mere presence of HTTPS done right.** A modern TLS 1.3-only config with a valid cert, HSTS, and Secure cookies has nothing for this skill — note it as hardened and move on rather than burning iterations.
- **Server-side template/command evaluation** of an input is SSTI/RCE, not crypto, even if the input passed through a token field. Crypto cares about the secret's strength and transport, not code execution.
