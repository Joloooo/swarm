# Leaked secret detection & validation — Open WHEN: you have pulled JS bundles, a `.env`, a config dump, or a reconstructed repo and need to find keys in it and confirm which are live

## Where secrets hide

- **Source code / bundles** — hardcoded `api_key = "..."`, `const TOKEN = "..."`.
  Always grep minified JS + source maps.
- **Config files** — `.env`, `config.json`, `settings.py`, `appsettings.json`,
  `web.config`, `.aws/credentials`, `docker-compose.yml`.
- **DVCS history** — committed then "removed" (see `references/dvcs-extraction.md`).
- **Debug / log output** — keys echoed into stack traces or verbose logs.
- **Docker image layers** — `ENV`/`ARG` baked secrets.

## Regex shapes worth grepping

High-signal patterns (grep recovered files with these):
```
AKIA[0-9A-Z]{16}                                   # AWS access key id
[0-9a-z]+\.execute-api\.[0-9a-z._-]+\.amazonaws\.com  # AWS API gateway host
-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----    # private keys
ghp_[0-9A-Za-z]{36}                                # GitHub personal token
xox[baprs]-[0-9A-Za-z-]+                           # Slack token
eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.             # JWT (header.payload.)
```
For breadth, scanners ship large pattern DBs: `trufflehog`,
`gitleaks`, `noseyparker` (run against the reconstructed repo + its history),
and the `secrets-patterns-db` regex set. `nuclei -t token-spray/` tests one
token against many provider endpoints at once.

## Validate before reporting (minimal, read-only probe)

A key is only a finding if it is live AND in scope. Validate with the
provider's cheapest identity/echo endpoint — never a state-changing call:
```
# Telegram bot token
curl https://api.telegram.org/bot<TOKEN>/getMe
# AWS keys (identity only, no resource access)
aws sts get-caller-identity     # if aws CLI is available in scope
```
`keyhacks` documents a one-liner validity check per provider. Stop at "this key
is valid and maps to identity/account X" — do not enumerate the account.

## Reporting

Report the leaked secret's **type, source location, and validity state**
(live / revoked / unknown). A live cloud/DB/SMTP/JWT-signing key is Critical:
chain note is "key → provider control-plane / data access," but the proof stops
at identity confirmation. A revoked or scoped-to-nothing key is informational.
