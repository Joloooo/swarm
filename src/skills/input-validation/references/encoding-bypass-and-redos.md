# Encoding-transformation bypass + ReDoS catalogue — Open WHEN: a filter/validator strips or rejects one form of an input but you suspect the server normalizes, decodes, or re-encodes the value after the check (Unicode normalize, percent-decode, base64-decode) — OR a parameter feeds a regex validator and you want to test for catastrophic backtracking (ReDoS)

This file holds two related input-validation gaps: (1) the value the
filter inspects is not the value the sink receives, because a normalize/
decode step runs *after* validation; and (2) a regex validator that can be
made to hang on a crafted input.

---

## 1. Unicode normalization bypass

If the server normalizes (NFC/NFD/NFKC/NFKD) AFTER its filter runs, a
character that the filter does not recognize as dangerous collapses into
the dangerous ASCII one. Submit the exotic code point; the post-filter
normalize step turns it back into the blocked character at the sink.

Workflow: take a payload the filter blocks, swap each significant ASCII
char for a code point that normalizes to it, resubmit, and watch whether
the sink behaves as if the original char arrived.

| Goal char | Use code point | Example input | Normalizes to |
|-----------|----------------|---------------|---------------|
| `..` (traversal) | `‥` U+2025, `︰` U+FE30 | `‥/‥/‥/etc/passwd` | `../../../etc/passwd` |
| `'` (SQLi quote) | `＇` U+FF07 | `＇ or ＇1＇=＇1` | `' or '1'='1` |
| `"` | `＂` U+FF02 | `＂ or ＂1＂=＂1` | `" or "1"="1` |
| `--` (SQL comment) | `﹣` U+FE63 | `admin'﹣﹣` | `admin'--` |
| `.` (host/ext) | `。` U+3002 | `domain。com`, `shell。php` | `domain.com` |
| `/` | `／` U+FF0F | `／／domain.com` | `//domain.com` |
| `<` `>` (XSS) | `＜` U+FF1C, `＞` U+FF1E | `＜img src=a＞` | `<img src=a>` |
| `{{ }}` (SSTI) | `﹛` U+FE5B, `﹜` U+FE5C | `﹛﹛3+3﹜﹜` | `{{3+3}}` |
| `[[ ]]` | `［` U+FF3B, `］` U+FF3D | `［［5+5］］` | `[[5+5]]` |
| `&&` (cmd chain) | `＆` U+FF06 | `＆＆whoami` | `&&whoami` |
| `php` (ext bypass) | `ｐ`U+FF50 `ʰ`U+02B0 `ｐ` | `shell.ｐʰｐ` | `shell.php` |
| `a` (alpha) | `ª` U+00AA, `ᵃ` superscript | `ªdmin` | `admin` |

The full bidirectional reference table:
https://appcheck-ng.com/wp-content/uploads/unicode_normalization.html

Generate candidates locally:

```py
import unicodedata
for form in ("NFC","NFD","NFKC","NFKD"):
    print(form, unicodedata.normalize(form, "shell.ｐʰｐ"))
```

The "Special K" polyglot (`K` U+212A KELVIN SIGN, `ﬁ` ligatures, etc.) is
a single string that survives many filters and expands under NFKC — useful
to fingerprint *whether* a normalize step exists before writing targeted
payloads.

## 2. Punycode / homoglyph confusion

For IDN / email / host / OAuth-provider / password-reset fields: a
look-alike Unicode domain (`раypal.com` with Cyrillic `а`) encodes to a
distinct Punycode host (`xn--ypal-43d9g.com`) yet renders identically.
Use to test host allow-lists and account-takeover flows where the app
compares display form but routes on encoded form (or vice-versa).

MySQL treats some similar characters as equal under the default collation,
so `'admin'` and a homoglyph variant can match the same row in
forgot-password / login lookups:

```sql
SELECT 'a' = 'ᵃ';                              -- 1 (equal, default collation)
SELECT 'a' = 'ᵃ' COLLATE utf8mb4_0900_as_cs;   -- 0 (distinct, strict)
```

Test: register/reset against a homoglyph variant of an existing account
and see whether the DB lookup collapses it onto the real account.

## 3. Layered encoding (decode-after-check)

When one encoding is stripped but another survives, stack them. Try, in
order, against any filter:
- URL-encode the trigger char (`%2e%2e%2f`), then **double**-encode
  (`%252e%252e%252f`) — the filter decodes once, the framework decodes
  again.
- Mixed case / overlong UTF-8 where the platform tolerates it.
- Base64 — if a value is base64-decoded server-side, the filter sees
  opaque text. `echo -n "../../etc/passwd" | base64` →
  `Li4vLi4vZXRjL3Bhc3N3ZA==`; submit that where the app decodes.
- Combine with §1: percent-encode the *normalizing* code point so neither
  the decoder nor the filter sees the literal dangerous char.

Always confirm by differential: benign baseline vs. encoded variant must
produce the sink behavior the plain (blocked) form would.

---

## 4. ReDoS — catastrophic regex backtracking

If a parameter is validated by a regex (email, URL, username, format
checks) or fed to a search/filter that builds a regex, a crafted input can
make the engine backtrack exponentially and hang the request — a
denial-of-service input-validation flaw.

### "Evil regex" shapes (vulnerable when the app's validator looks like these)

- Repetition inside a repeated group: `(a+)+`, `([a-zA-Z]+)*`
- Overlapping alternation under repetition: `(a|aa)+`, `(a|a?)+`
- `(.*a){N}` for N > ~10

### Trigger input

A long run of the inner character followed by one char that forces the
overall match to fail — the engine explores every grouping before giving
up:

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!        # 30–50 'a' then a non-matching char
```

Scale the run length up (50 → 100 → ...) and measure response latency
with `curl -s -o /dev/null -w '%{time_total}\n'`. A response time that
climbs sharply (sub-second → many seconds) as you add characters confirms
backtracking. Keep runs modest so you probe, not knock the service over —
report the latency curve as the finding.

### PHP PCRE note

PHP caps backtracking via `pcre.backtrack_limit` (default 1,000,000).
Exceeding it makes `preg_match()` return **false** rather than 0/1 — i.e.
the match silently *fails*. If a security check is `if (preg_match(...))`,
forcing the limit can flip the check open. Test by sending an input long
enough to blow the limit on a known-vulnerable pattern and watch whether a
validation that should reject the input instead lets it through.

```php
// (a+)+$ against ~1000 'a' + 'b' can exceed the limit → preg_match returns false
```

### Detection helpers (if available on host)

- `regexploit` (doyensec) and `redos-detector` (tjenkinson) statically
  flag vulnerable patterns when you can see the source regex.
- Otherwise treat it black-box: latency-vs-input-length curve via `curl`.

## What to record in the finding

- The vector (which param, which transform/regex).
- For encoding bypass: the blocked plain form, the encoded form that got
  through, and the sink behavior proving the decode/normalize ran after
  the filter.
- For ReDoS: the input length → latency table and the suspected evil
  pattern shape.
