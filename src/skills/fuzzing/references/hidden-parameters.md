# Hidden / unlinked parameter discovery — Open WHEN: an endpoint accepts input but its full parameter set is unknown, or you need parameter wordlists, history-mining recipes, or the detection-oracle detail behind a behaviour-diff hit

A hidden parameter is a query / form / JSON key the UI never sends but
the backend still reads. They are common: debug flags, legacy filters,
internal ids, admin toggles, feature switches. They survive long after
the form that used them was removed. Finding one turns a single known
endpoint into a new input vector for the test skills downstream.

Two independent sources find them — run both, they overlap little:

- **Brute-force**: try a wordlist of candidate names, watch the
  response change.
- **History**: harvest names that were once live (web archives, JS
  bundles, old docs), then replay them against the current endpoint.

---

## Detection oracle — what counts as a hit

Adding a parameter the backend ignores changes nothing in the
response. Adding one it reads shifts the response in some way. A
candidate is a real hidden parameter only when at least one of these
diverges from a baseline request carrying a junk parameter:

| Signal | What it looks like |
|--------|--------------------|
| **Length / words / lines** | body size or word/line count changes (most common, most reliable) |
| **Status code** | 200→500 (it hit a code path that errors), 403→200 (it unlocked something), 200→302 |
| **Reflection** | the name or value appears in the body, a response header, or a redirect `Location` |
| **Timing** | response noticeably slower — the value triggered a DB lookup or external fetch |
| **Error string** | a new stack trace, validation message, or type error naming the parameter |

**Calibration first.** Send two *different* random junk names
(`?zqx1=1`, `?zqx2=1`) and confirm they produce identical responses.
If they differ, the endpoint reflects or logs every unknown
parameter and a naive length-diff will flag everything — switch to
matching on status, error string, or value reflection instead, and
treat name-only reflection as noise.

**Manual oracle** (when Arjun / x8 are unavailable):

```bash
base=$(curl -s "https://target/api/item?zqx_junk=1" | wc -c)
for p in $(cat params.txt); do
  n=$(curl -s "https://target/api/item?$p=swarmprobe" | wc -c)
  [ "$n" -ne "$base" ] && echo "DIFF  $p  ($base -> $n)"
done
```

Re-test each `DIFF` line twice before trusting it — size can vary on
dynamic pages. Arjun / x8 do this diffing automatically and also
stabilise the baseline across multiple requests; prefer them when
present.

---

## Brute-force tooling

```bash
# Arjun — diff-based, GET / POST / JSON, handles baseline stabilisation
arjun -u https://target/api/item --get  -oJ arjun-get.json
arjun -u https://target/api/item --post -m JSON -oJ arjun-json.json
arjun -i crawl-of-endpoints.txt -oJ arjun-all.json   # batch over many URLs

# x8 — fast Rust param scanner, GET then POST body
x8 -u "https://target/api/item" -w params.txt
x8 -u "https://target/api/item" -X POST -w params.txt

# ffuf as a fallback parameter fuzzer (no diff engine — filter manually)
ffuf -u "https://target/api/item?FUZZ=swarmprobe" -w params.txt \
     -mc all -ac -fs <baseline_size>     # then refine with -fw / -fl
```

Order of likelihood the backend reads a candidate: **GET query →
POST form body → JSON body keys → request headers**. Run the cheaper
GET pass first; only escalate to POST/JSON/header passes on the
endpoints that matter.

Header-name discovery (rarer, e.g. `X-Forwarded-For`,
`X-Original-URL`, custom `X-Debug-*`) uses the same oracle with the
candidate placed in a header instead of the query — Param Miner's
"guess headers" mode does this; ffuf can approximate it with
`-H "FUZZ: swarmprobe"` and a header-name wordlist.

---

## Parameter wordlist sources

Parameter lists are different from path lists — names like `debug`,
`admin`, `redirect`, `callback`, `id`, `format`, `template`, `file`,
`url`, `next`, `lang`, not directory names. Start small, escalate on
zero hits.

| List | Where | Size / use |
|------|-------|------------|
| `burp-parameter-names.txt` | SecLists `Discovery/Web-Content/` | broad first pass |
| Arjun `small.txt` / `medium.txt` / `large.txt` | bundled with Arjun (`arjun/db/`) | ranked by real-world frequency; `small` first |
| samlists `sam-cc-parameters-lowercase-all.txt` | the-xentropy/samlists | very dense, crawl-derived; use on stubborn endpoints |
| samlists `sam-cc-parameters-mixedcase-all.txt` | the-xentropy/samlists | adds camelCase variants (`userId`, `redirectUrl`) |

**Tech-stack tuning matters here too.** A Spring app reads
`?debug`, `?trace`, actuator-style keys; a PHP app reads
`?page`, `?file`, `?cmd`; a templating endpoint reads `?template`,
`?view`, `?name`. Add stack-specific names from the fingerprint
before falling back to a giant generic list.

**Self-built corpus** — pull candidate names straight off the target,
they out-perform generic lists:

```bash
# names already present in the live HTML/JS query strings and forms
curl -s https://target/ | grep -oE 'name="[A-Za-z0-9_-]+"' \
  | sed 's/name="//;s/"//' | sort -u >> seed-params.txt
```

---

## History mining — old / unlinked parameters

Names that were once live are high-value candidates the current UI
hides. The web archives remember URLs the site has long since
dropped.

```bash
# Wayback Machine CDX API — plain curl, no extra tool needed.
# fl=original returns the raw URL; collapse=urlkey dedupes.
curl -s "https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey&limit=50000" \
  | grep '?' > wayback-urls.txt

# gau (installed) aggregates Wayback + Common Crawl + OTX + URLScan
gau --threads 5 --subs target.com | grep '?' >> wayback-urls.txt

# Extract distinct parameter NAMES from every harvested query string
grep -oE '[?&][A-Za-z0-9_.\[\]-]+=' wayback-urls.txt \
  | tr -d '?&=' | sort -u > hist-params.txt

# JS bundles hold parameter names the markup never shows —
# query keys and get/setParameter-style calls
for js in $(curl -s https://target/ | grep -oE 'src="[^"]+\.js"' | sed 's/src="//;s/"//'); do
  curl -s "https://target/$js"
done | grep -oE '[?&][A-Za-z0-9_-]{2,}=|[gs]et[A-Za-z]*[Pp]aram[A-Za-z]*\(["'"'"'][A-Za-z0-9_-]+' \
     | grep -oE '[A-Za-z0-9_-]{2,}' | sort -u >> hist-params.txt
```

**Always replay.** A name in the archive only proves it was *once*
accepted. Feed the harvested list back through the live oracle —
Arjun / x8 with `-w hist-params.txt` — and keep only the names the
current endpoint still reacts to:

```bash
arjun -u https://target/api/item --get -w hist-params.txt -oJ hist-confirmed.json
```

---

## Pivot — what a confirmed hidden parameter feeds

A hidden parameter is a lead, not a finding. Route it by what it
appears to do:

| Hidden parameter shape | Hand off to |
|------------------------|-------------|
| swappable record id (`?uid=`, `?account=`) | idor |
| file / path value (`?file=`, `?template=`, `?include=`) | lfi / ssti |
| outbound URL (`?url=`, `?callback=`, `?next=`, `?dest=`) | ssrf / open-redirect |
| value reflected into the page | xss / ssti |
| debug / admin toggle (`?debug=`, `?admin=`, `?test=`) | information-disclosure / auth-testing |
| anything that changes a state it shouldn't | business-logic / mass-assignment |

Persist confirmed names + the endpoint they affect so the downstream
skill consumes them without re-discovering.
