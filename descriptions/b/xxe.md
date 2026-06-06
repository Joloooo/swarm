# xxe — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A request body that is XML.** If you see `Content-Type: application/xml`, `text/xml`, `application/soap+xml`, or a body that starts with `<?xml ...?>` or `<root>...</root>` → this skill applies. XML on the wire is the single strongest tell.
- **A SOAP / WSDL endpoint.** If recon finds `?wsdl`, a `.asmx`, `.svc`, `/services/`, a SOAPAction header, or `<soap:Envelope>` framing → XXE belongs in the SOAP body regardless of how JSON-ish the rest of the API is.
- **A SAML flow.** If you see `SAMLRequest=` / `SAMLResponse=` form fields, an Assertion Consumer Service (`/saml/acs`, `/sso/acs`, `/Shibboleth.sso/SAML2/POST`), or base64 that decodes to `<saml:` XML → the SP parses XML before signature verification; dispatch here.
- **A file-upload that accepts a container/markup format.** If the app takes `.svg`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.xml`, `.epub`, `.rss`, `.atom`, `.gpx`, `.kml`, `.plist`, or `.pom` → these are XML or ZIP-of-XML; the server-side parser/renderer is the sink.
- **A document/image conversion or "preview/thumbnail" feature.** Upload-to-PDF, SVG→PNG/PDF rasterisers, "generate report", "import config", e-reader/EPUB ingestion, invoice/XML import → a server-side XML or XSLT pipeline is almost always behind it.
- **Content-negotiation that honours Accept/Content-Type for XML.** If a normally-JSON endpoint returns XML when you send `Accept: application/xml`, or stops erroring when you flip the body to `text/xml` → an unhardened auto-negotiating parser is exposed. Dispatch here.
- **Parser error strings leaking in responses.** If you see substrings like `DOCTYPE is disallowed`, `org.xml.sax.SAXParseException`, `lxml.etree.XMLSyntaxError`, `xmlParseEntityRef`, `Premature end of file`, `Content is not allowed in prolog`, `DTD ... not allowed`, `external entity`, `libxml2`, `Xerces`, `Expat`, `nokogiri` → you've fingerprinted an XML parser and its hardening posture. This is a green light.
- **A parameter literally named for XML.** Params/fields named `xml`, `data`, `import`, `upload`, `transform`, `xslt`, `xsl`, `xinclude`, `feed`, `dtd`, or a base64 blob that decodes to markup → probe for entity expansion.
- **XML-RPC / WebDAV / RSS surfaces.** `xmlrpc.php`, `/RPC2`, `PROPFIND`/`MKCOL` WebDAV verbs, feed-import or "subscribe to RSS" features → all are XML parsers reachable from outside.

## Use-case scenarios

- **Any endpoint whose body is XML.** The textbook case: a REST/SOAP endpoint takes an XML document, you inject a `<!DOCTYPE>` with an external entity, and read a file or pivot to SSRF. The moment the wire format is XML, this is the right move before anything else.
- **Upload-driven attacks on "modern" JSON apps.** Even when the whole API is JSON, file uploads frequently still hit XML parsers underneath. SVGs feed image libraries and rasterisers; Office/ODF/EPUB files are ZIPs whose `document.xml` / `content.opf` / `META-INF/container.xml` are parsed; this is often the *highest-yield* surface on an app that otherwise looks XML-free. Dispatch here whenever the upload accepts one of those formats.
- **SOAP / SAML at the auth and integration edge.** Identity federation and B2B integrations keep XML at the protocol layer. SAML SPs and SOAP services parse the document — and SAML SPs notoriously parse *before* checking the signature, so an unsigned DOCTYPE still resolves. These deserve a separate pass even after the main API has been swept.
- **Server-side transform / report engines.** XSLT processors, Jasper/FOP report generators, and `<?xml-stylesheet?>` consumers can fetch external resources via XSLT `document()` even when ordinary entity resolution is locked down. If recon hints at "export to PDF", "render template", or "apply stylesheet", route here.
- **Background / async processors.** Email-to-XML ingestion, queue workers, CI artifact parsers (JUnit `report.xml` in GitLab, Jenkins `config.xml`, Maven `pom.xml`), and admission webhooks parse XML out-of-band. They frequently run a *different, laxer* parser config than the front-end API — worth a dedicated probe even if the synchronous path was hardened.
- **SSRF / internal-recon pivot.** When you need to reach cloud metadata (`169.254.169.254`, ECS `169.254.170.2`), Docker (`2375`), Redis, kubelet, or an internal admin panel and the only foothold is an XML parser, XXE is the SSRF primitive — use it to port-scan internal services via timing differentials.
- **Blind / out-of-band conditions.** When an XML body is accepted but nothing useful is reflected, this skill's parameter-entity + external-DTD OOB technique exfiltrates via DNS/HTTP callbacks. Reflected output is *not* required to justify dispatch.

## Concrete tells (request → response examples)

- **Capability probe (internal entity, no I/O):**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY test "INJECTED">]>
  <r>&test;</r>
  ```
  → If the response echoes `INJECTED` where `&test;` was, the parser expands entities. That alone justifies escalating to external entities (and confirms billion-laughs DoS reachability).

- **Local file read confirmation:**
  ```xml
  <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <r>&xxe;</r>
  ```
  → A response containing `root:x:0:0:` (or `[fonts]`/`[extensions]` for `file:///c:/windows/win.ini` on Windows) is a confirmed classic XXE.

- **Error-based leak:** send a malformed entity / bad path → response includes `java.io.FileNotFoundException: /etc/passwd` or `failed to load external entity "file:///..."` with the path/content interpolated. The exception text *is* your read channel.

- **Content-Type swap on a JSON endpoint:** take a working JSON request, change `Content-Type` to `application/xml` and send an XXE-laced XML body. → If you go from `415 Unsupported Media Type` to a `200`/parsed response (or an XML parser error), the endpoint silently accepts XML — escalate.

- **OOB confirmation (no reflection):** point a parameter entity at your external DTD on a host you control → an inbound DNS/HTTP hit to `attacker.tld` (ideally with a leaked filename/hostname encoded in the subdomain) confirms blind XXE even with an empty HTTP response body.

- **DOCTYPE-rejection fingerprint:** a `DOCTYPE is disallowed` / `DTD prohibited` error means hardening is present *but XML is still being parsed* — pivot to XInclude (`xmlns:xi` + `<xi:include parse="text" href="file://...">`) or XSLT, which are often still enabled.

## When NOT to use it / easily-confused-with

- **JSON / form-encoded / multipart-only endpoints.** If the body is JSON, `application/x-www-form-urlencoded`, or plain multipart with no XML part, and the server returns `415` or errors when you send XML, there is no XML sink — do not route here.
- **A `<...>`-looking value that is reflected, not parsed.** If your angle-bracket input comes back in an HTML page unescaped, that is **XSS**, not XXE. XXE requires a server-side *XML parser*, not mere reflection of markup. Likewise, template syntax (`{{...}}`, `${...}`) evaluated server-side is **SSTI**, not XXE.
- **A URL/host parameter that fetches a resource.** If a plain parameter (`url=`, `image=`, `callback=`, `webhook=`) drives a server-side request, that's a **direct SSRF** primitive — route to the SSRF skill. XXE is only the right tool when the SSRF must be smuggled *through an XML parser*.
- **`file=`/`path=` parameters reading arbitrary files directly.** Direct path traversal / **LFI** does not need XML; only use XXE when the file read is mediated by external-entity resolution.
- **Entities echoed literally with no I/O.** If the parser returns `&xxe;` verbatim, or echoes the entity *string* without performing any file/network access, entity resolution is disabled — this is a false positive, not a finding. Confirm real I/O before claiming impact.
- **Client-side-only XML.** XML processed entirely in the browser (e.g. a JS `DOMParser`) never reaches a server parser — not in scope.
- **Hardened parser, DTD fully blocked, no XInclude/XSLT path.** If `DOCTYPE` is rejected *and* no transclusion (XInclude/XSLT) channel exists, the surface is closed; record and move on rather than burning iterations.

B:xxe done

