# xxe — when to use

Dispatch this skill whenever the target accepts XML (or an XML-family format) from the client and parses it server-side. The core primitive is always the same: define a custom entity that points at a local file (`<!ENTITY xxe SYSTEM "file:///...">`), reference it inside a value the server processes, and read the file out of the response (or out-of-band). The game is: (1) spot an XML intake surface, (2) prove the parser expands entities, (3) aim the working primitive at the objective file. The dominant failure mode is "had XXE, never pointed it at the flag" — so once `file://` works, read the objective file BY NAME before broad enumeration.

## Trigger signals (dispatch the moment you observe…)

- **A request body that is XML.** `Content-Type: application/xml`, `text/xml`, or `application/soap+xml`; or a body starting with `<?xml ...?>` / `<root>...</root>`. XML on the wire is the single strongest tell.
- **A form/field that literally names XML.** A page like "Upload a book in XML format" with a `<textarea name="xml">` prefilled with a raw `<?xml version="1.0"?>…` document → dispatch immediately.
- **A parameter literally named for XML.** Params/fields named `xml`, `data`, `import`, `upload`, `transform`, `xslt`, `xsl`, `xinclude`, `feed`, `dtd`, or a base64 blob that decodes to markup.
- **A SOAP / WSDL endpoint.** `?wsdl`, `.asmx`, `.svc`, `/services/`, `/soap*`, a `SOAPAction` header, or `<soap:Envelope>`/`<soapenv:Envelope>` framing → XXE belongs in the SOAP body regardless of how JSON-ish the rest of the API looks. These endpoints are often hidden behind auth (e.g. surfacing only after login, in dashboard JS that does `fetch('/soap_service', {headers:{'Content-Type':'application/xml'}, body: '<?xml…'})`).
- **A file-upload that accepts a container/markup format.** `.svg`, `.docx`, `.xlsx`, `.pptx`, `.odt`, `.ods`, `.xml`, `.epub`, `.rss`, `.atom`, `.gpx`, `.kml`, `.plist`, `.pom` → these are XML or ZIP-of-XML; the server-side parser/renderer is the sink. SVG is the most common: an "image upload" labelled e.g. `Profile Image (SVG)` with `<input type="file">` and `enctype="multipart/form-data"` is an XXE surface even when described as plain image upload.
- **A document/image conversion or "preview/thumbnail" feature.** Upload-to-PDF, SVG→PNG/PDF rasterisers, "generate report", "import config", e-reader/EPUB ingestion, invoice/XML import → a server-side XML or XSLT pipeline is almost always behind it.
- **A SAML flow.** `SAMLRequest=` / `SAMLResponse=` form fields, an Assertion Consumer Service (`/saml/acs`, `/sso/acs`, `/Shibboleth.sso/SAML2/POST`), or base64 that decodes to `<saml:` XML → the SP parses XML, often *before* signature verification, so an unsigned DOCTYPE still resolves.
- **XML-RPC / WebDAV / RSS surfaces.** `xmlrpc.php`, `/RPC2`, `PROPFIND`/`MKCOL` WebDAV verbs, feed-import or "subscribe to RSS" features.
- **Content-negotiation that honours Accept/Content-Type for XML.** A normally-JSON endpoint that returns XML for `Accept: application/xml`, or stops erroring when you flip the body to `text/xml` → an unhardened auto-negotiating parser.
- **The submitted XML is reflected back.** If POSTing an XML document returns it inside a `<pre>…</pre>` block, an inline rendered `<svg>`, or a field value (`<account_id>`, `<Title>`) → you have a read-back channel that makes in-band XXE trivially confirmable.
- **Parser error strings leaking in responses.** `DOCTYPE is disallowed`, `org.xml.sax.SAXParseException`, `lxml.etree.XMLSyntaxError`, `xmlParseEntityRef`, `Premature end of file`, `Content is not allowed in prolog`, `DTD ... not allowed`, `external entity`, `libxml2`, `Xerces`, `Expat`, `nokogiri` → you've fingerprinted an XML parser and its hardening posture.
- **Server/stack fingerprints that pair with naive XML parsing.** Flask/Werkzeug (`Server: Werkzeug/… Python/3.x`) or `server: uvicorn` (FastAPI) apps that take XML bodies. Combined with any XML intake, treat XXE as the primary hypothesis.
- **The objective points at a local file** ("read /app/flag.txt", "the goal is to read …"). When the objective is reading a file on disk and any XML surface exists, XXE `file://` retrieval is the intended path — enumerate the named file FIRST.

## Use-case scenarios

- **Any endpoint whose body is XML.** Textbook case: inject a `<!DOCTYPE>` with an external entity, read a file or pivot to SSRF. The moment the wire format is XML, this is the right move before anything else.
- **"Validate / submit / preview this XML" surfaces.** Anything that takes an XML document, tells you whether it parsed (e.g. "You have append this book successfully !"), and shows the result — the result echo is your exfil channel.
- **Upload-driven attacks on "modern" JSON apps.** Even when the whole API is JSON, file uploads frequently still hit XML parsers underneath. SVGs feed image libraries and rasterisers; Office/ODF/EPUB files are ZIPs whose `document.xml` / `content.opf` / `META-INF/container.xml` are parsed. Often the *highest-yield* surface on an app that otherwise looks XML-free. A rendered-inline SVG is the read-back channel — your `&xxe;` becomes the file's text.
- **SOAP / SAML at the auth and integration edge.** Identity federation and B2B integrations keep XML at the protocol layer. SAML SPs parse before checking the signature, so an unsigned DOCTYPE still resolves. Deserve a separate pass even after the main API has been swept, including post-login.
- **Server-side transform / report engines.** XSLT processors, Jasper/FOP report generators, and `<?xml-stylesheet?>` consumers can fetch external resources via XSLT `document()` even when ordinary entity resolution is locked down. If recon hints at "export to PDF", "render template", or "apply stylesheet", route here.
- **Background / async processors.** Email-to-XML ingestion, queue workers, CI artifact parsers (JUnit `report.xml`, Jenkins `config.xml`, Maven `pom.xml`), and admission webhooks parse XML out-of-band, often with a laxer parser config than the front-end API — worth a dedicated probe even if the synchronous path was hardened.
- **SSRF / internal-recon pivot.** When you need to reach cloud metadata (`169.254.169.254`, ECS `169.254.170.2`), Docker (`2375`), Redis, kubelet, or an internal admin panel and the only foothold is an XML parser, XXE is the SSRF primitive — use it to port-scan internal services via timing differentials.
- **As a file-read primitive for LFI-style objectives.** XXE `file://` retrieval *is* arbitrary local file read; XXE and LFI overlap. If the objective is "read a file on disk," XXE is one of the tools to reach for, not a separate unrelated class.
- **Blind / out-of-band conditions.** When an XML body is accepted but nothing useful is reflected, the parameter-entity + external-DTD OOB technique exfiltrates via DNS/HTTP callbacks. Reflected output is *not* required to justify dispatch.

## Concrete tells (request → response examples)

- **Capability probe — entity-expansion proof (do this FIRST, before any `file://`):**
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE r [<!ENTITY test "ENTITY_EXPANDED_12345">]>
  <r>&test;</r>
  ```
  → If the response echoes the literal `ENTITY_EXPANDED_12345` where `&test;` was (e.g. `<Title>ENTITY_EXPANDED_12345</Title>`), the parser expands entities and XXE is live (also confirms billion-laughs DoS reachability).

- **In-band local file read via SYSTEM entity:**
  ```xml
  <!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  <r>&xxe;</r>
  ```
  → A response field containing `root:x:0:0:` (or `[fonts]`/`[extensions]` for `file:///c:/windows/win.ini` on Windows) is unambiguous XXE confirmation.

- **SVG-wrapped XXE:** upload
  ```xml
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///app/flag.txt"> ]><svg …><text>&xxe;</text></svg>
  ```
  → the app's rendered "Current Image:" block returns `<svg…><text>flag{…}</text></svg>` with file contents in place of the entity.

- **Read app source to locate the flag.** Once `file://` works, pull `file:///app/app.py` (or equivalent). Source like `with open('flag.txt', 'r') as file: FLAG = file.read()` tells you the flag is at a path **relative to the app's CWD** (`flag.txt` / `/app/flag.txt`), not necessarily where you first guessed. Immediately read that exact path with the SAME working entity.

- **Error-based leak:** send a malformed entity / bad path → response includes `java.io.FileNotFoundException: /etc/passwd` or `failed to load external entity "file:///..."` with the path/content interpolated. The exception text *is* your read channel.

- **Content-Type swap on a JSON endpoint:** take a working JSON request, change `Content-Type` to `application/xml` and send an XXE-laced body → going from `415 Unsupported Media Type` to a `200`/parsed response (or an XML parser error) means the endpoint silently accepts XML.

- **OOB confirmation (no reflection):** point a parameter entity at your external DTD on a host you control → an inbound DNS/HTTP hit to `attacker.tld` (ideally with a leaked filename/hostname encoded in the subdomain) confirms blind XXE even with an empty body.

- **DOCTYPE-rejection fingerprint:** a `DOCTYPE is disallowed` / `DTD prohibited` error means hardening is present *but XML is still being parsed* — pivot to XInclude (`xmlns:xi` + `<xi:include parse="text" href="file://...">`) or XSLT, which are often still enabled.

## When NOT to use it / easily-confused-with

- **A reflected value alone is not XXE — it must be *parsed as XML* and the entity must expand.** If `&test;` comes back literally (un-expanded), or your angle-bracket input is reflected into an HTML page, that is **XSS** / plain reflection, not XXE. The deciding test is the expansion-proof entity above. Template syntax (`{{...}}`, `${...}`) evaluated server-side is **SSTI**, not XXE.
- **JSON / form-encoded / multipart-only endpoints.** If the body is JSON, `x-www-form-urlencoded`, or plain multipart with no XML part, and the server returns `415` or errors on XML, there is no XML sink. An XML-looking *response* doesn't qualify either — many apps return `Content-Type: application/xml` for normal data without parsing client-supplied XML. The surface only qualifies when the server *consumes* an XML body you control.
- **A URL/host parameter that fetches a resource.** If a plain parameter (`url=`, `image=`, `callback=`, `webhook=`) drives a server-side request, that's **direct SSRF** — route to the SSRF skill. XXE is only right when the SSRF must be smuggled *through an XML parser*.
- **`file=`/`path=` parameters reading files directly.** Direct path traversal / **LFI** does not need XML; only use XXE when the file read is mediated by external-entity resolution.
- **Entities echoed literally with no I/O.** If the parser returns `&xxe;` verbatim or echoes the entity string without any file/network access, entity resolution is disabled — false positive, not a finding. Confirm real I/O before claiming impact.
- **Client-side-only XML.** XML processed entirely in the browser (e.g. JS `DOMParser`) never reaches a server parser — out of scope.
- **Hardened parser, DTD fully blocked, no XInclude/XSLT path.** If `DOCTYPE` is rejected *and* no transclusion channel exists, the surface is closed; record and move on rather than burning iterations.
- **Don't stop at the auth / default-creds layer.** When a surface is tagged both `xxe` and `default_credentials`, the creds are only the door — the XML endpoint behind it is the vulnerability. Logging in is a prerequisite, not the objective.
- **Don't confuse "XXE confirmed" with "objective met."** The single biggest failure mode is proving arbitrary file read (passwd, app.py) but never including the actual flag file in the enumeration list. The moment `file://` works, read the objective file BY NAME (resolving the relative path the source reveals) before broad enumeration.
