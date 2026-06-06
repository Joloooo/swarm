# insecure-file-uploads — when to use

## Trigger signals (dispatch this skill the moment you observe…)

- **A form with `enctype="multipart/form-data"` and an `<input type="file">`** → there is an upload sink; this skill applies.
- **Any field named `file`, `upload`, `avatar`, `image`, `photo`, `attachment`, `import`, `document`, `media`, `logo`, `banner`, `cv`, `resume`, `proof`, `screenshot`** → upload surface, dispatch here even if the input is buried in a multi-step form.
- **A successful upload that returns a URL or path back to you** (`{"url":"/uploads/abc.jpg"}`, `Location: /files/123`, an `<img src>` pointing at your file) → you can now reach the stored object — the highest-value condition for this class.
- **The stored file is served from a guessable/incremental path** (`/uploads/1.jpg`, `/media/2024/03/...`, `/u/<userid>/avatar.png`) → retrieval is trivial, test execution/inline rendering.
- **The response echoes the original filename** (in JSON, an HTML page, a `Content-Disposition`, or a directory listing) → filename is preserved → path-traversal and double-extension games are in scope.
- **`Content-Type: image/svg+xml` or `text/html` on a download you uploaded**, or **missing `X-Content-Type-Options: nosniff`** → stored-XSS-via-upload path; dispatch here, not generic XSS.
- **`Content-Disposition: inline`** (rather than `attachment`) on user-uploaded content → the browser will render it, so HTML/SVG payloads execute.
- **Server reflects/echoes your `Content-Type` back on retrieval** (you send `image/jpeg`, you get `image/jpeg`; you send `text/html`, you get `text/html`) → MIME is attacker-controlled → high signal.
- **An error string naming a media tool**: `ImageMagick`, `convert`, `MagickWand`, `Ghostscript`, `gs`, `ExifTool`, `libvips`, `libheif`, `ffmpeg`, `LibreOffice`, `unoconv`, `wkhtmltopdf` → a server-side processor touches the file → toolchain-RCE territory.
- **Upload triggers a visible thumbnail / preview / PDF-to-image conversion** → a parser runs server-side; even "image-only" endpoints become RCE candidates.
- **A presigned-URL flow**: response contains `X-Amz-Signature`, `x-goog-signature`, an S3/GCS/Azure-blob hostname, or you `POST`/`PUT` directly to `*.amazonaws.com` / `*.blob.core.windows.net` / `storage.googleapis.com` → direct-to-cloud abuse path; the server-side validator is likely bypassed entirely.
- **A resumable/chunked protocol**: `tus-resumable` headers, `uploadId` / `?uploads`, `partNumber`, an `init`/`create` → `chunk` → `complete`/`finalize` sequence → finalize-step validation gaps apply.
- **An endpoint that accepts a `.zip` / `.tar` / `.tar.gz` / `.jar` and extracts it** (importers, "restore backup", "bulk upload", plugin/theme installers) → Zip Slip / symlink / zip-bomb scope.
- **A "fetch from URL" upload** (`?url=`, `imageUrl`, `import_from`, "upload by link") → SSRF/LFI pivot lives here too; the file fetcher is the interesting part.
- **Client-side-only validation**: the page rejects `.php` in JavaScript but you can replay the POST directly with `curl`/Repeater → validation is cosmetic; dispatch immediately.
- **Server tech fingerprint that makes uploaded code executable**: `X-Powered-By: PHP`, `Server: Apache` with `.php` handling, IIS/`ASP.NET`, Tomcat/JSP, plus an upload that lands inside the web root → web-shell path.

## Use-case scenarios

- **Web-root-writable PHP/ASP/JSP apps.** Classic LAMP/IIS/Tomcat targets where uploads land under a path the server will execute. The whole game is getting a file with an executable extension (or a handler-flipping config like `.htaccess` / `.user.ini` / `web.config`) past the validator and then requesting it. This is the highest-impact scenario (RCE) and the most common XBOW-style benchmark shape.
- **Profile/avatar/document uploads in modern SPAs.** Even when the file is stored in object storage and served via CDN, weak MIME handling yields stored XSS, and the SVG/HTML-served-inline path is very common because frameworks default `Content-Type` from the uploaded file or from the extension.
- **Media pipelines.** Any product that resizes, thumbnails, watermarks, transcodes, or converts (image hosts, document viewers, "export to PDF", video platforms). The processor (ImageMagick/Ghostscript/ExifTool/ffmpeg/libheif) is a far larger input surface than the storage layer — fingerprint the tool and version, then pick the matching CVE.
- **Bulk importers and archive handlers.** "Import users from CSV", "restore from backup", plugin/theme/extension installers, anything that unzips. Zip Slip writes outside the extraction directory (e.g. overwrite a config or drop a shell); symlink-in-zip reads arbitrary files; zip-bombs cause DoS.
- **Direct-to-cloud (presigned) uploads.** The browser uploads straight to S3/GCS/Azure using a server-issued presigned URL or POST policy. If the policy's `conditions` are loose (no key-prefix lock, no content-type lock, wide expiry), the attacker controls the object key, content type, and disposition — server-side validation never runs on the actual bytes.
- **Resumable/multipart finalize tricks.** tus and S3 multipart split work across `init` → `chunk` → `complete`. If validation only fires at `init`, you declare a benign type up front and swap content/metadata at `complete`.
- **Filename as an injection primitive.** Where the filename is shelled out, used in a SQL insert, used to build a path, or passed to a downstream tool, the filename field itself is the payload carrier (command injection, SQLi, path traversal, SSRF via UNC).
- **Rich-text editors and "embed an image" features.** RTEs almost always have an image/attachment upload behind them; they're easy to miss because the file input is hidden inside the editor toolbar.

## Concrete tells (request → response examples)

- **Magic-vs-extension probe.** Upload a file whose bytes start with `GIF89a` but whose name is `x.php`, content-type `image/jpeg`.
  - Stored as `x.php` and served executable → critical (RCE path).
  - Renamed to a random name but kept `.php` → still test execution.
  - Rejected → the validator checks extension; move to double-extension / null-byte tricks.
- **Double extension.** `shell.php.jpg`, `shell.jpg.php`, `shell.phtml`, `shell.php5`, `shell.pHp`.
  - Any accepted-and-served-as-PHP → bypass confirmed.
  - Apache `AddHandler`/`mod_mime` misconfig means `shell.php.jpg` can still execute.
- **Handler-flip drop.** When only "images" are allowed but you can also drop `.htaccess` with `AddType application/x-httpd-php .jpg` (Apache) or `.user.ini` with `auto_prepend_file` (PHP-FPM) or `web.config` (IIS) → subsequent "image" uploads execute. If the `.htaccess` upload is accepted → strong signal.
- **SVG stored-XSS probe.** Upload `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>` as `x.svg`.
  - Retrieved with `Content-Type: image/svg+xml` and `Content-Disposition: inline` → stored XSS fires when viewed.
  - Retrieved as `attachment` with `nosniff` → not exploitable as XSS; note it but don't claim a finding.
- **HTML sniff probe.** Upload an HTML file as `x.png` whose content is `<script>...</script>`.
  - Served without `X-Content-Type-Options: nosniff` → IE/legacy/edge-case sniffing renders it as HTML.
- **ImageMagick MVG/SVG probe.** Upload an `.mvg`/`.svg` containing `fill 'url(http://<your-collab>/)'`.
  - An out-of-band HTTP hit to your listener on upload/preview → ImageMagick processing confirmed → escalate toward the `MSL`/`policy.xml`/delegate RCE family.
- **ExifTool probe.** A JPEG with a crafted DjVu/metadata block (CVE-2021-22204 family); a callback or error referencing `ExifTool` → version-match the CVE.
- **Path-traversal filename.** Send `filename="../../../../tmp/poc.txt"` (and URL-encoded `..%2f` variants, and `\\` on Windows).
  - File appears at the traversed location, or a stack trace reveals the absolute write path → traversal confirmed.
- **Zip Slip probe.** Upload an archive with an entry named `../../../../tmp/zipslip.txt`.
  - The file lands outside the extraction dir → Zip Slip confirmed.
- **Presigned-policy probe.** At policy-request time declare `Content-Type: image/png`; at the actual `PUT`/`POST` to the bucket, send `Content-Type: text/html` and a `key` with `../` or a different prefix.
  - Object stored with `text/html` / outside the intended prefix → policy conditions are too loose.
- **Finalize swap.** In a tus/S3-MPU flow, `init` with a benign type, then `complete` with a different `Content-Type`/last chunk; if retrieval reflects the swapped type → finalize gap.

## When NOT to use it / easily-confused-with

- **A reflected/stored value in a normal text field (comment, name, bio) → that is XSS, not this skill.** Only route here when the script-bearing content arrives *as an uploaded file* and the upload/serving headers are the weakness.
- **`?url=`/`?path=` that reads a server file with no file *upload* involved → that is LFI/path-traversal or SSRF**, route to those skills. Upload-skill only owns it when the traversal/SSRF rides *inside an upload* (filename field, presigned key, URL-fetch uploader).
- **A download/export endpoint that lets you read arbitrary files (`?file=report.pdf` → `?file=../../etc/passwd`) → that is path traversal / file disclosure**, not insecure upload — there is no write of attacker content.
- **Generic SSRF where the app fetches a URL for previews but you cannot influence what gets stored/served → prefer the SSRF skill.** Only stay here when the fetched bytes hit a vulnerable media processor or land as a served upload.
- **A pure parser/deserialization bug reached by a non-file body (JSON/XML POST) → that is deserialization/XXE**, not upload — unless the malicious document is delivered *as an uploaded file* (e.g. XXE via an uploaded `.docx`/`.svg`, in which case it can legitimately overlap and either skill is defensible).
- **Uploads that are stored but provably never served back, or always served `attachment` + `nosniff` from a no-execute store, with no server-side processor** → likely a false positive; don't burn iterations claiming a finding without execution, inline rendering, traversal, or a pipeline race as proof.
- **CSRF on the upload form alone** is a different class — that's about forging the request, not about bypassing content/extension/MIME validation.

B:insecure-file-uploads done

