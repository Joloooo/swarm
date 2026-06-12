# Client-side HTTP Parameter Pollution (CSHPP) — Open WHEN: a value you control is reflected into a URL/link the page builds in the browser (href, form action, redirect, fetch/XHR URL), not directly into HTML or JS

Server-side HPP makes two server parsers disagree about a duplicated
parameter. Client-side HPP (CSHPP) is different: a parameter you supply is
reflected into a URL that the page assembles **in the browser** — an `<a>`
link, a form `action`, a `window.location`/redirect, or a `fetch`/`XHR`
target. By encoding a separator inside your value, you append a second
parameter to that generated URL. When the link is clicked or auto-followed,
the injected parameter rides along to a same-origin endpoint that trusts
page-built links.

## Core mechanism

The page takes your input, decodes it, and concatenates it into a URL
without re-encoding. An encoded `&` in your value becomes a real separator
in the built link.

```
You send:        ?lang=en%26admin=true
Page builds:     <a href="/account?lang=en&admin=true">
On click:        /account?lang=en&admin=true   ← admin=true was never your param
```

The same idea works against any URL the page generates from reflected input:

```
?cb=https://app/ok%26next=https://app/admin   → injects next= into a redirect
?id=5%26role=admin                            → injects role= into a fetch() URL
?q=term%26page=999                            → injects page= into pagination link
```

## Where to look (reflection sinks)

Crawl the rendered page (not just the raw HTML) and find your input echoed
into any of these:

- `<a href="...">` / `<link href>` — navigation links.
- `<form action="...">` — the next form submission target.
- `<iframe src>`, `<img src>`, `<script src>` built from input.
- JS that does `location = ...`, `location.assign(...)`, `history.pushState`.
- `fetch(url)` / `XMLHttpRequest.open(url)` where `url` includes your value.
- Meta-refresh / `Refresh:` redirect targets.
- Social-share, "back to", "continue", and OAuth `redirect_uri` links.

A value that lands inside a `query string position` of a generated URL is
the candidate. A value that lands in the path, in plain text, or in an
attribute that is HTML/JS-executed is a different bug (open-redirect, XSS) —
hand those off.

## Probe pairs

For each reflected parameter, run a baseline and an injection, and diff the
**generated link** in the response (or DOM), not just the HTTP status.

1. Baseline — `?p=marker123` and locate where `marker123` appears in any
   built URL.
2. Encoded-`&` injection — `?p=marker123%26injected=POLLUTED`. If the built
   link now reads `...marker123&injected=POLLUTED`, the separator was
   decoded into the URL: CSHPP confirmed.
3. Double-encoding — if a single `%26` is stripped/re-encoded, try
   `%2526` (decodes to `%26` then `&` one layer deeper).
4. Separator variant — try `;` (`%3B`) where the consuming endpoint splits
   on `;` as well as `&`.
5. Targeted override — replace `injected=POLLUTED` with a parameter the
   destination endpoint actually honors (`admin`, `role`, `redirect_uri`,
   `next`, `callback`, `amount`) and confirm the destination acts on it.

```bash
# fetch the page and grep for your marker inside a built URL
curl -s 'https://t/page?p=marker123%26injected=POLLUTED' \
  | grep -oE '(href|action|src)="[^"]*marker123[^"]*"'
```

## Impact and chaining

- **Override a trusted value** on the destination endpoint — flip a role,
  flag, id, or amount the page-built link carries to a same-origin handler.
- **Open redirect / token theft** — inject `redirect_uri`, `next`, `url`,
  or `callback` into an OAuth or login-return link so the code/token (or
  the user) is sent somewhere you choose. Co-dispatch open-redirect.
- **CSRF amplification** — inject parameters into a form `action` so the
  victim's authenticated submission carries values they never entered.
  Co-dispatch csrf.

## Validation

CSHPP is real only when:
1. Your encoded separator is decoded into a URL the page builds (visible in
   the response HTML or the live DOM), splitting one parameter into two.
2. The injected second parameter reaches a destination endpoint that acts
   on it — naming the source reflection and the destination handler.
3. The destination behavior changes (different role, redirect, id, amount)
   solely because of the injected parameter, with a clean single-value
   baseline for comparison.

## False positives to rule out

- The page re-encodes your value (`%26` stays `%2526` or `%26` in the
  built link) — no separator was introduced, no injection.
- Your value lands in the path or as plain text, not in a query-string
  position — no extra parameter is formed.
- The destination endpoint ignores the injected parameter, or the original
  copy still wins — no security-relevant change.
- The value is HTML/JS-executed rather than concatenated into a URL — that
  is XSS, route it to the xss skill.
