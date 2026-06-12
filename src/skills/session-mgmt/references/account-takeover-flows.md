# Account-takeover and session-lifecycle flows — Open WHEN: the target exposes password-reset, registration, MFA, or "change email/password" flows and you want to persist as another user

Account takeover (ATO) is the end goal of most session work: get a valid
session for a victim account. The reset and MFA flows below are the cheapest
paths to it. Stay in the session-lifecycle lane — leave JWT signature/key
forgery to the auth-token specialist.

## Password-reset token weaknesses
A reset link is a one-shot credential. Test the token itself before anything else.

- **Predictable token.** Request several resets and diff the tokens. Flag if the
  value is short (<6 chars), sequential, a counter, or clearly derived from
  guessable inputs (timestamp, userID, email, name, DOB). Time two resets a
  second apart — if the tokens differ only in a time component, the token is
  forgeable.
- **Token reuse / no expiry.** Use a token, then replay the same link. If it
  still works, or still works hours later, lifecycle is broken.
- **Token leak in response.** Trigger a reset for `victim@mail.com` and read the
  HTTP/JSON response body — some APIs return `resetToken` directly. Then build
  the link yourself: `…/password/reset?resetToken=<TOKEN>&email=victim@mail.com`.
- **Token leak via Referer.** Open the reset link, then click any off-site link
  on the page; the token can ride out in the `Referer` header to a third party.

## Reset-poisoning via Host / X-Forwarded-Host
If the reset email's link is built from the request Host header, you can point
the link at a host you control and capture the victim's token when they click.

```http
POST /reset.php HTTP/1.1
Host: evil.example
X-Forwarded-Host: evil.example
Content-Type: application/json

{"email":"victim@mail.com"}
```
Then watch for the link `https://evil.example/reset-password.php?token=<TOKEN>`.

## Reset / change to a second address
Make the app deliver the reset (or accept the change) for the victim's account
but to an address you control. See `references/email-and-collision-payloads.md`
for the full payload set: parameter pollution, email arrays, CC/BCC header
injection, separator-joined lists, username-collision (whitespace padding,
CVE-2020-7245), and unicode-normalization collisions.

## IDOR on the change-password / change-email endpoint
Log in as yourself, start a "change password" or "change email", intercept it,
and swap the `email` / `userId` to the victim's. If the server trusts the body
over the session, you reset the victim's credential.

```http
POST /api/changepass
{"email":"victim@mail.com","password":"newpass"}
```

## Chaining a web bug into a session steal
- **XSS → cookie theft.** Any XSS in the app or a subdomain whose cookies are
  scoped to `*.domain.com` can read a session cookie that lacks `HttpOnly` and
  send it off-host; replay it to ride the victim's session. (Find the XSS via
  the xss specialist; this skill judges the cookie's flag hygiene and lifecycle.)
- **CSRF → forced credential change.** A cross-origin auto-submitting form that
  changes password/email completes ATO when the action has no anti-CSRF token.
  Deep CSRF analysis is the csrf specialist's job; flag the missing protection
  on session-security actions here.
- **Request smuggling → response capture.** When a front-end/back-end pair
  desync on Content-Length vs Transfer-Encoding, a smuggled prefix can capture
  the next user's request (and its session). This is the request-smuggling
  specialist's domain — note it and hand off.

## Lifecycle invariants to assert (these are the findings)
- A new session ID is issued **at login** (no fixation — see body).
- Logout invalidates the session **server-side**, not just by clearing the cookie.
- Password change / reset **invalidates all other active sessions**.
- Email change and MFA changes require re-auth and invalidate old sessions.
- Tokens (session and reset) expire on a sane clock and cannot be replayed.
