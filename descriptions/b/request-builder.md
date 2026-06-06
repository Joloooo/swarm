# request-builder — when to use

This skill is the differential-probing oracle: you have already poked an HTTP
endpoint several times and the responses have *not* converged on what you want.
Hand it the endpoint shape, the inputs you already sent, and the responses you
got back, and it infers the input→output transformation the server applies and
returns ONE new input to try next. It is the "I'm stuck on a guess-the-magic-
string loop, give me a smarter candidate" move — not a vulnerability scanner.

## Trigger signals (dispatch this skill the moment you observe…)

- You have sent **3+ different values to the same parameter** and the responses
  differ in a *patterned* way (e.g. some return 200, some 403; some echo a
  normalized form of your input) → there is a transformation to reverse-engineer;
  dispatch this skill to model it and propose the next value.
- A request comes back **403 / 400 / "invalid input" / "blocked" only for some
  values** and not others, suggesting a denylist or input filter standing between
  you and the desired behavior → you need a value that survives the filter.
- The endpoint **echoes your input back in a changed form** — uppercased,
  lowercased, trimmed, with characters stripped/escaped/doubled, URL-decoded,
  truncated to N chars → that visible normalization is exactly the round-trip
  this skill solves for.
- A WAF/filter **strips a keyword once** (you sent `SELECT`, the response shows
  it gone or replaced) → you need recursive/fragmented nesting candidates; this
  skill's symmetry reasoning generates them.
- You are close on a **known attack class** (SQLi, XSS, SSTI, path traversal,
  command injection) but the obvious payload is being neutralized, and you need a
  *bypass variant* of one specific test input rather than a new class of attack.
- A response **count or length changes with the input** (e.g. a search returns 5
  items for one term, 0 for another, 50 for `%`) → there is a query
  transformation worth probing for a value that maximizes/changes the result set.
- You sent two inputs that **differ by one property** (case, a space, a doubled
  char, length) and got **two different status codes / bodies** → the smallest
  difference that flips behavior is the strongest lever; feed both observations in
  and let it extrapolate.
- An auth/validation gate accepts some tokens and rejects others with **no error
  detail** and you are brute-forcing the accepted shape blindly → use this to turn
  blind guessing into pattern-driven guessing.

## Use-case scenarios

- **Filter / WAF bypass tuning.** You have confirmed an injection point but a
  filter mangles your payload. You have tried `<script>`, `<ScRiPt>`,
  `<scr<script>ipt>` and logged each response. This skill compares which mutation
  partially survived and proposes the next encoding/casing/nesting variant. This is
  its sweet spot: a tight observe→mutate→observe loop where each response is a clue.

- **Round-tripping a normalizer.** The server lowercases, trims, or URL-decodes
  your input before using it (you can see this because the echoed/stored value
  differs from what you sent). To land a specific post-transformation value you
  must pre-distort the input so it *becomes* your target after normalization. This
  skill works backwards through the observed transformation to find that pre-image —
  e.g. propose `%2e%2e%2f` because the endpoint URL-decodes once, or double an
  escaped char because a single pass un-escapes it.

- **Denylist probing.** A blocklist rejects certain substrings/values with a
  distinctive status. You feed in the accepted/rejected examples and it infers the
  rule (case-insensitive substring match? exact match? prefix?) and proposes a
  value that dodges the rule while keeping the semantics you need.

- **Result-set steering on a search/filter/lookup endpoint.** You want a query that
  returns *something it shouldn't* (more rows, a different user's row, a wildcard
  match). Given how item counts moved across prior inputs, this skill proposes the
  input that pushes the count or content where you want it.

- **Magic-value / token-shape discovery.** An endpoint accepts a value only in a
  specific format and gives terse feedback. You log accept/reject pairs and it
  models the format constraint, proposing a conforming-but-novel value.

## Concrete tells (request → response examples)

- **Normalization visible in echo:**
  `POST /profile {"name":"  Bob  "}` → response body shows `"name":"bob"`.
  The server trimmed and lowercased. → Dispatch with both observations; it will
  reason about what pre-image yields your desired stored value.

- **Single-pass strip (recursion candidate):**
  `?q=SELECT` → 200, body shows `q=`. `?q=SELSELECTECT` → 200, body shows
  `q=SELECT`. → A single non-recursive removal. This skill proposes the nested
  form that survives one pass.

- **Denylist by status code:**
  `name=admin` → 403; `name=administrator` → 200; `name=Admin` → 200. → The rule
  is an exact, case-sensitive match on `admin`. It proposes a value that is treated
  as admin downstream but isn't the literal blocked string.

- **Length / truncation:**
  A 20-char input is accepted, a 21-char input returns the same response as a
  20-char input (silently truncated), a 19-char input changes behavior. → It
  infers the cutoff and proposes a value crafted around the boundary.

- **Count steering:**
  `search=apple` → 3 results; `search=a` → 40 results; `search=` → 403. → The
  endpoint does substring matching with a non-empty guard. It proposes the input
  that maximizes or specifically shapes the returned set.

- **Encoding layers:**
  `path=../etc` → "not found"; `path=%2e%2e/etc` → "not found";
  `path=%252e%252e/etc` → different error mentioning the path. → Double-decoding is
  happening; it proposes the encoding depth that lands the literal `../`.

## When NOT to use it / easily-confused-with

- **You have no prior observations yet.** This skill *needs* a handful of
  input/output pairs to do differential inference. If you have never touched the
  endpoint, first run the relevant recon/fuzzing skill to gather the
  `(input, status, excerpt)` tuples, *then* hand them here. It is a second-stage
  refiner, not a first-contact prober.

- **You need many payloads / a full wordlist sweep.** This returns exactly ONE
  candidate per call. For brute-force enumeration, directory busting, or spraying a
  large list, use a fuzzer — not this skill. Use this when the search space is
  small and *reasoned*, not large and *exhaustive*.

- **You already have a working payload and just want to exploit it.** Once a value
  produces the desired behavior, hand off to the exploitation/data-extraction skill
  for that class. This skill's job ends the moment the loop converges.

- **The vulnerability class itself is unidentified.** This skill assumes you know
  the *kind* of behavior you're chasing (a status flip, a non-empty body, a new
  value in the response). If you don't yet know whether the bug is SQLi vs XSS vs
  SSTI, classify it first — a reflected value is XSS (not SSTI) unless it is
  *evaluated*; a value that changes row counts is a query/SQLi concern, not a
  rendering one. Don't route here to *decide* the class; route here to *bypass a
  filter or reverse a transformation* within a class you've already identified.

- **The response differences are random / non-deterministic.** If the same input
  yields different responses on repeat (rate-limiting jitter, load balancing,
  random tokens), there is no stable transformation to infer and the proposals will
  be noise. Confirm determinism first.

- **Confused with general fuzzing or recon.** Fuzzing throws inputs broadly to find
  *where* something interesting happens; this skill is the opposite — it converges
  on the *one* next input given a known-interesting endpoint and a clear behavioral
  goal.
