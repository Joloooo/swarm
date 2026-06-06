# request-builder

The differential-probing oracle. You have already poked an HTTP endpoint several times and the responses have not converged on what you want. Hand it the endpoint shape, the inputs you already sent, and the responses you got back; it infers the input→output transformation the server applies and returns ONE new input to try next. It is the "I'm stuck on a guess-the-magic-string loop, give me a smarter candidate" move — a second-stage refiner, not a vulnerability scanner or fuzzer.

## Dispatch when:

- You have sent **3+ different values to the same parameter** and the responses differ in a *patterned* way (some 200, some 403; some echo a normalized form of your input) — there is a transformation to reverse-engineer.
- A request returns **403 / 400 / "invalid input" / "blocked" only for some values** and not others, suggesting a denylist or input filter you need a value to survive.
- The endpoint **echoes your input back in a changed form** — uppercased, lowercased, trimmed, characters stripped/escaped/doubled, URL-decoded, truncated to N chars — that visible normalization is the round-trip to solve for.
- A WAF/filter **strips a keyword once** (you sent `SELECT`, the response shows it gone or replaced) — you need recursive/fragmented nesting candidates.
- You are close on a **known attack class** (SQLi, XSS, SSTI, path traversal, command injection) but the obvious payload is neutralized, and you need a *bypass variant* of one specific test input — not a new attack class.
- A response **count or length changes with the input** (search returns 5 items for one term, 0 for another, 50 for `%`) — there is a query transformation worth probing for a value that maximizes or reshapes the result set.
- Two inputs that **differ by one property** (case, a space, a doubled char, length) produce **two different status codes / bodies** — the smallest difference that flips behavior is the strongest lever; feed both observations in and extrapolate.
- An auth/validation gate accepts some tokens and rejects others with **no error detail** and you are brute-forcing the accepted shape blindly — turn blind guessing into pattern-driven guessing.

## Recognition tells (request → response):

- **Normalization visible in echo:** `POST /profile {"name":"  Bob  "}` → body shows `"name":"bob"` (trimmed + lowercased). Reason backwards for the pre-image that yields your desired stored value.
- **Single-pass strip (recursion candidate):** `?q=SELECT` → body shows `q=`; `?q=SELSELECTECT` → body shows `q=SELECT`. A non-recursive removal — propose the nested form that survives one pass.
- **Denylist by status code:** `name=admin` → 403; `name=administrator` → 200; `name=Admin` → 200. Exact, case-sensitive match on `admin` — propose a value treated as admin downstream but not the literal blocked string.
- **Length / truncation:** 20-char input accepted; 21-char input returns the same response as 20-char (silently truncated); 19-char input changes behavior. Infer the cutoff and craft a value around the boundary.
- **Count steering:** `search=apple` → 3 results; `search=a` → 40; `search=` → 403. Substring matching with a non-empty guard — propose the input that maximizes or shapes the returned set.
- **Encoding layers:** `path=../etc` → "not found"; `path=%2e%2e/etc` → "not found"; `path=%252e%252e/etc` → a different error mentioning the path. Double-decoding is happening — propose the encoding depth that lands the literal `../`.

## Key techniques:

- **Filter / WAF bypass tuning.** Confirmed injection point, but a filter mangles your payload. Compare which mutation partially survived (`<script>` vs `<ScRiPt>` vs `<scr<script>ipt>`) and propose the next encoding/casing/nesting variant. The sweet spot: a tight observe→mutate→observe loop where each response is a clue.
- **Round-tripping a normalizer.** The server lowercases/trims/URL-decodes input before using it (echoed or stored value differs from what you sent). To land a specific post-transformation value, pre-distort the input so it *becomes* your target after normalization — e.g. propose `%2e%2e%2f` because the endpoint URL-decodes once, or double an escaped char because a single pass un-escapes it.
- **Denylist probing.** Infer the rule from accept/reject examples (case-insensitive substring? exact match? prefix?) and propose a value that dodges the rule while keeping the semantics you need.
- **Result-set steering** on a search/filter/lookup endpoint. Given how item counts moved across prior inputs, propose the input that pushes the count or content where you want it (more rows, another user's row, a wildcard match).
- **Magic-value / token-shape discovery.** Model the format constraint from accept/reject pairs and propose a conforming-but-novel value.

## When NOT to use / easily confused with:

- **No prior observations yet.** It *needs* a handful of `(input, status, excerpt)` pairs to do differential inference. With no prior contact, run recon/fuzzing first to gather them, then hand them here.
- **You need many payloads / a full wordlist sweep.** This returns exactly ONE candidate per call. For brute-force enumeration, directory busting, or list spraying, use a fuzzer. Use this when the search space is small and *reasoned*, not large and *exhaustive*.
- **You already have a working payload.** Once a value produces the desired behavior, hand off to the exploitation/data-extraction skill for that class. Its job ends the moment the loop converges.
- **The vulnerability class is unidentified.** It assumes you know the *kind* of behavior you're chasing (a status flip, a non-empty body, a new value in the response). Classify first — a reflected value is XSS (not SSTI) unless it is *evaluated*; a value that changes row counts is a query/SQLi concern, not a rendering one. Route here to *bypass a filter or reverse a transformation* within a known class, not to *decide* the class.
- **Response differences are random / non-deterministic.** If the same input yields different responses on repeat (rate-limiting jitter, load balancing, random tokens), there is no stable transformation to infer and proposals will be noise. Confirm determinism first.
- **Confused with general fuzzing or recon.** Fuzzing throws inputs broadly to find *where* something interesting happens; this converges on the *one* next input given a known-interesting endpoint and a clear behavioral goal.
