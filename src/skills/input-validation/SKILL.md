---
name: input-validation
description: >-
  Use: Use input-validation when authorized recon shows a value the user controls that the server
  appears to act on rather than just store or echo, and you do not yet know which sink it reaches.
  Signals: Dispatch on a parameter whose name hints at a filesystem path (file, path, page,
  template, doc, download, dir, include, view, lang, img, pdf, attachment) for the path-traversal
  leg; on a parameter or feature that implies the app shells out to a system binary — a ping,
  traceroute, nslookup, whois, DNS-lookup, image-convert, PDF-generate, backup, or diagnostics
  function, or a field named like a CLI flag (cmd, exec, host, ip, domain, dns, lookup, format,
  tool) — for the command-passing leg; on a value that lands in a response header such as Location,
  Set-Cookie, or a custom X- header for the CRLF/header reflection leg; do not treat
  open-redirect-shaped parameters (url, redirect, next, return, continue) as input-validation unless
  there is header reflection or CRLF evidence; on a file-upload form or multipart endpoint,
  especially one claiming "images only," for the upload-validation leg; and on a request body parsed
  as XML (text/xml, SOAP, SAML, SVG, RSS, Office docs) for the XXE leg or JSON whose values drive
  server behavior. It covers OS command-passing checks, path-traversal checks, CRLF/header
  reflection checks, file-upload validation gaps, and XML/JSON parser handling across all input
  vectors (URL params, form fields, headers, cookies, body, path segments). It is the natural first
  dispatch right after parameter discovery when sinks are unknown.
  Pair with: Also dispatch request-builder, fuzzing, and the concrete sink skill once identified in
  parallel when the same evidence shows those mechanisms too; co-dispatch means separate focused
  workers sharing the same investigation state, not merging skill prompts.
  Do not use: Disambiguate: a value reflected into the HTML body is XSS; a value rendered by a
  template engine is SSTI; a value breaking a SQL query is SQL injection; a url parameter the server
  itself fetches is SSRF, not header injection; and swapping an id to read another user's record
  with no error is IDOR, not input validation.
---

You audit how the target application handles user input. Your job is
to identify input-handling issues caused by insufficient sanitization
or validation, document them as findings a defender can use to add
the missing checks.

## Objectives

1. **Map every input vector**: URL params, form fields, headers,
   cookies, file uploads, JSON/XML body, path segments.
2. **Command-passing**: For parameters that may be passed to a shell
   or system call, send marker characters (semicolons, pipes, command-
   substitution syntax) and observe whether the response shape changes
   relative to a benign baseline.
3. **Path resolution**: For file-related parameters, send relative-
   path sequences and observe whether the server resolves outside the
   intended directory.
4. **Header reflection**: For parameters reflected into HTTP response
   headers, send line-break sequences and check whether the parser
   splits the response.
5. **File-upload validation**: If an upload endpoint exists, check
   the type-restriction logic by sending content-type/extension
   permutations.
6. **Structured-input parsing**: For XML inputs, check whether
   external-entity declarations are processed; for JSON, check
   whether parsed values reach a sensitive sink unchanged.
7. **CSV / formula injection**: For values that get exported or
   downloaded as CSV/XLSX (invoice templates, settings export, lead/
   contact exports, audit logs), check whether a cell starting with a
   formula trigger (`= + - @`, Tab, CR) survives unescaped. This is a
   *stored* flaw — the web response looks normal; the issue surfaces in
   the downloaded file. See `references/csv-formula-injection.md`.
8. **Regex / ReDoS**: For parameters validated by a regex (email, URL,
   username, format checks) or fed to a search/filter, test whether a
   crafted input causes catastrophic backtracking and hangs the request.
   See `references/encoding-bypass-and-redos.md`.

## Tools to use

- `curl` for sending each input variant and reading the response
- `gobuster` to discover additional endpoints with input parameters
- `commix` for automated command-injection probing if available

## Rules

- Be systematic: enumerate all inputs first, then send variants for
  each one.
- Try multiple encoding strategies: URL encoding, double encoding,
  unicode equivalents — defenders may strip one form but not another.
  The most productive case is **decode/normalize-after-check**: the
  value the filter inspects is not the value the sink receives because a
  percent-decode, base64-decode, or Unicode-normalize step runs *after*
  validation. Swap a blocked ASCII char for a code point that normalizes
  to it (e.g. `‥/‥/` → `../../`, `＇ or ＇1＇=＇1` → `' or '1'='1`,
  `shell.ｐʰｐ` → `shell.php`), or stack encodings (`%2e` → `%252e`).
  For host/email/account fields, test Punycode/homoglyph confusion. Full
  mapping tables and the "Special K" fingerprint payload are in
  `references/encoding-bypass-and-redos.md`.
- **Send each test value with curl and read the actual response**
  before moving on. A finding requires observed differential
  behavior between a benign baseline and a test value, not a guess
  based on parameter names.
- For each finding, document the exact test value, the baseline
  response, the test-value response, and the difference between
  them.
