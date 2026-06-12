# DNS rebinding — TOCTOU between validation and fetch, plus perimeter-filter bypasses — Open WHEN: the sink resolves a hostname, validates the first answer, then fetches it again (a separate DNS lookup), and you need to flip a public IP to an internal one between the two lookups

The classic SSRF rebinding case: the validator resolves your hostname and sees
an allowed public IP, then the fetcher re-resolves and gets the internal IP.
Works only when validation and fetch are two separate DNS lookups (no pinning).

## Ready-made rebinding services (no DNS server to run)
```
# 1u.ms — rotates two IPs per lookup (here 1.2.3.4 <-> 169.254.169.254)
make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms

# rbndr.us — flips between two hex-encoded IPs each lookup
http://make-1.2.3.4-127.0.0.1-rbndr.us
# helper to build rbndr names: lock.cmpxchg8b.com/rebinder.html
```
Verify the flip before relying on it:
```bash
nslookup make-1.2.3.4-rebind-169.254-169.254-rr.1u.ms   # run twice, watch addr change
```
Framework: `nccgroup/singularity` (Singularity of Origin) for browser-driven
rebinding and the protection bypasses below.

## Perimeter DNS-filter bypasses
Most "DNS protection" blocks responses whose A record is RFC1918
(10/8, 172.16/12, 192.168/16), sometimes also loopback (127.0.0.0/8) and
0.0.0.0/0. Bypasses (documented by NCC Group / Singularity):

- **0.0.0.0** — reaches localhost (127.0.0.1) on many stacks but is NOT in a
  `127.0.0.0/8` blocklist. Rebind/resolve to `0.0.0.0` when 127.* is blocked.
- **CNAME to an internal name** — return a CNAME (not an A record) pointing at
  an internal hostname. The perimeter filter only inspects A-record IPs, so the
  CNAME passes; the internal resolver then resolves it to the private target.
  ```
  cname.example.com.   381  IN  CNAME  target.local.
  ```
- **localhost via CNAME** — CNAME to the literal `localhost` to dodge a filter
  that only blocks the string/IP `127.0.0.1`.
  ```
  www.example.com.   381  IN  CNAME  localhost.
  ```

## Public hostnames that already resolve internal (no rebinding needed)
```
localtest.me                 -> ::1
localh.st                    -> 127.0.0.1
<anything>.127.0.0.1.nip.io  -> 127.0.0.1     (nip.io maps any IP)
169.254.169.254.nip.io       -> 169.254.169.254
spoofed.<your>.oastify.com   -> 127.0.0.1     (CNAME under an allowed parent)
```

## Headless-browser split-second rebinding (Chrome/Safari)
When the sink is a headless browser rather than a server fetcher, force the
flip inside one page load using the IPv6->IPv4 fallback:
1. Answer both `AAAA` (public Internet IP) and `A` (internal IP).
2. Chrome connects to the IPv6 (public) address first.
3. Close the IPv6 listener right after the first response.
4. Open an iframe to your rebinding host; the IPv6 connect now fails and Chrome
   falls back to the IPv4 (internal) address — same origin.
5. From the top window, read/inject into the iframe to exfiltrate the response.
`nccgroup/singularity` automates this; tune TTLs near zero.

## When rebinding will NOT work
- The sink resolves once and **pins** the IP for the whole request (one lookup
  used for both validation and fetch).
- The fetcher connects by IP it already validated, re-using the socket.
In those cases pivot to parser-differential / redirect / encoding bypasses
(see `references/bypass-payloads.md`) instead.
