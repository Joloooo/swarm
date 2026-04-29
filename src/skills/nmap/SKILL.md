---
name: nmap
description: Use when planning nmap scans, choosing between scan types, reading ScanResult dicts, or recovering from scan errors. Covers the typed-tool reference, the tool-selection decision tree (ping_sweep, fast_scan, default_scripts, ssl_enum, http_enum, smb_enum, vuln_scan, full_scan, host_discovery, script), the required two-pass workflow (discovery then enrichment), and error-code handling (binary_missing, permission_denied, invalid_target, timeout, invalid_args, unknown).
---

# Nmap — Typed Tool Reference

You have typed nmap tools. Prefer them over `run_command("nmap ...")` —
they return structured dicts, set safe timeouts, and hide flag syntax.
Every tool's output is a `ScanResult` dict: `{ok, tool, target, command,
elapsed_seconds, hosts: [...], summary, error?, warnings?}`.

## How to read a ScanResult

1. Check `ok`. If `False`, read `error.code` and `error.hint` — do NOT
   retry blindly.
2. Scan `summary` for a quick overview (e.g. "2 host(s) up, 3 open
   port(s) (22/ssh OpenSSH 6.6.1, 80/http Apache 2.4.7)").
3. Walk `hosts[].ports[]` for structured data: `port`, `state`,
   `service`, `product`, `version`, `scripts[]`.

Empty `hosts: []` with `ok=True` means the scan ran cleanly but
nothing responded — the target is filtered or down.

## Tool selection decision tree

**Starting with a CIDR or unknown network?**
→ `nmap_ping_sweep(network="10.0.0.0/24")` — finds live hosts only.

**One host, first look?**
→ `nmap_fast_scan(target, top_ports=100)` — top TCP ports in ~30s.

**Fast scan returned open ports → enrich them.**
→ `nmap_default_scripts(target, ports="22,80,443")` — safe NSE + versions.
→ OR `nmap_service_detection(target, ports="22,80,443")` — versions only,
   faster than default_scripts when you don't need script output.

**Target has 443 (or any TLS port) open?**
→ `nmap_ssl_enum(target, ports="443")` — cipher list, cert, heartbleed.

**Target is a web app (80/443/8080/8443)?**
→ `nmap_http_enum(target)` — title, headers, methods, path enum.

**Windows/SMB target (139/445)?**
→ `nmap_smb_enum(target)` — shares, users, OS, signing mode.

**Want to check known CVEs on confirmed-open ports?**
→ `nmap_vuln_scan(target, ports="...")` — INTRUSIVE. Only run after a
   fast_scan and only on scoped ports.

**Fast scan missed a port you expect to be open?**
→ `nmap_full_scan(target)` — all 65535 TCP ports, SLOW (5-10 min).

**ICMP ping filtered?**
→ `nmap_host_discovery(target, method="tcp-syn")` — alt probe type.

**Need a specific NSE script the named tools don't cover?**
→ `nmap_script(target, script="<name>", ports="...")` — last resort.

## Two-pass workflow (REQUIRED)

1. **Discovery pass** — `nmap_ping_sweep` (network) or `nmap_fast_scan`
   (single host). Cheap, ~30s. Identifies what's reachable.
2. **Enrichment pass** — feed the open ports from step 1 into
   `nmap_default_scripts`, `nmap_ssl_enum`, `nmap_http_enum`, etc.

**Never** run `nmap_vuln_scan`, `nmap_aggressive`, or `nmap_full_scan`
without a prior fast scan. These are expensive and noisy.

## Error recovery

When `ok=False`, the `error.code` tells you what to try next:

| error.code | What it means | What to do |
|---|---|---|
| `binary_missing` | nmap not installed in sandbox | Fall back to `run_command` + curl, or ask user to install nmap |
| `permission_denied` | scan needs root (UDP/OS detection) | For port scans: retry with `tcp_connect=True`. For OS/UDP: skip entirely |
| `invalid_target` | hostname did not resolve | Try an IP directly; verify DNS |
| `timeout` | exceeded `--host-timeout` | Narrow ports (smaller `top_ports`, specific `ports`) — DON'T just retry with the same args |
| `invalid_args` | nmap rejected flags | Read `error.stderr`, fix the offending arg |
| `unknown` | unexpected | Read `error.stderr`, retry once, else `run_command` |

If `ok=True` but `hosts=[]` → target is filtered or down; try
`nmap_host_discovery(target, method="tcp-syn")` before giving up.

## Rules

- Scripts can be slow. Every script tool has `--script-timeout` baked
  in; trust it and don't raise timeouts unless you've scoped ports.
- `nmap_ssl_enum` replaces `nmap --script ssl-enum-ciphers` — use it
  instead of calling `nmap_script` with that script name.
- `nmap_udp_scan` and `nmap_os_detection` will warn (or error) when
  not run as root. Respect the warning — results will be degraded
  or missing.
- Don't interpret filtered ports as closed. `filtered` means a
  firewall is in the way; try `nmap_host_discovery(method="tcp-ack")`
  to probe past stateful firewalls.
- For IPv6 targets (addresses containing `:`), every tool automatically
  adds `-6`. You don't need to think about it.
