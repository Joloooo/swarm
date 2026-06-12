# Exposed management & admin interfaces — Open WHEN: recon shows a framework actuator/management path, an admin panel reachable by a low/anonymous caller, or a default-credential login

A management interface is a function-level authorization failure when the
interface itself is the restricted "function": it controls config, secrets,
or lifecycle actions and should never answer an unprivileged caller. Treat a
reachable management endpoint exactly like a privileged action that the caller
was never authorized to invoke.

## 1. Detect exposed panels and default logins

Use template scans before hand-crafting requests — they cover hundreds of
known panels and credential pairs:

```bash
# Exposed admin/management panels (Spring, Jenkins, Grafana, phpMyAdmin, ...)
nuclei -t http/exposed-panels/ -u https://TARGET
# Default / weak credential pairs (admin/admin, root/root, vendor defaults)
nuclei -t http/default-logins/ -u https://TARGET
# Generic exposures (config files, debug consoles, info leaks)
nuclei -t http/exposures/ -u https://TARGET
```

Brute-force likely management paths when no scan template fits the stack:

```bash
ffuf -u https://TARGET/FUZZ -w wordlist -mc 200,301,302,401,403 \
  -e /,/login
# common: /admin /administrator /manage /console /backoffice /internal
#         /actuator /management /debug /metrics /status /server-status
```

A `401`/`403` is still a lead, not a dead end — the interface exists; pivot to
the gateway-trust and method/route bypasses in the SKILL body.

## 2. Spring Boot Actuator (highest-value finding)

Actuators are management endpoints that ship with Spring Boot apps. When
exposed to an unprivileged caller they leak secrets and can lead to remote
code execution. Probe both the bare names and the `/actuator/` prefix (Spring
Boot 1.x used bare names; 2.x+ moved them under `/actuator/`).

```bash
# Quick presence check — JSON list of enabled endpoints
curl -s https://TARGET/actuator | jq . 2>/dev/null || curl -s https://TARGET/actuator
```

Full endpoint list to probe lives in `references/actuator-endpoints.txt`
(feed it to a fuzzer):

```bash
ffuf -u https://TARGET/FUZZ -w references/actuator-endpoints.txt -mc 200
```

### Endpoints that matter, and why

| Endpoint | What it gives | How to use it |
|----------|---------------|---------------|
| `/actuator/env` (or `/env`) | All environment + config properties | Read DB passwords, API keys, secrets. Values may show as `******` — see the unmasking trick below. |
| `/actuator/heapdump` (`/heapdump`) | Full JVM heap as a binary download | Carve plaintext credentials, session tokens, cookies out of memory. |
| `/actuator/configprops` | Resolved configuration beans | Same secret-leak surface as `/env`. |
| `/actuator/mappings` | Every request mapping in the app | Reveals hidden/admin routes with no UI — feed straight back into the BFLA role-matrix work. |
| `/actuator/httptrace` / `/actuator/trace` | Recent HTTP requests with headers | Capture other users' session cookies / `Authorization` headers. |
| `/actuator/sessions` | Active session ids | Session hijacking leads. |
| `/actuator/loggers` | Live log-level config (POST to change) | Turn on DEBUG/TRACE to leak more, or confirm write access. |
| `/actuator/jolokia` | JMX-over-HTTP bridge | If present, a known route to remote code execution (see below). |
| `/actuator/shutdown` | POST gracefully stops the app | Availability impact — only confirm presence, do not trigger on a live target without authorization to disrupt. |
| `/actuator/info`, `/actuator/health` | Version / dependency hints | Low-sensitivity, but fingerprints the stack and confirms actuators are live. |

### Unmasking `******` values in `/env`

When `/actuator/env` masks sensitive values, a single property can often be
read in clear via the property-name path:

```bash
curl -s https://TARGET/actuator/env/PROPERTY.NAME
# e.g. /actuator/env/spring.datasource.password
```

### `/env` property-injection to escalate (POST writable)

If `/actuator/env` accepts POST (older setups, or when `loggers`/`env` are
writable), changing properties can pivot to credential capture or, with
`jolokia` present, to code execution. Confirm write access first:

```bash
curl -s -X POST https://TARGET/actuator/env \
  -H 'Content-Type: application/json' \
  -d '{"name":"PROBE_KEY","value":"PROBE_VALUE"}'
# then read it back from /actuator/env/PROBE_KEY
```

A reachable `/actuator/jolokia` combined with writable `/env` is a documented
remote-code-execution chain (Jolokia → JNDI/reloadByURL). For SwarmAttacker
purposes, confirming the **reachability of an unauthorized management endpoint
that exposes secrets** is already a valid, high-severity BFLA finding — record
the leaked secret as proof and do not run a destructive RCE step on a live
target unless the engagement explicitly authorizes it.

## 3. Other framework management consoles to fingerprint

Same logic — a management console reachable by an unprivileged caller is a
function-level authorization failure:

- **Jolokia** standalone: `/jolokia`, `/jolokia/list` — JMX bean enumeration.
- **Java melody**: `/monitoring` — heap, SQL, HTTP request monitoring.
- **Druid** monitor: `/druid/index.html` — SQL + session data.
- **Generic**: `/server-status`, `/server-info` (Apache mod_status),
  `/metrics`, `/debug`, `/_debug`, `/console`, `/h2-console` (H2 DB web UI,
  itself an RCE path when reachable).

For each: confirm it answers an unprivileged/anonymous request, capture the
leaked data as evidence, and note whether the gateway was supposed to block it
(gateway-trust mismatch — see the SKILL body).
