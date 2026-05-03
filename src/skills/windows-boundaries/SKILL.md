---
name: windows-boundaries
description: Reference document on Windows security boundaries — what Microsoft considers a "security boundary" vs. "defense-in-depth", which crossings are vuln-class (UAC bypass, kernel-from-user, sandbox escape) and which are not, attack-surface scoping, and how to determine whether an observed primitive crosses an actual security boundary. Used by other skills when triaging Windows-specific findings. Reference-only — not dispatched as an attack agent.
---

# Windows Boundaries

Reference knowledge on Windows security boundaries. Used by
other skills when triaging primitives observed on a Windows
target — to decide whether a finding is a real vulnerability,
a defense-in-depth bypass, or an out-of-scope curiosity.

This skill is **reference-only** — it has no `agent_id`. The
planner and vulnerability-class agents consult it when
reconnaissance fingerprints a Windows host (typical signals:
`Server: Microsoft-IIS`, `X-Powered-By: ASP.NET`, NTLM in
`WWW-Authenticate`, `.aspx` / `.asmx` extensions, SMB ports
445/139, RDP 3389, Kerberos 88, WinRM 5985/5986).

## Microsoft's boundary model

Microsoft splits trust transitions into three categories. Only
the first earns a CVE and a patch under the Security Servicing
Criteria.

| Category | Meaning | Patched? |
|---|---|---|
| Security boundary | Strong promise: code on one side cannot reach the other without a vuln. | Yes — CVE + servicing. |
| Security feature | Helps but not promised. Bypass = weakness, not boundary break. | Sometimes — best-effort. |
| Defense-in-depth | Speed bump. Bypass alone is not a vuln. | No — won't-fix unless chained. |

Boundary types Microsoft commits to:

| Boundary | Sides | Crossing = vuln class |
|---|---|---|
| Network | Remote attacker / local system | RCE, auth bypass |
| Kernel | User mode / kernel mode | LPE, sandbox escape into kernel |
| Process | Process A / process B (same user, same IL) | Cross-process info leak, injection without permission |
| AppContainer | Sandboxed app / outside | Sandbox escape |
| Session | Session N / session M | Cross-session takeover |
| VTL (VBS) | VTL0 normal world / VTL1 secure world | HVCI / Credential Guard break |
| Hyper-V guest | Guest VM / host or other guest | Hypervisor escape |
| Virtual TPM | Guest / vTPM state | TPM secret leak |

Things Microsoft explicitly calls **not** a boundary:

- UAC (admin split-token) — feature, not boundary.
- Same-user / same-IL process isolation when caller already
  has `SeDebugPrivilege` or admin.
- AppLocker — defense-in-depth.
- WDAC in audit mode.
- Constrained Language Mode (CLM) when caller is admin.
- Mark-of-the-Web (MOTW) — feature.
- ASR rules.
- AMSI.
- ETW / event log integrity from admin.
- Protected Process Light (PPL) — anti-malware DRM-style
  feature; bypass is not a CVE on its own.

## Crossings that count

Treat as a real vulnerability when reachable.

| Primitive | Why it counts | Boundary crossed |
|---|---|---|
| Unauthenticated RCE on listening service | Network -> code exec | Network |
| SMB / RPC / RDP auth bypass | Remote -> local | Network |
| Arbitrary write as user -> SYSTEM via service | User -> kernel-trusted | Process / kernel |
| User-mode read of kernel memory | User -> kernel | Kernel |
| AppContainer process escapes to medium IL | Sandbox -> normal user | AppContainer |
| Browser renderer escapes to broker | LPAC -> outside | AppContainer |
| Cross-session token theft without admin | Session N -> session M | Session |
| Code exec in VTL1 / SMM / hypervisor | VTL0 -> VTL1, host break | VBS / Hyper-V |
| Standard user reads another user's files without ACL grant | User A -> user B | Process / user |
| Guest VM reads host memory | Guest -> host | Hyper-V |

Rule: if the attacker starts with strictly less authority than
the victim resource and reaches it without a credential or
ACL granting access, it is a boundary crossing.

## Crossings that don't

These look exciting but Microsoft will not patch them as
vulns. Report them as findings only when chained into a real
crossing above.

| Primitive | Why it does not count |
|---|---|
| UAC bypass (medium -> high IL, same user) | UAC is not a boundary; admin can always elevate. |
| Admin -> SYSTEM | Admin is already trust-equivalent to SYSTEM. |
| Admin -> kernel via signed driver load | Admin is allowed to load drivers. |
| Admin -> PPL bypass | Admin owns the box; PPL is anti-tamper, not a boundary. |
| AppLocker / WDAC bypass when policy is audit-only | Not enforced. |
| AMSI bypass in user's own PowerShell | Same trust level on both sides. |
| MOTW strip on a file the user already has | User already controls the file. |
| ETW provider patch from admin | Admin can disable telemetry by design. |
| CLM bypass as admin | Admin overrides CLM. |
| Reading own process memory | No boundary involved. |
| Same-IL process injection with `SeDebugPrivilege` | Privilege grants the access. |
| Persistence in HKCU / `%APPDATA%` | User writing user-owned locations. |

## Triage rubric

When a skill observes a primitive on a Windows target, walk
this checklist before claiming a vulnerability.

1. **Identify the two sides.** Who runs the attacker code?
   Who owns the resource being reached? Capture: user SID,
   integrity level, session, AppContainer SID (if any),
   process protection (PPL / PPLight), VTL.
2. **Look up the pair in the boundary table above.** If the
   crossing is in "Crossings that count", continue. If it is
   in "Crossings that don't", stop — it is not a CVE-class
   finding on its own.
3. **Confirm no granting credential exists.** A finding stops
   being a boundary crossing if the attacker holds an
   explicit grant: ACL entry, capability SID, granted
   privilege (`SeDebugPrivilege`, `SeImpersonatePrivilege`,
   `SeLoadDriverPrivilege`, `SeTcbPrivilege`,
   `SeBackupPrivilege`, `SeRestorePrivilege`,
   `SeTakeOwnershipPrivilege`).
4. **Check the integrity-level delta.** Lower IL reaching a
   higher-IL resource without a grant = real. Same-IL or
   same-user with privilege = not a boundary.
5. **Check the AppContainer / capability set.** If the source
   is an AppContainer, any object outside its capability list
   is across the boundary. Capability SIDs start with
   `S-1-15-3-`.
6. **Check the network side.** Anything pre-auth from the
   network is automatically a boundary crossing. Post-auth
   counts only if the auth was for a strictly lower
   privilege than what the primitive achieves.
7. **Decide chain potential.** A non-boundary primitive can
   still matter: UAC bypass + a separate kernel driver vuln =
   real LPE chain. Always record non-boundary primitives;
   never claim them alone.
8. **Record the verdict.** Findings emitted to the planner
   must include: source identity, target identity, boundary
   name (or "none"), and whether a credential / privilege
   granted the access.

Quick decision shorthand:

| Source | Target | Verdict |
|---|---|---|
| Remote unauth | Anything local | Boundary (network) |
| Standard user | SYSTEM / kernel / other user | Boundary if no privilege grants it |
| Standard user | Same user, higher IL | Not a boundary (UAC) |
| Admin | SYSTEM / kernel / PPL | Not a boundary |
| AppContainer | Outside capabilities | Boundary |
| LPAC (browser renderer) | Anything | Boundary |
| Guest VM | Host / other VM | Boundary |
| VTL0 | VTL1 / Credential Guard secret | Boundary |

## Rules

- Never claim "UAC bypass" as a vulnerability. Record it as
  a primitive and look for a chain.
- Never claim "admin -> SYSTEM" or "admin -> kernel via
  driver" as a vulnerability. Both are by-design.
- Never claim PPL, AMSI, ETW, MOTW, or AppLocker bypass as
  a vulnerability without an accompanying boundary crossing.
- Always record the integrity level and AppContainer SID of
  any process-level primitive — without them, triage is
  impossible.
- Treat any pre-auth network primitive on a Windows-exposed
  service as boundary-crossing until proved otherwise.
- Treat AppContainer escapes as boundary crossings even when
  the escaped-to context is medium IL — the boundary is the
  AppContainer, not the IL delta.
- Default to caller-side privilege check before claiming a
  process-isolation break: `SeDebugPrivilege` and
  `SeImpersonatePrivilege` are common false positives.
- Hyper-V guest -> host is always a boundary; never report
  guest-internal LPE as a hypervisor finding.
- VBS / HVCI is a boundary only against VTL1 secrets
  (Credential Guard creds, KMCI policy). User-mode code
  running inside a normal VM does not cross VBS.
- When unsure, default to "defense-in-depth bypass, not
  vuln" and let the planner decide whether to chain it.
