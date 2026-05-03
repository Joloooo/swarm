---
name: windows-mitigations
description: Reference document on Windows security mitigations — DEP, ASLR, CFG, CET (Intel Shadow Stack / IBT), ACG, CIG, PPL (Protected Process Light), HVCI, VBS / Credential Guard, smart app control, EAF / EAF+, SEHOP — how each works, what attacks it stops, known bypass classes, and how an attacker fingerprints whether a given target has each enabled. Used by other skills when planning Windows attack chains. Reference-only — not dispatched.
---

This skill is a **reference catalogue** for Windows exploit mitigations. It is
loaded by other skills that need to reason about *what is in the way* on a
Windows target — exploit-dev, post-exploitation, EDR/AV evasion, BYOVD, kernel
work — before committing to a payload or technique. SwarmAttacker is a
black-box web pentester; this skill exists so that when an attack chain
crosses into a Windows binary or kernel boundary, the planner has a compact
description of every mitigation, what it actually blocks, the well-known
bypass classes, and what to read to detect it on the target.

The catalogue is split into three blocks:

1. **Per-mitigation table** — one row per mitigation, with mechanism, what it
   stops, and known bypass classes.
2. **Fingerprinting** — for each mitigation, what to read or probe (PE
   headers, registry keys, WMI, process tokens, CPUID, syscalls) to decide
   whether it is enabled on the target.
3. **Rules** — short list of invariants the planner should respect when
   chaining mitigations together.

Mitigations not covered here (KASLR, SMEP, kCFG, KDP, WDAC, WDEG specific
EAF variants, Pluton, Administrator Protection, Smart App Control variants
beyond the row below) are referenced only where they interact with a row.

## Per-mitigation table

| Mitigation | Layer | Mechanism | Stops | Known bypass classes |
|------------|-------|-----------|-------|----------------------|
| **DEP / NX** | CPU page table | NX bit on PTE; data pages marked non-executable. Stack, heap, .data are RW; code is RX. Page fault on instruction fetch from NX page → `STATUS_ACCESS_VIOLATION` (0xC0000005, param 8). | Direct shellcode execution from stack/heap. | ROP / JOP (no new code, reuse `ret`/`jmp` gadgets); call `VirtualProtect` / `VirtualAlloc(PAGE_EXECUTE_READWRITE)` to flip pages to RWX; abuse JIT pages (`PAGE_EXECUTE_READWRITE` mapped legitimately by browser/.NET runtime); return-to-libc style chaining into `WinExec` / `system`. |
| **ASLR / DYNAMICBASE** | Loader | Per-boot random seed offsets module image base, stack, heap, PEB/TEB. With `/HIGHENTROPYVA` x64 EXE has ~17 bits, DLLs ~19 bits. | Hardcoded address exploitation; jumps to fixed gadget addresses. | Info leak (any pointer disclosure: format string `%p`, uninitialised memory, stack trace, side-channel) → derives base for entire module; partial overwrite of low bytes (high bytes stay random); non-ASLR module loaded into the process (`DYNAMICBASE` flag absent → image at preferred base every time); brute force on x86 (8 bits = 256) when remote process auto-restarts; shared DLL bases across processes within one boot — leak from any process gives base in target process. |
| **/GS stack cookie** | Compiler | Random cookie placed between locals and saved RBP/return; checked at epilogue; mismatch → `__report_gsfailure` → `__fastfail(2)` → exit 0xC0000409. | Naive linear stack overflow that overruns return address. | Cookie info leak (read-then-write); overflow that does not cross the cookie (corrupt local pointer / variable only); overwrite of SEH chain on x86 before cookie check (SEH-based bypass); structured exception unwinding skipping the check on some legacy x64 paths; targeting non-`/GS` functions (small frames, no buffers) reachable through corrupted function pointers. |
| **SafeSEH / SEHOP** | Linker + loader (x86 only) | `/SAFESEH` registers valid handlers in PE; SEHOP walks the SEH chain at dispatch time and verifies it terminates at `ntdll!FinalExceptionHandler`. x64 uses table-based unwinding in `.pdata` (read-only) — classic SEH overwrite is impossible there. | x86 SEH-overwrite exploitation pre-Vista. | x86 only — bypass by loading a non-SafeSEH module and pivoting through it; corrupt VEH list (`ntdll!LdrpVectorHandlerList`) via heap corruption; on x64 attack vectored handlers / `.pdata` parsing bugs instead. |
| **CFG (Control Flow Guard)** | Compiler + OS bitmap | `/guard:cf` instruments every indirect call/jmp with `__guard_check_icall`; OS keeps a per-process bitmap of all valid call targets; non-target → `__fastfail(0xA)` → exit 0x80000003. | Indirect call to shellcode, mid-function gadget, arbitrary RVA. Forward-edge only. | ROP via `ret` (CFG does **not** validate return addresses — that is CET's job); call to *any* valid function entry, including dangerous ones (`VirtualProtect`, `WinExec`, `LoadLibrary`) — CFG is target-set, not type-checked; non-CFG-instrumented call site (any DLL not built with `/guard:cf`); JIT-emitted indirect calls; data-only attacks; overwrite of `__guard_check_icall_fptr` itself if writable. |
| **XFG (eXtended Flow Guard)** | Compiler | CFG + per-call-site type-hash check — target's signature hash must match the call site's. | CFG-bypass via valid-but-wrong-signature function (e.g. `VirtualProtect` from a vtable site). | Type collisions (find a valid target whose hash matches); same-signature gadgets; not universally enabled — most third-party DLLs ship CFG only. |
| **CET Shadow Stack (SHSTK)** | CPU (Intel 11th gen+, AMD Zen 3+) | Hardware shadow stack pushes return address on `call`; on `ret` CPU compares main-stack and shadow-stack addresses; mismatch → `#CP` exception → `__fastfail(0x16)` → exit 0xC0000407. | All ROP that overwrites a return address on the main stack. | Bypass requires not corrupting saved return: pure data-only attacks; corrupt function pointer / vtable instead of return (CFG/XFG then become primary defence); `INCSSP` / `RSTORSSP` abuse if attacker has an existing primitive in CET-aware code; processes without `CETCOMPAT` bit fall back to no-op (silent fallback common in VMs without hypervisor passthrough); kernel-mode code mostly not yet covered (Kernel Shadow Stack lags user-mode). |
| **CET IBT (Indirect Branch Tracking)** | CPU + compiler | Every valid indirect-jmp/call target must begin with `ENDBR64` / `ENDBR32`; CPU tracks `WAIT_FOR_ENDBR` after indirect branch; missing ENDBR → `#CP`. | JOP-style gadgets that jump into mid-function. | Find an `ENDBR`-prefixed gadget (any function entry qualifies); call/jmp pairs where the target is a real function; legacy non-IBT module mapped in process — branches into it not enforced. |
| **ACG (Arbitrary Code Guard)** | Process mitigation policy | Blocks `VirtualAlloc(PAGE_EXECUTE_*)`, blocks `VirtualProtect` raising X on non-X pages, blocks dynamic code generation (JIT). Used by Edge content processes. | Shellcode injection, JIT spraying, stage-2 reflective loaders that need to flip RWX. | Abuse out-of-process code generation (broker / "JITless" sandbox-escape style — JIT code is generated in a sibling broker process and mapped read-only into the ACG process); overwrite an existing executable mapping (e.g. corrupt mapped DLL via shared memory bug); pure ROP/JOP using existing module code; ACG-disabled child process spawned. |
| **CIG (Code Integrity Guard)** | Process mitigation policy | Only Microsoft- or WHQL-signed images may be mapped into the process; loader rejects unsigned DLLs. | DLL injection, DLL search-order hijack with attacker-controlled DLL, reflective DLL load (when image must traverse mapping APIs). | Manual map / reflective loader that never goes through `LoadLibrary` (parses PE in private memory then chains ROP — but combined with ACG this is closed); side-load a Microsoft-signed-but-vulnerable DLL ("LOLBins"); sign the payload (stolen / leaked cert); abuse a process not opted into CIG. |
| **PPL (Protected Process Light)** | Kernel | Process is given a Protection level (signer + level) at creation; only equal-or-higher PPL may open with sensitive accesses (`PROCESS_VM_READ`, `PROCESS_VM_WRITE`, debug, `PROCESS_QUERY_LIMITED_INFORMATION` is allowed). Used for `lsass.exe` (with RunAsPPL), antimalware, Windows Defender. | Userland LSASS dump (mimikatz `sekurlsa::logonpasswords`), AV-process tampering by admin malware. | Load a signed-but-vulnerable kernel driver (BYOVD — `mimidrv`, `RTCore64`, `gdrv`) and clear `EPROCESS.Protection` from kernel; exploit a kernel vulnerability; abuse a misconfigured PPL signer hierarchy (lower-tier PPL opening higher-tier service when ACL allows); shadow-copy `lsass` memory via VSS instead of opening the process. |
| **HVCI / Memory Integrity** | Hypervisor (VTL 1) | Secure Kernel validates every kernel page before it is marked executable; only Microsoft- or WHQL-signed code may receive X. Kernel pages are W^X enforced by EPT. | Unsigned kernel driver loading, kernel shellcode injection via arbitrary write. | BYOVD with a *signed* vulnerable driver — HVCI checks integrity, not quality; data-only kernel attacks (corrupt `EPROCESS.Token`, `SEP_TOKEN_PRIVILEGES`, page table entries) — no new code needed; exploit a hypervisor or Secure Kernel CVE; downgrade attacks where HVCI is not in `UEFI lock` mode and an admin can disable it via registry. |
| **VBS** | Hypervisor | Hyper-V + VTL split: Normal World (VTL 0) cannot read/write Secure World (VTL 1). Substrate for HVCI, Credential Guard, KDP. | Direct kernel-mode read of VTL 1 secrets; tampering with secure-kernel-protected pages from VTL 0. | Disable VBS pre-boot (UEFI/registry if not locked); hypervisor escape; attack the IUM trustlet itself; not booted with VBS at all on a target → no protection. |
| **Credential Guard** | VBS / VTL 1 | NTLM hashes, Kerberos TGTs, cached domain creds live inside `lsaiso.exe` (LSA Isolated) in VTL 1; LSASS holds only opaque handles. | `mimikatz sekurlsa::logonpasswords` (returns null hashes); pass-the-hash from RAM dump. | Shoulder-surf credentials at logon (keylogger, SSPI hooks before isolation); steal Kerberos tickets that are still in LSASS handle form for ongoing sessions; downgrade NTLM (force NTLMv1 if not removed); abuse delegation / S4U2Self; not enabled on Pro/Home editions, not enabled before Windows 10 Enterprise. |
| **Smart App Control (SAC)** | OS | Cloud-reputation gate at process creation; unknown / untrusted PEs and scripts blocked. Clean-install only on Windows 11 22H2+; once disabled cannot be re-enabled. | Running unknown unsigned malware payloads. | LOLBins (signed Microsoft binaries: `mshta`, `wmic`, `regsvr32`, `installutil`); signed malware (stolen cert); LNK / ISO / VHD smuggling that strips MOTW; in `Evaluation` mode it monitors but does not block. |
| **EAF / EAF+ (Export Address Filter)** | EMET / Exploit Protection | Hardware breakpoints on the Export Address Tables of `ntdll`, `kernel32`, etc.; trips on read access from non-image (i.e. shellcode walking exports to resolve `LoadLibrary`/`GetProcAddress`). EAF+ extends to additional modules and adds stack-pointer / module sanity checks. | Position-independent shellcode using PEB→Ldr→export-walk to resolve APIs. | Resolve APIs through PEB walk only (no EAT read) — use `LDR_DATA_TABLE_ENTRY` lists instead; pre-resolved API table baked into the loader by the operator; clear the hardware breakpoints (Dr0–Dr3) from the shellcode (requires arbitrary write to debug registers, generally needs ring-0 or `NtSetContextThread`); use direct syscalls (`syscall` instruction with hardcoded SSN). |

## Fingerprinting

For each mitigation, what to **read** or **probe** to decide whether it is on
for a given target. Most of these require code execution on the box; the
remote-only column flags the few that survive black-box recon.

| Mitigation | Read this | Tells you | Remote-only signal |
|------------|-----------|-----------|--------------------|
| **DEP / NX** | `IsProcessorFeaturePresent(PF_NX_ENABLED)` (hardware support); `GetProcessDEPPolicy()` (per-process); `Get-CimInstance Win32_OperatingSystem` → `DataExecutionPrevention_SupportPolicy` (system policy: 0 AlwaysOff / 1 AlwaysOn / 2 OptIn / 3 OptOut); PE `DllCharacteristics` bit `0x0100` ("NX compatible") via `dumpbin /headers`. | Hardware NX present; per-process DEP policy; system policy mode; per-binary opt-in. | None reliable — assume DEP on for any modern Windows process. |
| **ASLR** | PE `DllCharacteristics` bit `0x0040` ("Dynamic base") and `0x0020` ("High Entropy VA") via `dumpbin /headers <file>`; compare module base across reboots in WinDbg `lm`; `Get-ProcessMitigation -Name <exe>` → `ASLR.{BottomUp,ForceRelocateImages,HighEntropy}`. | Per-binary ASLR opt-in; whether `ForceRelocateImages` is set (per-launch randomisation); kernel ASLR is implicit on modern Win 10/11. | If a remote service leaks any pointer (stack trace, debug page, version banner with hash), compare across reconnects to infer base randomisation. |
| **/GS** | PE `/GS` is not a `DllCharacteristics` flag — detect via `dumpbin /loadconfig` showing `Security Cookie` field set, and presence of `__security_cookie` / `__security_check_cookie` symbols. | Per-binary cookie protection. | None. |
| **SafeSEH / SEHOP** | PE `DllCharacteristics` bit `0x0400` ("No SEH"); `dumpbin /loadconfig` → "Safe Exception Handler Table"; `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation` (0 = SEHOP enabled); `Get-ProcessMitigation` → `SEHOP.Enable`. | x86 SEH posture only — irrelevant on x64 binaries (table-based unwind is mandatory). | None. |
| **CFG** | PE `DllCharacteristics` bit `0x4000` ("CF Guard") + `0x8000` ("Guard CF function table"); `dumpbin /headers /loadconfig` → "Guard CF function count", "Guard Flags"; `Get-ProcessMitigation -Name <exe>` → `CFG.Enable`. | Per-binary CFG + presence of the CFG bitmap. Look for `0x10014500`-style Guard Flags. | None. |
| **XFG** | `dumpbin /loadconfig` → "Guard CF function count" with type-hash entries; `Guard Flags` includes XFG bit; XFG functions in disassembly carry a hash before `endbr64`. | Per-binary XFG instrumentation. | None. |
| **CET SHSTK** | CPUID leaf 7 ECX bit 7 (`CET_SS`) for hardware support; PE `IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT` (Extended DLL Characteristics, separate from regular `DllCharacteristics`); `Get-ProcessMitigation -Name <exe>` → `UserShadowStack.{Enable,StrictMode,Audit}`; in WinDbg: `dx @$cursession.Processes[pid].Threads[tid].Stack.Frames` — shadow stack visible if SSP non-zero. | Whether the binary opts into CET, whether CPU supports it, and whether the policy is in audit-only or strict-mode. **Beware**: policy ON without hardware passthrough silently no-ops on most VMs. | None. |
| **CET IBT** | Look for `endbr64` / `endbr32` at function entries in disassembly; `IMAGE_DLLCHARACTERISTICS_EX` IBT bit; `Get-ProcessMitigation` → IBT-related fields. | Per-binary IBT compilation. | None. |
| **ACG** | `Get-ProcessMitigation -Name <exe>` → `DynamicCode.BlockDynamicCode`; or via `GetProcessMitigationPolicy(ProcessDynamicCodePolicy)` from inside the target. | Per-process ACG. Edge / WebView2 content procs typically ON. | None. |
| **CIG** | `Get-ProcessMitigation -Name <exe>` → `BinarySignature.MicrosoftSignedOnly`; `GetProcessMitigationPolicy(ProcessSignaturePolicy)`. | Per-process CIG. | None. |
| **PPL** | `Get-Process <name> | Format-List ProcessName, Id, *Protect*` — but the cleanest read is via NtQueryInformationProcess(`ProcessProtectionInformation`) → `PS_PROTECTION { Type, Audit, Signer }`; in WinDbg/livekd: `!process 0 0 lsass.exe` → look for `Protected: Yes (Signer: Lsa-Light)`. | Protection level + signer of the process. Tells you whether `OpenProcess(PROCESS_VM_READ)` will be denied. | None. |
| **HVCI** | `Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard` → `SecurityServicesRunning` array contains `2`; **note** `Get-ComputerInfo | Select DeviceGuardSmartStatus` is misleading — "Off" does *not* mean HVCI off, it means full Device Guard policy not enforced. Settings UI: Windows Security → Device Security → Core Isolation → Memory Integrity. | Whether kernel signed-code enforcement is live. | None. |
| **VBS** | Same `Win32_DeviceGuard` → `VirtualizationBasedSecurityStatus` (0/1/2 = off/enabled-not-running/running); `DeviceGuard*` properties from `Get-ComputerInfo`. | Whether the hypervisor split is active. Often disabled in nested VMs. | None. |
| **Credential Guard** | `Win32_DeviceGuard.SecurityServicesRunning` contains `1`; check `Get-ComputerInfo` → `WindowsEditionId` (must be Enterprise/Education); `lsaiso.exe` running in process list. | LSA isolation active; mimikatz will return null hashes. | None. |
| **Smart App Control** | `HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy` → `VerifiedAndReputablePolicyState` (0 Off / 1 Enforcement / 2 Evaluation); also visible in Windows Security UI. | SAC mode. Once `Off` it cannot be re-enabled without re-install. | None. |
| **WDAC / App Control** | `Win32_DeviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus` (0 Off / 1 Audit / 2 Enforced); `citool.exe -lp` lists active policies; `Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational"` for blocks (3076 audit, 3077 enforce). | Application whitelisting policy state. | None. |
| **EAF / EAF+** | `Get-ProcessMitigation -Name <exe>` → `ExportAddressFilter.{Enable,Audit}` and `ExportAddressFilterPlus.{Enable,Audit,Modules}`; presence of hardware breakpoints (Dr0–Dr3) on EAT addresses inside `ntdll`. | Per-process EAF state and module list for EAF+. | None. |

### PE `DllCharacteristics` quick-reference

The single most economical fingerprint for any on-disk binary. Read with
`dumpbin /headers <file> | findstr "DLL characteristics"` — the hex value
ANDs against:

| Flag | Bit | Mitigation |
|------|-----|------------|
| `IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA` | `0x0020` | High-entropy 64-bit ASLR |
| `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` | `0x0040` | ASLR (`/DYNAMICBASE`) |
| `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` | `0x0100` | DEP-aware (`/NXCOMPAT`) |
| `IMAGE_DLLCHARACTERISTICS_NO_SEH` | `0x0400` | No SEH chain (x86) |
| `IMAGE_DLLCHARACTERISTICS_GUARD_CF` | `0x4000` | Control Flow Guard instrumentation |
| (CF function table present) | `0x8000` | CFG bitmap referenced via load config |

CET-Compat lives in the *Extended* DLL characteristics field
(`IMAGE_DLL_CHARACTERISTICS_EX_CET_COMPAT`) and is reported separately by
`dumpbin /headers /loadconfig`.

### Crash signature → mitigation map

When the agent observes a Windows crash on the target (post-RCE, fuzzer
output, log scrape) the exit/exception code disambiguates which mitigation
fired. Useful for inferring posture without reading config.

| Process exit | WinDbg exception | Caused by |
|--------------|------------------|-----------|
| `0xC0000005` (param[0]=8) | `0xC0000005` | DEP / NX violation (execute on NX page) |
| `0xC0000409` (subcode 2) | `0xC0000409` | `/GS` stack cookie corruption (`__fastfail(2)`) |
| `0x80000003` | `0xC0000409` (subcode 0xA) | CFG indirect-call validation failed |
| `0x80000003` | `0xC0000407` | CET shadow stack mismatch (`#CP`) |
| `0xC0000374` | `0xC0000374` | Heap integrity check (`_HEAP` / Segment Heap LFH) |

## Rules

1. **Mitigations stack — bypassing one rarely buys exploitation alone.** A
   modern Windows 11 24H2 process typically has DEP + ASLR + /GS + CFG + CET
   + ACG + CIG simultaneously. An ROP chain bypasses DEP but trips CET; a
   `VirtualProtect` call bypasses CET but trips ACG; a DLL inject bypasses
   ACG but trips CIG. Plan the chain by listing every active mitigation
   first, then picking a path through.

2. **Forward-edge ≠ backward-edge.** CFG/XFG/IBT protect indirect
   *calls/jmps*. CET protects *returns*. ROP needs only `ret` gadgets and is
   immune to CFG. JOP needs only `jmp [reg]` and is immune to CET shadow
   stack. The two together close most code-reuse paths in user mode; data-
   only attacks remain.

3. **An info leak is not optional.** With `/HIGHENTROPYVA` on, blind brute
   force of x64 module bases is infeasible. Every modern chain includes a
   leak primitive (uninit memory, format string, OOB read, side-channel,
   sibling-process pointer leak). If the bug class does not yield a leak,
   chain it with one before attempting RCE.

4. **HVCI does not stop data-only kernel attacks.** It stops *new code* in
   the kernel. Token-stealing, page-table corruption, `CI!g_CiOptions`
   patching from kernel-data primitives, and BYOVD all stay viable. Plan
   kernel work as data-only by default on HVCI hosts.

5. **PPL is a userland boundary, not a kernel one.** Once you have ring-0
   (legitimately or via BYOVD) PPL is trivially cleared. Treat PPL as a
   filter on which userland primitives work, not as a real defence against
   kernel-capable adversaries.

6. **Policy ON ≠ enforcement on.** CET, HVCI, Credential Guard, VBS all
   silently fall back to no-op when hardware passthrough is missing
   (VirtualBox guests, non-CET CPUs, non-SLAT firmware). Always corroborate
   `Get-ProcessMitigation` policy reads with a *behavioural* probe (try the
   primitive in audit mode and read `Microsoft-Windows-Security-Mitigations`
   event log) before concluding the mitigation is active.

7. **PE `DllCharacteristics` is the cheapest fingerprint.** `dumpbin
   /headers <file>` reveals DEP, ASLR, High-Entropy VA, CFG, CFG-table,
   No-SEH for any binary on disk in milliseconds, with no kernel access.
   Use this first; fall back to `Get-ProcessMitigation` and WMI only for
   process-policy mitigations (ACG, CIG, EAF, UserShadowStack) and
   system-wide ones (HVCI, VBS, Credential Guard, SAC, WDAC).

8. **Third-party DLLs are the soft underbelly.** A Microsoft binary may be
   fully hardened, but a vendor DLL loaded into the same process — without
   `/guard:cf`, without `/CETCOMPAT`, without `/HIGHENTROPYVA` — drags every
   protection in the process down to its level for any call site that
   reaches it. Inventory the loaded modules of the target process; the
   weakest module sets the bar.

9. **SwarmAttacker scope — this skill is consulted, not executed.**
   SwarmAttacker is a black-box web pentester. The catalogue is here so that
   when web exploitation lands a Windows command-execution primitive (RCE,
   deserialization, file upload to a service running on Windows), the
   planner can reason about what the next stage will face — UAC, AV/EDR,
   PPL, CIG, AMSI, ASR rules, etc. — without launching exploit-dev work the
   agent is not equipped to perform. If the chain demands real Windows
   exploit development, escalate to the human operator.
