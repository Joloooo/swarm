---
name: fuzzing-course
description: Educational reference for advanced fuzzing techniques — coverage-guided fuzzing concepts, mutation strategies, harness design, sanitizer integration. Read this when the planner or a fuzzing-related skill needs deeper background than the operational `fuzzing` skill provides. Reference-only — not dispatched as an attack agent.
---

# Fuzzing — Background Reference

Background material for fuzzing campaigns. The operational `fuzzing` skill
explains what to do; this file explains why those choices work and what the
underlying tools assume. Reach for it when you need to justify a harness
decision, interpret a sanitizer report, or pick between fuzzer families.

Adapted from the Pwn3rzs offensive exploit-development curriculum (Week 2,
MIT-licensed). Toolchain-only build steps and kernel-fuzzing labs from the
upstream material are stripped — they do not apply to web pentest contexts.

## What fuzzing actually is

Fuzzing is automated input generation against a target, looking for inputs
that crash, hang, or violate a stated invariant. The fuzzer mutates a corpus
of seed inputs, runs the target, watches for signals (signals, sanitizer
aborts, assertion failures, timeouts), and saves the inputs that produced
those signals.

Three things make a fuzzer effective:

1. **Mutation quality** — does the next input it tries reach new code?
2. **Signal quality** — when a bug is hit, does the fuzzer notice?
3. **Throughput** — how many inputs per second can it execute?

A weak fuzzer fails on at least one of these. AFL++ improved on naive
fuzzing by adding coverage feedback (mutation quality). AddressSanitizer
improved signal quality. Persistent and in-process modes improved
throughput. Modern campaigns combine all three.

## Coverage-guided fuzzing

The core idea: instrument the target so every executed branch is recorded.
After each input, compare the branch trace to a global "seen" set. If the
input hit a new branch, save it to the corpus and prefer mutating it.

This turns fuzzing from random search into directed exploration. The
fuzzer naturally drifts toward inputs that exercise more of the target's
code, even when the path requires very specific values (magic bytes,
checksums, length fields).

Coverage feedback is what separates AFL++, libFuzzer, Honggfuzz, and
FuzzTest from old "dumb" fuzzers like zzuf. It is also why instrumentation
matters: AFL++'s `afl-clang-fast` and libFuzzer's `-fsanitize=fuzzer` both
inject the bookkeeping needed for the feedback loop.

## Fuzzer families and when to pick which

- **AFL++** — process-level fuzzer. Forks a fresh target for each input,
  or uses persistent mode for speed. Best when you have a binary that
  takes a file or stdin and you want black-box-style fuzzing with
  instrumentation. Strong default for unknown targets.
- **libFuzzer** — in-process fuzzer driven by a `LLVMFuzzerTestOneInput`
  function. Much faster than AFL++ because it never forks. Best when you
  control the source and can write a small C/C++ harness around the
  target API.
- **Honggfuzz** — process-level, multi-threaded, supports hardware-assisted
  coverage (Intel PT). Often used in OSS-Fuzz infrastructure. Useful for
  large or complex targets where AFL++ throughput stalls.
- **Google FuzzTest** — unit-test-style. You write `FUZZ_TEST(...)` next
  to your `TEST(...)` cases. Coverage-guided under the hood (libFuzzer).
  Best for property-based fuzzing of individual functions in a code base
  that already uses GoogleTest.
- **Syzkaller** — kernel-syscall fuzzer. Out of scope for web pentest but
  worth knowing about because the same coverage-guided principles apply
  one layer down.

For black-box web targets, none of these apply directly. Web fuzzing
typically uses tools like `ffuf`, `wfuzz`, or `Burp Intruder` over HTTP,
which are dictionary-driven rather than coverage-guided. The deep theory
here is mostly relevant when fuzzing parsers, decoders, or backend
binaries reachable through a web surface (file upload handlers, image
thumbnailers, archive extractors, XML/JSON parsers, deserializers).

## Mutation strategies

Coverage-guided fuzzers combine several mutation operators per generation:

- **Bit/byte flips** — small, cheap, finds byte-level boundary bugs.
- **Arithmetic** — increment/decrement integers in the input. Catches
  off-by-one and signed/unsigned issues.
- **Interesting values** — substitute known-troublesome integers
  (0, -1, INT_MAX, MIN, powers of two ± 1).
- **Block operations** — copy, delete, splice chunks between corpus
  entries. Reorders structure.
- **Dictionary tokens** — when a format dictionary is supplied
  (e.g. JSON keywords, HTTP method names, SQL keywords), the fuzzer
  inserts these tokens directly. Reaches deep parsing logic faster than
  random mutation.
- **Havoc / splicing** — large, random combinations of the above. Used
  when other operators stop producing new coverage.

Structure-aware fuzzing (e.g. libprotobuf-mutator, FuzzTest's domain
specifications) lets the fuzzer mutate inputs at the level of the format
rather than raw bytes. This is critical for highly-structured inputs like
protocol buffers, AST nodes, or signed/checksummed records — random byte
mutation almost never produces a valid header, so the fuzzer never
reaches the interesting code.

## Sanitizers — turning bugs into crashes

A bug only matters if the fuzzer notices. Sanitizers instrument the
target so that subtle memory or arithmetic errors abort the program
immediately, instead of silently corrupting state.

- **AddressSanitizer (ASan)** — detects heap, stack, and global buffer
  overflows; use-after-free; double-free. Roughly 2× slowdown, ~3× memory.
  Indispensable.
- **UndefinedBehaviorSanitizer (UBSan)** — catches signed integer
  overflow, shifts past width, null deref, type confusion. Cheap. Pair
  with ASan on every campaign.
- **MemorySanitizer (MSan)** — detects use of uninitialised memory.
  Higher overhead, more setup (whole-program rebuild including libc
  shims), but finds info-leak bugs.
- **ThreadSanitizer (TSan)** — race-condition detection. Mutually
  exclusive with ASan. Use on multi-threaded targets when you suspect
  concurrency bugs.
- **LeakSanitizer (LSan)** — bundled with ASan. Detects memory leaks at
  process exit. Useful in persistent harnesses to catch state pollution.
- **KASAN / KCOV** — kernel-side ASan and coverage. Used by Syzkaller.

Without sanitizers, fuzzing finds only inputs that segfault. With them,
it finds out-of-bounds reads, type confusions, and integer overflows
that would otherwise corrupt silently and surface as exploitable bugs
months later in production.

## Seed corpus quality

Random bytes are a terrible starting point. The fuzzer wastes generations
on inputs that fail in the first few bytes of format validation, never
reaching deeper parsing logic. A good corpus:

- Contains valid inputs covering the format's major features (e.g. for
  WebP: lossy, lossless, animated, with/without alpha).
- Is small in file size — smaller files mean faster mutation and faster
  execution.
- Is minimised: corpus minimisation (`afl-cmin`) drops files that
  contribute no unique coverage; per-file minimisation (`afl-tmin`)
  shrinks each file while preserving its coverage trace.

Rule of thumb: a 15-file 500 KB minimised corpus often outperforms a
50-file 5 MB raw corpus on the same target.

## Harness design

A fuzzing harness is the glue between the fuzzer's input buffer and the
target's API. The harness decisions dominate campaign quality:

- **In-process beats out-of-process.** A `LLVMFuzzerTestOneInput`-style
  harness runs thousands of inputs per second per core. A CLI wrapper
  that opens a file each iteration runs hundreds at best.
- **Target the API, not the binary.** Bypass argument parsing, file I/O,
  network setup. Hand the input directly to the parser or decoder.
- **Exercise many code paths per input.** After parsing, walk the parsed
  tree, serialise back to text, query field values. More API calls per
  input means more coverage per generation.
- **Clean up between iterations.** Free everything the harness allocated.
  Persistent-mode fuzzers run thousands of iterations in one process —
  leaks accumulate and can mask real bugs as OOMs.
- **Fail closed.** If the input is malformed enough that the API returns
  an error, return cleanly. Do not assert or abort on expected error
  paths — that turns parser rejection into false-positive crashes.

## Crash triage and exploitability

A campaign that finds 200 crashes typically has 5-10 unique root causes.
Triage steps:

1. **Deduplicate.** Tools like `casr-afl` cluster crashes by stack hash.
   Hundreds collapse to a handful of unique bugs.
2. **Minimise.** `afl-tmin` (or libFuzzer's built-in minimiser) shrinks
   the crashing input while preserving the crash. Smaller inputs make
   root-cause analysis easier.
3. **Read the sanitizer report.** ASan tells you the bug class
   (heap-buffer-overflow, use-after-free, etc.), the access size, the
   allocation site, and the access site. This is usually enough for
   root cause.
4. **Classify exploitability.** Tools like CASR provide a heuristic
   rating (EXPLOITABLE, PROBABLY_EXPLOITABLE, NOT_EXPLOITABLE). These
   are a starting point only — sanitizer instrumentation may abort
   before the actual exploit primitive (e.g. CASR rates a UAF read of a
   function pointer as not exploitable, even though hijacking that
   pointer is straightforward without ASan).
5. **Manual verification.** Reproduce in GDB without sanitizers (or
   with `quarantine_size_mb=0`) to see real heap behaviour. Check
   whether the attacker controls overflow size, overflow contents, or
   the freed-then-reused object.

The honest exploitability question is: does the input control enough of
the corrupted state to direct execution? Heap overflow with attacker
controlled size and contents → usually exploitable. UAF where the freed
object is immediately reallocated by the same code path → usually
exploitable. UAF where the freed object is never reused → likely just a
crash.

## Where fuzzing fits in web pentest

Direct relevance is narrow but real:

- **File-upload backends** that invoke libwebp, libpng, ImageMagick,
  ffmpeg, etc. on attacker-supplied content. Past CVEs in these
  parsers (CVE-2023-4863 libWebP, CVE-2024-47606 GStreamer) were all
  fuzzer-discovered.
- **Archive extractors** behind upload endpoints (libarchive, p7zip,
  unrar). Path traversal via crafted symlinks (CVE-2023-38831 WinRAR
  family) is fuzz-discoverable.
- **Deserializers** — XML (XXE, billion laughs), YAML, protobuf, AMF,
  Java/PHP/.NET native serialization. Structure-aware fuzzing is the
  natural tool here.
- **Custom binary protocols** exposed over WebSocket or raw TCP behind
  the web frontend.

For pure HTTP-layer testing (parameter discovery, IDOR enumeration,
input-validation bypass) use dictionary-driven HTTP fuzzers. The
coverage-guided machinery here is overkill and the wrong abstraction.

## The campaign loop, in one line

`fuzz → crash → deduplicate → minimise → triage with ASan → root cause →
exploitability check → write PoC`. Every fuzzer family follows this
shape. Tool choice changes the constants, not the steps.
