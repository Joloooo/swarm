#!/usr/bin/env python3
"""Reconstruct May-9-2026 ("hard era") system prompts for refused requests.

We captured 411 refused worker/planner requests during recent benchmark
runs. Each was assembled with the CURRENT (softened, post-2026-05-10)
system prompt. This script rebuilds, for every case, the OLD hard-tone
system prompt that the SAME request would have carried at commit
``2de37c8`` (2026-05-09) — replacing ONLY ``request.system_prompt`` and
leaving ``request.messages`` and everything else byte-identical.

No LLM is run. The output is a new JSONL corpus the replay harness reads.

How the OLD prompt is assembled (faithfully copied from the 2de37c8
sources, see ``_extract_old_constants``):

  non-minimal worker (executor / recon — old code had ONE builder):
      "\n\n".join([
          header,                 # "You are a penetration testing agent (ID: ...)"
          get_base_prompt(0),     # AUTH_PREAMBLE + NARRATION + PENTEST_RULES + FINDING_FORMAT
          old_skill_body,         # SKILL.md body @ 2de37c8
          RAG_HINT,               # "--- Dynamic Knowledge ---" block
          BENCHMARK_FLAG_ADDENDUM # always appended (all cases are XBEN benchmarks)
      ])

  minimal worker (skip_base_prompt, e.g. request-builder):
      "\n\n".join([old_skill_body, BENCHMARK_FLAG_ADDENDUM])

  planner (_planner — separate builder in 2de37c8 planner.py):
      AUTHORIZATION_PREAMBLE + "\n\n" + SUPERVISOR_SYSTEM_PROMPT
      (SUPERVISOR_SYSTEM_PROMPT with the dynamic __SKILLS_MENU__ rebuilt
       from the 2de37c8 SKILL.md frontmatter descriptions)

The header fields (agent_id / methodology / config_name / target_url) are
parsed from each captured CURRENT prompt so the OLD prompt keeps the same
runtime identity the request actually ran with; only the framing + body
revert to the hard era.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

# Repo-root-relative paths. Script lives at SwarmAttacker/scripts/.
SWARM_DIR = Path(__file__).resolve().parent.parent          # .../SwarmAttacker
REPO_ROOT = SWARM_DIR.parent                                 # .../Thesis
IN_PATH = SWARM_DIR / "logs/safety_tests/refusals_survived_retry1_414.jsonl"
OUT_PATH = SWARM_DIR / "logs/safety_tests/refusals_hardera_reconstructed.jsonl"

ERA_COMMIT = "2de37c8"

# ── Non-hard-era skill → nearest hard-era skill (no old SKILL.md exists) ──
SKILL_MAP = {
    "vulntype-information-disclosure": "information-disclosure",
    "vulntype-lfi": "lfi",
    "vulntype-rce": "rce",
    "vulntype-sqli": "sqli",
    "vulntype-ssti": "ssti",
    "vulntype-insecure-file-uploads": "insecure-file-uploads",
    "owasp-input-validation": "input-validation",
    "owasp-auth": "auth-testing",
    "owasp-session": "session-mgmt",
    "owasp-business-logic": "business-logic",
    "methodology-fuzzing": "fuzzing",
    "recon-ports": "recon",
}


def git_show(path: str) -> str | None:
    """Return the contents of ``<ERA_COMMIT>:<path>`` or None if absent."""
    try:
        return subprocess.run(
            ["git", "show", f"{ERA_COMMIT}:{path}"],
            cwd=REPO_ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return None


# ── SKILL.md frontmatter / body splitter (mirrors loader._split_frontmatter) ──
def split_frontmatter(text: str) -> tuple[dict, str]:
    import yaml
    if not text.startswith("---"):
        return {}, text
    rest = text[3:].lstrip("\n")
    parts = rest.split("\n---", 1)
    if len(parts) != 2:
        return {}, text
    raw_yaml, body = parts
    try:
        meta = yaml.safe_load(raw_yaml) or {}
    except yaml.YAMLError:
        return {}, text
    if not isinstance(meta, dict):
        return {}, text
    return meta, body.lstrip("\n")


def old_skill_body(skill_dir: str) -> str | None:
    text = git_show(f"SwarmAttacker/src/skills/{skill_dir}/SKILL.md")
    if text is None:
        return None
    _meta, body = split_frontmatter(text)
    return body


# The planner's free-form ``tasks`` lane registers a per-case config named
# ``executor`` whose ``config.system_prompt`` is the generic-executor
# template with the case's specific task spliced in. There is no
# ``src/skills/executor/SKILL.md`` — the body lives only inside the
# captured prompt. We slice it back out (between the generic-executor
# marker and the first trailing block) to recover the exact runtime
# ``config.system_prompt``, then wrap it in the OLD framing. The task text
# (the only case-specific part, fixed by the planner's decision and
# independent of era) is preserved verbatim; only the surrounding
# authorization framing reverts to the hard era.
_GENERIC_EXEC_MARKER = "You are a generic penetration-testing executor."
_GENERIC_BODY_TAILS = (
    "\n## References",
    "\n## How this exercise is scored",
    "\n--- Dynamic Knowledge ---",
)


def slice_generic_executor_body(sp: str) -> str | None:
    start = sp.find(_GENERIC_EXEC_MARKER)
    if start < 0:
        return None
    ends = [sp.find(t, start) for t in _GENERIC_BODY_TAILS]
    ends = [e for e in ends if e >= 0]
    if not ends:
        return None
    return sp[start:min(ends)].rstrip("\n")


# ── Extract the OLD prompt constants verbatim from 2de37c8 base.py ────────
def _extract_triple_quoted(src: str, name: str) -> str:
    """Pull a verbatim ``NAME = \"\"\"\\ ... \"\"\"`` constant out of source.

    The old prompt constants are all defined as ``NAME = \"\"\"\\\\n...\"\"\"``
    (the leading backslash strips the first newline). We reproduce that
    exactly: capture the body and drop a single leading newline.
    """
    m = re.search(
        rf'^{re.escape(name)} = """\\\n(.*?)\n"""',
        src, re.S | re.M,
    )
    assert m, f"could not extract {name} from old base.py"
    return m.group(1) + "\n"  # closing-quote-on-own-line constants end with \n


def extract_old_constants() -> dict:
    """Pull the OLD prompt constants verbatim from 2de37c8 base.py.

    We do NOT import the module (it drags in langchain + a dataclass whose
    field annotations need the real package). We extract the three relevant
    triple-quoted string constants by regex and re-implement
    ``get_base_prompt(0)`` with the exact same concatenation the old code
    used: "\\n\\n".join([AUTH, NARRATION, PENTEST_RULES, FINDING_FORMAT]).
    """
    src = git_show("SwarmAttacker/src/nodes/base.py")
    assert src is not None, "could not read old base.py"

    auth = _extract_triple_quoted(src, "AUTHORIZATION_PREAMBLE")
    narration = _extract_triple_quoted(src, "NARRATION_RULES")
    pentest = _extract_triple_quoted(src, "PENTESTING_RULES")
    finding = _extract_triple_quoted(src, "FINDING_FORMAT")
    flag_addendum = _extract_triple_quoted(src, "_BENCHMARK_FLAG_ADDENDUM")

    def get_base_prompt(_stealth: int = 0) -> str:
        return "\n\n".join([auth, narration, pentest, finding])

    return {
        "AUTHORIZATION_PREAMBLE": auth,
        "get_base_prompt": get_base_prompt,
        "BENCHMARK_FLAG_ADDENDUM": flag_addendum,
    }


# RAG-hint block — copied verbatim from the 2de37c8 _build_system_message.
OLD_RAG_HINT = (
    "\n--- Dynamic Knowledge ---\n"
    "If you need specific CVE details, bypass techniques, or tool syntax "
    "that you're unsure about, describe what you need and the system will "
    "provide relevant knowledge snippets.\n"
)


# ── Rebuild the OLD planner prompt (AUTH_PREAMBLE + SUPERVISOR body+menu) ──
def build_old_planner_prompt(auth_preamble: str) -> str:
    planner_src = git_show("SwarmAttacker/src/nodes/planner.py")
    assert planner_src is not None

    # The raw SUPERVISOR_SYSTEM_PROMPT triple-quoted body (before the
    # .replace(menu) and the AUTH-preamble prepend).
    m = re.search(
        r'SUPERVISOR_SYSTEM_PROMPT = """\\\n(.*?)\n"""',
        planner_src, re.S,
    )
    assert m, "could not extract old SUPERVISOR_SYSTEM_PROMPT body"
    body = m.group(1)

    menu = build_old_skills_menu()
    body = body.replace("__SKILLS_MENU__", menu)
    return auth_preamble + "\n\n" + body


def build_old_skills_menu() -> str:
    """Reproduce planner._build_skills_menu() against 2de37c8 skills.

    Iterates every old SKILL.md, keeps the ones whose frontmatter sets
    ``metadata.agent_id`` (dispatchable), sorts by config_name, and renders
    the same trimmed one-line hint the old code produced.
    """
    skill_dirs = subprocess.run(
        ["git", "ls-tree", "-d", "--name-only", f"{ERA_COMMIT}:SwarmAttacker/src/skills/"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.split()

    entries: list[tuple[str, str]] = []
    for d in skill_dirs:
        text = git_show(f"SwarmAttacker/src/skills/{d}/SKILL.md")
        if text is None:
            continue
        meta, _body = split_frontmatter(text)
        md = meta.get("metadata") or {}
        if not isinstance(md, dict) or not md.get("agent_id"):
            continue  # reference-only skill — not in the dispatch menu
        config_name = str(md.get("config_name") or d)
        description = str(meta.get("description") or "").strip()
        entries.append((config_name, description))

    entries.sort(key=lambda t: t[0])
    if not entries:
        return "  (no skills loaded — check src/skills/)"
    lines = []
    for name, desc in entries:
        short = desc.split(". ")[0].strip().rstrip(".")
        if len(short) > 220:
            short = short[:220].rstrip() + "..."
        lines.append(f"- {name}: {short}.")
    return "\n".join(lines)


# ── Header parsing from a captured CURRENT prompt ─────────────────────────
_RE_ID = re.compile(r"\(ID:\s*(.+?)\)")
_RE_METH = re.compile(r"^Methodology:\s*(.+?)\s*$", re.M)
_RE_FOCUS = re.compile(r"^Focus area:\s*(.+?)\s*$", re.M)
_RE_TARGET = re.compile(r"^Target:\s*(\S+)\s*$", re.M)


def parse_header(sp: str, skill: str, messages: list) -> dict:
    """Extract agent_id / methodology / config_name / target_url.

    Falls back to skill-derived defaults for recon/minimal cases whose
    captured header has no agent line.
    """
    agent_id = m.group(1).strip() if (m := _RE_ID.search(sp)) else skill
    methodology = m.group(1).strip() if (m := _RE_METH.search(sp)) else "reconnaissance"
    config_name = m.group(1).strip() if (m := _RE_FOCUS.search(sp)) else skill
    target_url = m.group(1).strip() if (m := _RE_TARGET.search(sp)) else _target_from_messages(messages)
    return {
        "agent_id": agent_id,
        "methodology": methodology,
        "config_name": config_name,
        "target_url": target_url or "",
    }


def _target_from_messages(messages: list) -> str:
    for msg in messages or []:
        content = msg.get("content") if isinstance(msg, dict) else None
        if not isinstance(content, str):
            continue
        m = re.search(r"https?://[^\s\"'<>]+", content)
        if m:
            return m.group(0).rstrip(".,)")
    return ""


# ── Path classification of a captured CURRENT prompt ──────────────────────
def classify_path(sp: str, skill: str) -> str:
    if skill == "_planner":
        return "planner"
    if sp.startswith("You are a security testing agent (ID:"):
        return "executor"
    if sp.startswith("Target:"):
        return "recon"
    # No identity framing, no Target header → minimal (skip_base_prompt).
    return "minimal"


def is_minimal_skill(skill: str) -> bool:
    """skip_base_prompt skills at 2de37c8. request-builder is the only
    one in this corpus; confirm against the old frontmatter."""
    text = git_show(f"SwarmAttacker/src/skills/{skill}/SKILL.md")
    if text is None:
        return False
    meta, _ = split_frontmatter(text)
    md = meta.get("metadata") or {}
    return bool(isinstance(md, dict) and md.get("skip_base_prompt"))


def main() -> None:
    consts = extract_old_constants()
    auth = consts["AUTHORIZATION_PREAMBLE"]
    base_prompt = consts["get_base_prompt"](0)
    flag_addendum = consts["BENCHMARK_FLAG_ADDENDUM"]
    old_planner_prompt = build_old_planner_prompt(auth)

    # NB: split on "\n" only — a captured prompt can contain Unicode line
    # separators (U+2028/U+0085) that str.splitlines() would wrongly break on.
    records = [
        json.loads(l) for l in IN_PATH.read_text().split("\n") if l.strip()
    ]

    # Cache old skill bodies + minimal-flags.
    body_cache: dict[str, str | None] = {}
    minimal_cache: dict[str, bool] = {}

    def get_body(skill_dir: str) -> str | None:
        if skill_dir not in body_cache:
            body_cache[skill_dir] = old_skill_body(skill_dir)
        return body_cache[skill_dir]

    def get_minimal(skill: str) -> bool:
        if skill not in minimal_cache:
            minimal_cache[skill] = is_minimal_skill(skill)
        return minimal_cache[skill]

    out_lines: list[str] = []
    stats = {
        "total_in": len(records),
        "usable": 0,
        "roundtrip_ok": 0,
        "roundtrip_total": 0,
        "by_source": {"hardera": 0, "mapped": 0, "planner": 0, "minimal": 0},
        "excluded_null": [],
        "excluded_custom": [],
        "excluded_no_body": [],
        "samples": {},
    }

    for rec in records:
        req = rec.get("request") or {}
        sp = req.get("system_prompt")
        skill = rec["skill"]

        if not sp:
            stats["excluded_null"].append(rec["id"])
            continue

        stats["usable"] += 1

        # custom-* runtime skills have no faithful old mapping.
        if skill.startswith("custom-"):
            stats["excluded_custom"].append(rec["id"])
            continue

        path = classify_path(sp, skill)

        # ---- PLANNER ----
        if path == "planner":
            old_prompt = old_planner_prompt
            # Round-trip: the captured current planner prompt must begin
            # with the current IDENTITY_PREAMBLE then the supervisor body.
            rt = sp.startswith("You are a diagnostic tool.") and "You are the supervisor" in sp
            stats["roundtrip_total"] += 1
            if rt:
                stats["roundtrip_ok"] += 1
            rec["request"]["system_prompt"] = old_prompt
            rec["reconstruction"] = {
                "era_commit": ERA_COMMIT,
                "skill_source": "planner",
                "roundtrip_ok": bool(rt),
                "path": "planner",
            }
            stats["by_source"]["planner"] += 1
            out_lines.append(json.dumps(rec, ensure_ascii=False))
            if "planner" not in stats["samples"]:
                stats["samples"]["planner"] = old_prompt
            continue

        # ---- GENERIC-TASK executor lane (skill == "executor") ----
        # No SKILL.md exists; the body is the per-case generic-executor
        # template (task spliced in) carried inside the captured prompt.
        if skill == "executor":
            body = slice_generic_executor_body(sp)
            if body is None:
                stats["excluded_no_body"].append((rec["id"], "executor(generic)"))
                continue
            hdr = parse_header(sp, skill, req.get("messages") or [])
            header = (
                f"You are a penetration testing agent (ID: {hdr['agent_id']}) "
                f"in the SwarmAttacker swarm.\n"
                f"Methodology: {hdr['methodology']}\n"
                f"Focus area: {hdr['config_name']}\n"
                f"Target: {hdr['target_url']}\n"
            )
            old_prompt = "\n\n".join(
                [header, base_prompt, body, OLD_RAG_HINT, flag_addendum]
            )
            cur_header = (
                f"You are a security testing agent (ID: {hdr['agent_id']}) "
                f"in the SwarmAttacker swarm.\n"
                f"Methodology: {hdr['methodology']}\n"
                f"Focus area: {hdr['config_name']}\n"
                f"Target: {hdr['target_url']}\n"
            )
            rt = sp.startswith(cur_header) and bool(hdr["target_url"])
            stats["roundtrip_total"] += 1
            if rt:
                stats["roundtrip_ok"] += 1
            rec["request"]["system_prompt"] = old_prompt
            rec["reconstruction"] = {
                "era_commit": ERA_COMMIT,
                "skill_source": "hardera",
                "roundtrip_ok": bool(rt),
                "path": "executor",
            }
            stats["by_source"]["hardera"] += 1
            out_lines.append(json.dumps(rec, ensure_ascii=False))
            continue

        # ---- resolve skill source / old body ----
        if skill in SKILL_MAP:
            target_dir = SKILL_MAP[skill]
            skill_source = f"mapped:{target_dir}"
            src_kind = "mapped"
        else:
            target_dir = skill
            skill_source = "hardera"
            src_kind = "hardera"

        # ---- MINIMAL (skip_base_prompt) ----
        minimal = get_minimal(target_dir)
        if minimal:
            body = get_body(target_dir)
            if body is None:
                stats["excluded_no_body"].append((rec["id"], target_dir))
                continue
            old_prompt = "\n\n".join([body, flag_addendum])
            # Round-trip: current minimal prompt == old body verbatim
            # (the only era change is the appended flag addendum).
            rt = sp.strip() == body.strip()
            stats["roundtrip_total"] += 1
            if rt:
                stats["roundtrip_ok"] += 1
            rec["request"]["system_prompt"] = old_prompt
            rec["reconstruction"] = {
                "era_commit": ERA_COMMIT,
                "skill_source": skill_source if src_kind == "mapped" else "minimal",
                "roundtrip_ok": bool(rt),
                "path": "minimal",
            }
            stats["by_source"]["minimal"] += 1
            out_lines.append(json.dumps(rec, ensure_ascii=False))
            if "minimal" not in stats["samples"]:
                stats["samples"]["minimal"] = old_prompt
            continue

        # ---- NON-MINIMAL WORKER (executor / recon) ----
        body = get_body(target_dir)
        if body is None:
            stats["excluded_no_body"].append((rec["id"], target_dir))
            continue

        hdr = parse_header(sp, skill, req.get("messages") or [])
        header = (
            f"You are a penetration testing agent (ID: {hdr['agent_id']}) "
            f"in the SwarmAttacker swarm.\n"
            f"Methodology: {hdr['methodology']}\n"
            f"Focus area: {hdr['config_name']}\n"
            f"Target: {hdr['target_url']}\n"
        )
        old_prompt = "\n\n".join([header, base_prompt, body, OLD_RAG_HINT, flag_addendum])

        # Round-trip on CURRENT data: rebuild the current prompt's header
        # from the parsed fields and assert it matches the captured prefix.
        # This proves the field parse + path classification are correct;
        # the OLD reconstruction reuses the same fields with old constants.
        cur_header = (
            f"You are a security testing agent (ID: {hdr['agent_id']}) "
            f"in the SwarmAttacker swarm.\n"
            f"Methodology: {hdr['methodology']}\n"
            f"Focus area: {hdr['config_name']}\n"
            f"Target: {hdr['target_url']}\n"
        )
        rt = sp.startswith(cur_header) and bool(hdr["target_url"])
        stats["roundtrip_total"] += 1
        if rt:
            stats["roundtrip_ok"] += 1

        rec["request"]["system_prompt"] = old_prompt
        rec["reconstruction"] = {
            "era_commit": ERA_COMMIT,
            "skill_source": skill_source,
            "roundtrip_ok": bool(rt),
            "path": path,
        }
        stats["by_source"]["mapped" if src_kind == "mapped" else "hardera"] += 1
        out_lines.append(json.dumps(rec, ensure_ascii=False))
        if src_kind == "hardera" and "executor" not in stats["samples"]:
            stats["samples"]["executor"] = old_prompt
            stats["samples"]["executor_current"] = sp

    OUT_PATH.write_text("\n".join(out_lines) + "\n", encoding="utf-8")

    # ── Report ──
    print("=" * 70)
    print(f"input records      : {stats['total_in']}")
    print(f"usable (non-null)  : {stats['usable']}")
    print(f"written            : {len(out_lines)}")
    print(
        f"round-trip match   : {stats['roundtrip_ok']}/{stats['roundtrip_total']}"
    )
    print("by skill_source    :")
    for k, v in stats["by_source"].items():
        print(f"   {k:10s}: {v}")
    print(f"excluded null/empty: {len(stats['excluded_null'])} {stats['excluded_null']}")
    print(
        f"excluded custom-*  : {len(stats['excluded_custom'])}"
    )
    for cid in stats["excluded_custom"]:
        print(f"   {cid}")
    print(f"excluded no-body   : {stats['excluded_no_body']}")
    print(f"output file        : {OUT_PATH}")
    print(f"script             : {Path(__file__).resolve()}")

    if "executor" in stats["samples"]:
        print("\n--- SAMPLE: OLD executor reconstruction (first 15 lines) ---")
        for ln in stats["samples"]["executor"].splitlines()[:15]:
            print(ln)
        print("\n--- SAMPLE: CURRENT executor prompt (first 5 lines) ---")
        for ln in stats["samples"]["executor_current"].splitlines()[:5]:
            print(ln)
    if "minimal" in stats["samples"]:
        print("\n--- SAMPLE: OLD minimal reconstruction (last 12 lines) ---")
        for ln in stats["samples"]["minimal"].splitlines()[-12:]:
            print(ln)
    if "planner" in stats["samples"]:
        print("\n--- SAMPLE: OLD planner reconstruction (first 12 lines) ---")
        for ln in stats["samples"]["planner"].splitlines()[:12]:
            print(ln)


if __name__ == "__main__":
    main()
