"""Vendor skill-relevant slices of OWASP WSTG, GTFOBins, and can-i-take-over.

Stage-1 download (like ``download_references.py`` was for HackTricks/PATT), but
for three additional sources, fetching ONLY the parts that map to a skill we
already have — no new direction. Saved to the corpus staging dir for a later
mining pass into the per-skill references/.

  - OWASP WSTG  (github.com/OWASP/wstg) — per-vuln TEST PROCEDURE markdown,
    the methodology layer HackTricks/PATT (payload-heavy) lack. Only the files
    that map to an existing skill are pulled.
  - GTFOBins    (github.com/GTFOBins/GTFOBins.github.io) — the shell / file
    breakout one-liners for common binaries, for the rce skill's restricted
    command-injection case. Raw YAML-frontmatter files for ~50 common binaries.
  - can-i-take-over-xyz (github.com/EdOverflow/can-i-take-over-xyz) — the
    service->fingerprint->vulnerable table, for the subdomain-takeover skill.

Run:  uv run python scripts/download_external_refs.py
Out:  src/tools/web_recon/corpus/{wstg/<skill>/,gtfobins/,can-i-take-over/}
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "tools" / "web_recon" / "corpus"

_WSTG = "https://raw.githubusercontent.com/OWASP/wstg/master/document/4-Web_Application_Security_Testing"
_GTFO = "https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins"
_CITO = "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master"

# WSTG test files → the existing skill they belong to. Only skills we already
# have; only files that add a test procedure for that skill.
WSTG_BY_SKILL: dict[str, list[str]] = {
    "sqli": [
        "07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md",
        "07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection.md",
        "07-Input_Validation_Testing/05.7-Testing_for_ORM_Injection.md",
    ],
    "xss": [
        "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md",
        "07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md",
        "11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting.md",
    ],
    "ssti": ["07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection.md"],
    "ssrf": [
        "07-Input_Validation_Testing/19-Testing_for_Server-Side_Request_Forgery.md",
        "07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection.md",
    ],
    "lfi": [
        "05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include.md",
        "07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion.md",
    ],
    "xxe": ["07-Input_Validation_Testing/07-Testing_for_XML_Injection.md"],
    "rce": [
        "07-Input_Validation_Testing/12-Testing_for_Command_Injection.md",
        "07-Input_Validation_Testing/11-Testing_for_Code_Injection.md",
    ],
    "csrf": ["06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery.md"],
    "idor": ["05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md"],
    "bfla": [
        "12-API_Testing/04-API_Broken_Function_Level_Authorization.md",
        "12-API_Testing/02-API_Broken_Object_Level_Authorization.md",
        "05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema.md",
    ],
    "open-redirect": ["11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect.md"],
    "auth-testing": [
        "04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema.md",
        "06-Session_Management_Testing/10-Testing_JSON_Web_Tokens.md",
        "05-Authorization_Testing/05-Testing_for_OAuth_Weaknesses.md",
        "04-Authentication_Testing/02-Testing_for_Default_Credentials.md",
    ],
    "session-mgmt": [
        "06-Session_Management_Testing/01-Testing_for_Session_Management_Schema.md",
        "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.md",
        "06-Session_Management_Testing/03-Testing_for_Session_Fixation.md",
    ],
    "mass-assignment": ["07-Input_Validation_Testing/20-Testing_for_Mass_Assignment.md"],
    "parameter-pollution": ["07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution.md"],
    "request-smuggling": ["07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling.md"],
    "graphql": ["12-API_Testing/99-Testing_GraphQL.md"],
    "insecure-file-uploads": ["10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files.md"],
    "business-logic": [
        "10-Business_Logic_Testing/01-Test_Business_Logic_Data_Validation.md",
        "10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows.md",
        "10-Business_Logic_Testing/02-Test_Ability_to_Forge_Requests.md",
    ],
    "subdomain-takeover": ["02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover.md"],
    "crypto": ["09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle.md"],
    "error-handling": ["08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling.md"],
    "information-disclosure": [
        "02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information.md",
    ],
}

# GTFOBins binaries realistically present in a web app server/container whose
# shell/reverse-shell/command/file-read/file-write functions matter when
# command injection is restricted to specific binaries. (Files have no ext.)
GTFOBINS = [
    "python", "python2", "python3", "perl", "ruby", "php", "node", "lua",
    "bash", "sh", "awk", "gawk", "busybox", "nc", "ncat", "socat", "tar",
    "zip", "unzip", "gzip", "curl", "wget", "find", "vi", "vim", "nano",
    "less", "more", "man", "env", "nohup", "expect", "tclsh", "gdb",
    "base64", "xxd", "openssl", "sed", "ed", "dd", "cp", "ssh", "scp",
    "git", "make", "sqlite3", "mysql", "java", "jrunscript", "rlwrap",
]


def _save(client: httpx.Client, url: str, dest: Path, manifest: list, group: str, skill: str = "") -> None:
    try:
        r = client.get(url)
        body = r.text if r.status_code == 200 else ""
        ok = bool(body.strip())
        status: object = r.status_code
    except Exception as e:
        body, ok, status = "", False, f"ERR:{type(e).__name__}"
    if ok:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(body, encoding="utf-8")
        manifest.append({
            "group": group, "skill": skill, "url": url,
            "file": str(dest.relative_to(ROOT)), "bytes": len(body),
            "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(), "status": 200,
        })
        print(f"  OK   {group:<14} {skill:<22} {dest.name:<55} {len(body):>7} B")
    else:
        manifest.append({"group": group, "skill": skill, "url": url, "file": None, "status": status})
        print(f"  DEAD {group:<14} {skill:<22} {dest.name:<55} <- {status}")


def main() -> None:
    manifest: list[dict] = []
    fetched_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with httpx.Client(timeout=30.0, follow_redirects=True,
                      headers={"User-Agent": "swarm-references/1.0"}) as c:
        print("== OWASP WSTG ==")
        for skill, files in WSTG_BY_SKILL.items():
            for rel in files:
                name = rel.split("/")[-1]
                _save(c, f"{_WSTG}/{rel}", OUT / "wstg" / skill / name, manifest, "wstg", skill)
        print("== GTFOBins (rce) ==")
        for b in GTFOBINS:
            _save(c, f"{_GTFO}/{b}", OUT / "gtfobins" / f"{b}.md", manifest, "gtfobins", "rce")
        print("== can-i-take-over (subdomain-takeover) ==")
        _save(c, f"{_CITO}/fingerprints.json", OUT / "can-i-take-over" / "fingerprints.json",
              manifest, "can-i-take-over", "subdomain-takeover")
        _save(c, f"{_CITO}/README.md", OUT / "can-i-take-over" / "README.md",
              manifest, "can-i-take-over", "subdomain-takeover")

    (OUT / "SOURCES_external.json").write_text(
        json.dumps({"fetched_at": fetched_at, "sources": manifest}, indent=2), encoding="utf-8")
    ok = [m for m in manifest if m["status"] == 200]
    dead = [m for m in manifest if m["status"] != 200]
    kb = sum(m.get("bytes", 0) for m in ok) // 1024
    print(f"\nDone: {len(ok)}/{len(manifest)} fetched ({kb} KB) → {OUT.relative_to(ROOT)}/{{wstg,gtfobins,can-i-take-over}}")
    if dead:
        print(f"⚠ {len(dead)} dead:")
        for m in dead:
            print(f"  [{m['status']}] {m['group']}/{m['skill']}: {m['url']}")


if __name__ == "__main__":
    main()
