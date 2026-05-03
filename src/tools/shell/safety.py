"""Pre-flight safety checks for the shell tools (bash + tmux).

Three pure functions, no I/O, no LLM. Both ``bash`` and ``run_command``
call them before sending anything into a shell. The threat model here
is **the agent's own host**, not the target — the target is what the
agent is *supposed* to attack. So the checks fall into two categories:

1. **Attacker-host safety** — block writes to paths on this machine
   that the agent has no business touching (``~/.ssh``, ``~/.aws``,
   the project's own ``logs/``, ``.venv/``, ``/etc``).
   This is the equivalent of Claude Code's path hard-blocks, scoped to
   what makes sense for SwarmAttacker.

2. **Scope / rules-of-engagement** — extract the *target* argument
   from a recognised pentest binary (nmap, curl, sqlmap, ...) and
   verify it falls inside the configured engagement scope. Stops the
   agent from accidentally scanning out-of-scope hosts, which is a
   real legal hole.

A third helper, ``strip_wrappers``, peels off command wrappers like
``timeout``, ``sudo``, ``proxychains``, and ``stdbuf`` so the scope
extractor sees the actual binary the user is running.

These functions never raise. They return either ``None`` / ``True``
("allowed") or an error string the tool surfaces back to the LLM.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import shlex
import socket
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# -- Wrapper stripping -------------------------------------------------------
#
# Pentesters routinely chain wrappers in front of the actual command:
#
#     proxychains sudo timeout 600 nmap -sV target
#
# A naive "first word" check sees "proxychains" and either allows
# everything or blocks everything — neither is correct. We peel off
# wrappers per the table below until we hit the real binary.
#
# Each rule says how many tokens to consume after the wrapper:
#   "none"            — just the wrapper token itself (e.g. proxychains)
#   "consume_one"     — wrapper + 1 fixed argument (e.g. timeout 30 X)
#   "consume_one_int" — wrapper + 1 integer argument (e.g. nice -n 10 X)
#                       and any flag-style switches before the integer
#   "dash_flags"      — wrapper + any tokens that start with '-'
#                       and any space-separated values for those flags
#                       (covers sudo's many flags, stdbuf -oN -eN, etc.)
#   "assignments"     — wrapper + any tokens containing '=' (env A=1 B=2 X)

_WRAPPERS: dict[str, str] = {
    "timeout":      "consume_one",
    "stdbuf":       "dash_flags",
    "nice":         "dash_flags",
    "ionice":       "dash_flags",
    "taskset":      "dash_flags",
    "sudo":         "dash_flags",
    "doas":         "dash_flags",
    "env":          "assignments",
    "proxychains":  "none",
    "proxychains4": "none",
    "torsocks":     "none",
    "unbuffer":     "none",
    "script":       "dash_flags",
}


def strip_wrappers(argv: list[str]) -> list[str]:
    """Skip past wrappers (``timeout``, ``sudo``, ``proxychains``, ...) to the real command.

    Returns argv with all leading wrappers peeled off. If only wrappers
    are present (no real command after them), returns ``[]``.

    Examples
    --------
    >>> strip_wrappers(["proxychains", "sudo", "timeout", "30", "nmap", "-sV", "x"])
    ['nmap', '-sV', 'x']
    >>> strip_wrappers(["env", "A=1", "B=2", "curl", "https://x"])
    ['curl', 'https://x']
    >>> strip_wrappers(["timeout", "30"])
    []
    """
    i = 0
    while i < len(argv):
        head = argv[i]
        rule = _WRAPPERS.get(head)
        if rule is None:
            return argv[i:]

        if rule == "none":
            i += 1
            continue

        if rule == "consume_one":
            # timeout 30 X  →  drop "timeout" and "30"
            i += 2
            continue

        if rule == "dash_flags":
            # sudo -E -u user X  →  drop "sudo" and "-E" and "-u" and "user"
            # Heuristic: skip the wrapper, then skip any token starting with '-',
            # plus the very next token if the flag looks like one that takes
            # a value (length 2, e.g. -u, -n, -o without '=').
            i += 1
            while i < len(argv):
                tok = argv[i]
                if not tok.startswith("-"):
                    break
                # Bare-value flag like '-n 10' or '-u user' — also eat the value.
                takes_value = (
                    len(tok) == 2  # short flag without '='
                    and "=" not in tok
                    and i + 1 < len(argv)
                    and not argv[i + 1].startswith("-")
                )
                i += 2 if takes_value else 1
            continue

        if rule == "assignments":
            # env A=1 B=2 X  →  drop "env" and any "K=V" tokens
            i += 1
            while i < len(argv) and "=" in argv[i] and not argv[i].startswith("-"):
                i += 1
            continue

        # Unknown rule — be safe, return what we have.
        return argv[i:]

    return []


# -- Attacker-host safety ----------------------------------------------------

# Paths on the *attacker's own machine* that the agent must never write to.
# Reading is fine — pentest agents legitimately read /etc/passwd if they've
# popped a target shell that mounts it, etc. — but writing to these on the
# attacker box is almost always either a bug or a misbehaving model.
_FORBIDDEN_WRITE_PREFIXES: list[Path] = [
    Path.home() / ".ssh",
    Path.home() / ".aws",
    Path.home() / ".gnupg",
    Path.home() / ".config" / "swarmattacker",
    Path.home() / ".claude",
    Path("/etc"),
    Path("/boot"),
    Path("/System"),  # macOS
]

# Project paths we also protect when running from inside the SwarmAttacker
# checkout. Resolved lazily so tests can override CWD.
_PROJECT_PROTECTED_DIRS = (".venv", ".git")

# Commands that write to a path argument. Maps command name → which
# positional argument (1-indexed) is the destination, or "redirect_only"
# if writes only happen via shell redirects (``>``, ``>>``, ``tee``).
_WRITE_COMMANDS: dict[str, str] = {
    "cp":     "last",     # cp src... dst
    "mv":     "last",
    "rm":     "all",      # any path arg is destructive
    "rmdir":  "all",
    "chmod":  "all_after_mode",
    "chown":  "all_after_owner",
    "tee":    "all",
    "dd":     "of_kwarg",
    "ln":     "last",
    "install": "last",
}


def _path_under(candidate: Path, parent: Path) -> bool:
    """True if *candidate* is *parent* itself or a descendant of it."""
    try:
        candidate = candidate.expanduser().resolve(strict=False)
        parent = parent.expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    if candidate == parent:
        return True
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_forbidden_write_target(path_str: str) -> str | None:
    """Return the name of the matched forbidden prefix if *path_str* is forbidden, else None."""
    if not path_str:
        return None
    p = Path(path_str)
    for prefix in _FORBIDDEN_WRITE_PREFIXES:
        if _path_under(p, prefix):
            return str(prefix)

    # Project-relative protection: only triggers if the agent tries to
    # write into a path that, resolved against the current working
    # directory, lands inside one of the protected subdirs.
    cwd = Path.cwd()
    for sub in _PROJECT_PROTECTED_DIRS:
        if _path_under(p, cwd / sub):
            return str(cwd / sub)
    return None


def check_attacker_host_safety(command: str) -> str | None:
    """Return a block reason if *command* writes to a forbidden host path, else None.

    Heuristic only — meant to catch obvious accidents (``echo x >
    ~/.ssh/authorized_keys``, ``rm -rf .venv``), not adversarial
    obfuscation. The real defence against a malicious model is running
    the agent inside a disposable VM/container; this function is the
    pre-flight sanity net.
    """
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        # Unbalanced quotes — let the shell complain about it. Don't block.
        return None

    if not argv:
        return None

    # 1) Shell redirects: look for `> path`, `>> path`, regardless of binary.
    for i, tok in enumerate(argv[:-1]):
        if tok in (">", ">>", "1>", "1>>", "2>", "2>>", "&>", "&>>"):
            target = argv[i + 1]
            hit = _is_forbidden_write_target(target)
            if hit:
                return (
                    f"BLOCKED: write to forbidden attacker-host path "
                    f"{target!r} (under {hit!r})"
                )

    # 2) Recognised write commands — check their destination args.
    real = strip_wrappers(argv)
    if not real:
        return None

    cmd = real[0]
    rule = _WRITE_COMMANDS.get(cmd)
    if rule is None:
        return None

    args = real[1:]
    targets: list[str] = []

    if rule == "all":
        # rm/rmdir/tee — any non-flag arg is a target.
        targets = [a for a in args if not a.startswith("-")]
    elif rule == "last":
        # cp/mv/ln/install — the LAST non-flag arg is the destination.
        non_flag = [a for a in args if not a.startswith("-")]
        if non_flag:
            targets = non_flag[-1:]
    elif rule == "all_after_mode":
        # chmod 644 path1 path2 — skip the first non-flag arg (mode).
        non_flag = [a for a in args if not a.startswith("-")]
        targets = non_flag[1:] if len(non_flag) > 1 else []
    elif rule == "all_after_owner":
        non_flag = [a for a in args if not a.startswith("-")]
        targets = non_flag[1:] if len(non_flag) > 1 else []
    elif rule == "of_kwarg":
        # dd of=/path — only this form writes.
        for a in args:
            if a.startswith("of="):
                targets.append(a[3:])

    for t in targets:
        hit = _is_forbidden_write_target(t)
        if hit:
            return (
                f"BLOCKED: {cmd} would write to forbidden attacker-host path "
                f"{t!r} (under {hit!r})"
            )

    return None


# -- Scope / rules-of-engagement enforcement --------------------------------

# Extractors per binary. Each returns the URL-or-host string it finds,
# or None if it can't parse the args. Unknown binaries fall through to
# "allow with warning".
_TARGET_EXTRACTORS: dict[str, str] = {
    # tool name      → extractor strategy id
    "nmap":          "last_positional",
    "masscan":       "last_positional",
    "naabu":         "last_positional",
    "rustscan":      "flag_value",         # -a / --addresses
    "curl":          "first_url",
    "wget":          "first_url",
    "httpie":        "first_url",
    "http":          "first_url",          # httpie alias
    "xh":            "first_url",
    "sqlmap":        "url_flag",           # -u / --url
    "nikto":         "host_flag",          # -h / -host
    "gobuster":      "url_flag",
    "feroxbuster":   "url_flag",
    "ffuf":          "url_flag",
    "wfuzz":         "url_flag",
    "wpscan":        "url_flag",
    "dirb":          "first_positional",
    "dirbuster":     "first_url",
    "hydra":         "last_positional",
    "medusa":        "host_flag_h",
    "dig":           "first_positional",
    "host":          "first_positional",
    "nslookup":      "first_positional",
    "whois":         "first_positional",
    "dnsrecon":      "domain_flag",
    "amass":         "domain_flag",
    "subfinder":     "domain_flag",
    "ping":          "last_positional",
    "traceroute":    "last_positional",
}


def _extract_target(real_argv: list[str]) -> str | None:
    """Pull the target URL/host from a stripped argv. None if not recognised."""
    if not real_argv:
        return None
    cmd = real_argv[0]
    args = real_argv[1:]
    strategy = _TARGET_EXTRACTORS.get(cmd)
    if strategy is None:
        return None

    def _flag_value(flags: tuple[str, ...]) -> str | None:
        for i, a in enumerate(args):
            if a in flags and i + 1 < len(args):
                return args[i + 1]
            for f in flags:
                if a.startswith(f + "="):
                    return a[len(f) + 1:]
        return None

    if strategy == "last_positional":
        non_flag = [a for a in args if not a.startswith("-")]
        return non_flag[-1] if non_flag else None
    if strategy == "first_positional":
        non_flag = [a for a in args if not a.startswith("-")]
        return non_flag[0] if non_flag else None
    if strategy == "first_url":
        for a in args:
            if a.startswith(("http://", "https://", "ftp://")):
                return a
        # Some tools accept a bare host as positional (curl example.com).
        non_flag = [a for a in args if not a.startswith("-")]
        return non_flag[0] if non_flag else None
    if strategy == "url_flag":
        return _flag_value(("-u", "--url"))
    if strategy == "host_flag":
        return _flag_value(("-h", "-host", "--host"))
    if strategy == "host_flag_h":
        return _flag_value(("-h",))
    if strategy == "domain_flag":
        return _flag_value(("-d", "--domain"))
    if strategy == "flag_value":
        return _flag_value(("-a", "--addresses"))
    return None


def _host_from_target(target: str) -> str | None:
    """Strip URL scheme, port, path; return bare host."""
    if not target:
        return None
    if "://" in target:
        try:
            return urlparse(target).hostname
        except Exception:
            return None
    # bare host[:port][/path]
    host = target.split("/", 1)[0]
    host = host.split(":", 1)[0]
    return host or None


def _host_in_scope(host: str, scope: list[str]) -> bool:
    """True if *host* matches any scope entry.

    Scope entries can be:
    - exact hostnames: ``example.com``
    - wildcard subdomains: ``*.example.com``
    - CIDR blocks: ``10.0.0.0/24``, ``192.168.1.5/32``
    - bare IPs: ``10.0.0.5``
    """
    if not scope:
        # No scope configured = no enforcement (research/sandbox use).
        return True

    # Try IP comparison first.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is None:
        # If the host is a hostname, also resolve once for IP-rule matching.
        try:
            resolved = socket.gethostbyname(host)
            try:
                ip = ipaddress.ip_address(resolved)
            except ValueError:
                ip = None
        except OSError:
            ip = None

    for entry in scope:
        entry = entry.strip()
        if not entry:
            continue

        # CIDR or single-IP rule.
        try:
            net = ipaddress.ip_network(entry, strict=False)
            if ip is not None and ip in net:
                return True
            continue
        except ValueError:
            pass

        # Hostname rule (exact or wildcard).
        if entry.startswith("*."):
            suffix = entry[1:]  # ".example.com"
            if host == entry[2:] or host.endswith(suffix):
                return True
        elif host == entry:
            return True

    return False


def check_scope(command: str, scope: list[str]) -> str | None:
    """Return a block reason if *command* targets out-of-scope hosts, else None.

    If ``scope`` is empty, scope enforcement is disabled (returns None).
    If the binary isn't one of the recognised pentest tools, returns
    None — we don't block what we don't understand. Such cases are
    logged by the caller as ``scope_unknown`` so the operator notices.
    """
    if not scope:
        return None
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return None
    if not argv:
        return None

    real = strip_wrappers(argv)
    target = _extract_target(real)
    if target is None:
        # Unknown extractor — let it through, caller may log.
        return None

    host = _host_from_target(target)
    if host is None:
        return None

    if _host_in_scope(host, scope):
        return None

    return (
        f"BLOCKED: target {host!r} (from arg {target!r}) is not in the "
        f"engagement scope {scope!r}. If this is intentional, update the "
        f"scope or run with --allow-out-of-scope."
    )


# Convenience exposed for the JSONL log so the caller can attribute a
# rejection to "scope" vs "host_safety" without re-running the checks.
def classify_command(command: str) -> dict[str, str | None]:
    """Diagnostic helper — returns extracted command/target metadata."""
    try:
        argv = shlex.split(command, posix=True)
    except ValueError:
        return {"binary": None, "target": None, "host": None}
    real = strip_wrappers(argv)
    binary = real[0] if real else None
    target = _extract_target(real) if real else None
    host = _host_from_target(target) if target else None
    return {"binary": binary, "target": target, "host": host}


__all__ = [
    "strip_wrappers",
    "check_attacker_host_safety",
    "check_scope",
    "classify_command",
]


if __name__ == "__main__":
    # Inline smoke checks — `python -m src.tools.shell.safety`.
    assert strip_wrappers(["proxychains", "sudo", "timeout", "30", "nmap", "x"]) == ["nmap", "x"]
    assert strip_wrappers(["env", "A=1", "B=2", "curl", "https://x"]) == ["curl", "https://x"]
    assert strip_wrappers(["timeout", "30"]) == []
    assert strip_wrappers(["nmap", "-sV", "10.0.0.5"]) == ["nmap", "-sV", "10.0.0.5"]
    assert check_attacker_host_safety("echo hi > ~/.ssh/authorized_keys") is not None
    assert check_attacker_host_safety("nmap 10.0.0.5") is None
    assert check_scope("nmap 10.0.0.5", ["10.0.0.0/24"]) is None
    assert check_scope("nmap 8.8.8.8", ["10.0.0.0/24"]) is not None
    assert check_scope("curl https://example.com", ["*.example.com"]) is None
    assert check_scope("nmap target.com", []) is None  # empty scope = no enforcement
    print("safety.py: all inline smoke checks passed")
