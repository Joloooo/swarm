"""Typed hydra wrapper for HTTP form brute-forcing."""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from src.tools.shell import bash_exec


_DEFAULT_TIMEOUT = 600

# Tiny built-in lists for first-pass tests. The agent should escalate to
# real wordlists on the host (rockyou, seclists) only after a small probe
# confirms the form is brute-forceable at all.
_USERLIST_PRESETS = {
    "common": "/usr/share/wordlists/metasploit/http_default_users.txt",
    "tiny": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
}
_PASSLIST_PRESETS = {
    "common": "/usr/share/wordlists/metasploit/http_default_pass.txt",
    "tiny": "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "rockyou": "/usr/share/wordlists/rockyou.txt",
}


@tool
async def hydra_http_form(
    reasoning: str,
    host: str,
    path: str,
    form_spec: str,
    userlist: str = "tiny",
    passlist: str = "tiny",
    port: int = 80,
    https: bool = False,
    threads: int = 8,
    agent_id: str = "default",
) -> str:
    """Brute-force an HTTP login form with hydra.

    Hydra's ``http-post-form`` / ``https-post-form`` modules need a
    three-part ``form_spec`` describing the form fields and the failure
    condition: ``"path:user_field=^USER^&pass_field=^PASS^:F=Invalid"``
    where ``F=Invalid`` is a string in the response body that proves a
    failed login.

    Use a TINY userlist + passlist by default. Only escalate to real
    wordlists once a small probe confirms the form actually responds
    differently between success and failure.

    Args:
        reasoning: Required. Reference the prior recon finding (login
            form discovered, default-creds attempted, etc.) and the
            failure-string evidence behind your form_spec.
        host: Target host or IP (no scheme).
        path: Path to the form, e.g. ``/login``.
        form_spec: hydra form spec string (see module docstring).
        userlist: ``tiny`` / ``common`` preset, or absolute path.
        passlist: ``tiny`` / ``common`` / ``rockyou`` preset, or path.
        port: Server port (default 80, set 443 with ``https=True``).
        https: True for https-post-form, False for http-post-form.
        threads: Parallel attempts (default 8 — keep this low; high
            concurrency triggers rate limits and false negatives).
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        hydra stdout. Successful guesses appear as ``[<port>][http*-post-form]
        host: ... login: ... password: ...`` lines.
    """
    user_path = _USERLIST_PRESETS.get(userlist, userlist)
    pass_path = _PASSLIST_PRESETS.get(passlist, passlist)
    module = "https-post-form" if https else "http-post-form"

    # The form_spec already embeds the path as its first segment. Rebuild
    # it so we can apply the path the LLM passed (most common mistake is
    # passing form_spec WITHOUT a leading path).
    if not form_spec.startswith(path):
        form_spec = f"{path}:{form_spec}"

    cmd = (
        f"hydra -L {shlex.quote(user_path)} -P {shlex.quote(pass_path)} "
        f"-t {int(threads)} -f -s {int(port)} "
        f"{shlex.quote(host)} {module} {shlex.quote(form_spec)}"
    )
    return await bash_exec(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
