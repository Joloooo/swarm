"""Typed sqlmap tool wrappers.

The agent today fires sqlmap by constructing the command line itself.
These typed wrappers replace that pattern: the LLM picks the right
action, the wrapper builds a quoted command line with safe defaults,
and the bash backend runs it. Same plumbing as the ``bash`` LLM-facing
tool (see ``src/tools/shell/bash.py``) but returns raw stdout for
forwarding back to the agent.
"""

from __future__ import annotations

import shlex

from langchain_core.tools import tool

from src.tools.shell import bash_exec


# sqlmap can take 5–10 minutes on a real target. Keep a generous default;
# the typed tools narrow it where they can.
_DEFAULT_TIMEOUT = 600


def _build_data_arg(data: str | None) -> str:
    if not data:
        return ""
    return f" --data={shlex.quote(data)}"


def _build_cookie_arg(cookie: str | None) -> str:
    if not cookie:
        return ""
    return f" --cookie={shlex.quote(cookie)}"


@tool
async def sqlmap_basic(
    reasoning: str,
    url: str,
    data: str | None = None,
    cookie: str | None = None,
    level: int = 2,
    risk: int = 2,
    agent_id: str = "default",
) -> str:
    """Run a basic sqlmap probe against a target URL.

    Default first-pass for confirming SQL injection on a parameterized
    URL or POST form. Runs ``--batch`` so sqlmap never prompts.

    Args:
        reasoning: Required. One to two sentences naming the parameter
            you suspect is injectable and what evidence (error message,
            timing, response diff) led you here.
        url: Full URL with parameters, e.g. ``http://target/page?id=1``.
        data: Optional POST body (e.g. ``user=test&pass=test``). When set,
            sqlmap probes the POST parameters instead of the query string.
        cookie: Optional ``Cookie:`` header value, used when the injection
            point sits behind a session.
        level: sqlmap test level 1–5. 2 covers cookies + UA; 3+ adds more
            payloads at the cost of runtime.
        risk: sqlmap risk 1–3. 2 enables most heavy payloads without
            time-based blind tests that take minutes per parameter.
        agent_id: tmux pane identifier (do not set manually).

    Returns:
        sqlmap stdout (head + tail, truncated for very long runs).
    """
    cmd = (
        f"sqlmap -u {shlex.quote(url)} --batch "
        f"--level {int(level)} --risk {int(risk)}"
        f"{_build_data_arg(data)}{_build_cookie_arg(cookie)}"
    )
    return await bash_exec(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )


@tool
async def sqlmap_enum_dbs(
    reasoning: str,
    url: str,
    data: str | None = None,
    cookie: str | None = None,
    agent_id: str = "default",
) -> str:
    """Enumerate databases on a confirmed-injectable target.

    Use this only after ``sqlmap_basic`` has confirmed the parameter is
    injectable. sqlmap caches the previous probe so the second call is
    much faster than the first.

    Args:
        reasoning: Required. Reference the prior sqlmap_basic finding
            ("sqlmap_basic confirmed injection on id param via boolean
            blind, enumerating to map the schema").
        url: Same URL that sqlmap_basic was called with.
        data: Same POST body if used previously.
        cookie: Same cookie if used previously.
        agent_id: tmux pane identifier.

    Returns:
        sqlmap output listing DBMS-detected databases.
    """
    cmd = (
        f"sqlmap -u {shlex.quote(url)} --batch --dbs"
        f"{_build_data_arg(data)}{_build_cookie_arg(cookie)}"
    )
    return await bash_exec(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )


@tool
async def sqlmap_dump_table(
    reasoning: str,
    url: str,
    db: str,
    table: str,
    data: str | None = None,
    cookie: str | None = None,
    agent_id: str = "default",
) -> str:
    """Dump a specific table from a confirmed-injectable target.

    Pulls the rows of one table. For PoC purposes a single representative
    row is usually enough — call once and stop, don't dump huge tables.

    Args:
        reasoning: Required. Why this specific table — what evidence
            does dumping it provide that earlier steps didn't?
        url: Same URL used for sqlmap_basic / sqlmap_enum_dbs.
        db: Database name returned from sqlmap_enum_dbs.
        table: Table name (e.g. "users").
        data: Same POST body if used previously.
        cookie: Same cookie if used previously.
        agent_id: tmux pane identifier.

    Returns:
        sqlmap dump output.
    """
    cmd = (
        f"sqlmap -u {shlex.quote(url)} --batch "
        f"-D {shlex.quote(db)} -T {shlex.quote(table)} --dump"
        f"{_build_data_arg(data)}{_build_cookie_arg(cookie)}"
    )
    return await bash_exec(
        cmd, agent_id=agent_id, reasoning=reasoning, timeout=_DEFAULT_TIMEOUT
    )
