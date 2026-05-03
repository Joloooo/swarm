"""Tier 3 — verifies the tmux shell tool drives an interactive SSH session correctly.

This is the regression test for the dual-sentinel marker fix in
``src/tools/shell/tmux.py`` (see ``tests/FAILURES.md`` 2026-05-02).
Before the fix, ``_run_in_pane`` returned ``""`` for any command
that didn't finish printing output before the next ``capture-pane``
poll — including the SSH banner — because its substring marker check
fired on the typed ``echo MARKER`` line instead of waiting for the
shell to actually run it. The dual-sentinel scheme + bare-line regex
match (``^MARKER$``) un-races the check; this test pins that
behaviour by asking SwarmAttacker to read a known file across a
real SSH session and asserting the body comes back.

The flow:
1. Clean any leftover tmux session from a prior run.
2. ``shell()`` types ``ssh jolocorpagent`` into a tmux pane. Returns
   only once the bare-line end marker comes back from the *remote*
   shell — i.e. we know we are at a remote prompt.
3. ``shell()`` again types ``cat jolotest`` into the live SSH
   session. Returns once the remote bash prints the file body and
   the bare-line end marker.
4. Asserts ``"i like dancing"`` appears in the captured output.
5. Cleanly exits SSH and tears down tmux.

Marked ``@pytest.mark.tools`` (skipped by default). Run with::

    uv run pytest -m tools tests/tools/test_tmux_ssh.py -v

Skips automatically if tmux/ssh are missing or if passwordless SSH
to ``jolocorpagent`` does not work.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from src.tools.shell.tmux import cleanup_session, shell


SSH_HOST = "jolocorpagent"
EXPECTED_CONTENTS = "i like dancing"
AGENT_ID = "test-tmux-ssh"


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _ssh_passwordless_ok() -> bool:
    """Verify we can reach SSH_HOST non-interactively. ``BatchMode=yes``
    disables every prompt path (password, passphrase, host-key
    confirmation), so this only succeeds if a working agent / key is
    already in place."""
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
             SSH_HOST, "true"],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


# Mark the entire module as tier-3 and skip cleanly if any dependency
# is missing. Conditions are evaluated when the module is collected,
# but pyproject.toml's ``addopts = "-m 'not tools and not live'"``
# means collection is only attempted when the user explicitly opts in
# with ``-m tools``, so the SSH probe doesn't run on every pytest call.
pytestmark = [
    pytest.mark.tools,
    pytest.mark.skipif(not _have("tmux"), reason="tmux not installed"),
    pytest.mark.skipif(not _have("ssh"), reason="ssh not installed"),
    pytest.mark.skipif(
        not _ssh_passwordless_ok(),
        reason=f"{SSH_HOST} not reachable via passwordless SSH",
    ),
]


@pytest.fixture
def clean_tmux():
    """Wipe any stale session before AND after the test, so leftover
    panes from a previous run can't poison this one and vice versa."""
    cleanup_session()
    yield
    cleanup_session()


async def test_tmux_can_open_ssh_and_read_remote_file(clean_tmux):
    """Open SSH in a tmux pane, ``cat jolotest`` over it, get the body back.

    The two ``shell()`` calls represent two separate agent tool calls:
    the agent connects, then later runs commands in the live session.
    If the second call captures the file contents correctly, the tmux
    tool is working as intended for interactive sessions.
    """
    # Step 1 — open the SSH session. The marker echo runs on the
    # *remote* shell once auth completes, so a non-timeout return
    # implies we are past the SSH banner and at a remote prompt.
    connect_output = await shell(
        f"ssh -o BatchMode=yes -o ConnectTimeout=5 {SSH_HOST}",
        agent_id=AGENT_ID,
        reasoning="open interactive SSH session in a tmux pane",
        timeout=20,
    )
    assert not connect_output.startswith("[TIMEOUT"), (
        "SSH connect timed out before the marker came back. This usually "
        "means auth fell back to a password prompt, or the remote shell "
        "did not start. Pane tail:\n" + connect_output[-1000:]
    )

    # Step 2 — read the remote file. The string we type goes into the
    # local pane TTY, which SSH (now the foreground process) forwards
    # to the remote bash. The remote bash's output then comes back
    # through the same pane and is captured by ``shell()``.
    cat_output = await shell(
        "cat jolotest",
        agent_id=AGENT_ID,
        reasoning="read the test file across the live SSH session",
        timeout=10,
    )
    assert EXPECTED_CONTENTS in cat_output, (
        f"Did not see {EXPECTED_CONTENTS!r} in the cat output. "
        f"Either tmux capture is broken for SSH-relayed output, the "
        f"file content has changed, or the file is missing on the "
        f"remote host. Got:\n{cat_output!r}"
    )

    # Step 3 — leave the SSH session cleanly so cleanup_session()
    # does not have to kill an in-flight ssh process.
    await shell(
        "exit",
        agent_id=AGENT_ID,
        reasoning="close the remote shell before pane teardown",
        timeout=10,
    )
