"""Non-blocking terminal input for live operator guidance.

The graph cannot accept a second input while one ``astream`` invocation is
running. This module therefore only captures text. ``oneshot`` drains the
queue at a durable graph barrier, appends real ``HumanMessage`` objects, and
restarts the graph at ``START -> planner`` from the preserved state.

Unix terminals are put in cbreak/no-echo mode so typed guidance can be drawn
as part of the live renderer instead of colliding with streamed model output.
The original terminal settings and event-loop reader are always restored.
"""

from __future__ import annotations

import asyncio
import codecs
from collections import deque
import os
import subprocess
import sys
from typing import Deque


_BRACKETED_PASTE_START = "\x1b[200~"
_BRACKETED_PASTE_END = "\x1b[201~"
# Modified-Enter encodings used by terminals implementing the Kitty keyboard
# protocol, xterm modifyOtherKeys, or a conventional Meta/Option mapping.
# Ctrl-J is handled separately as a plain LF and is the universal fallback.
_MULTILINE_KEY_SEQUENCES = (
    "\x1b[13;2u",       # Shift-Enter (Kitty keyboard protocol)
    "\x1b[13;3u",       # Option/Alt-Enter (Kitty keyboard protocol)
    "\x1b[27;2;13~",    # Shift-Enter (xterm modifyOtherKeys)
    "\x1b[27;3;13~",    # Option/Alt-Enter (xterm modifyOtherKeys)
    "\x1b\r",           # Option/Alt-Enter (legacy Meta encoding)
    "\x1b\n",
)


class LiveOperatorInput:
    """Capture editable multiline guidance without blocking the graph."""

    def __init__(
        self,
        *,
        run_id: str,
        placeholder: str = "Type guidance for the planner, then press Enter",
        hint: str = (
            "Enter send · Shift/Option-Enter or Ctrl-J newline · Ctrl-C pause"
        ),
        allow_empty: bool = False,
        announce_submissions: bool = True,
        log_submissions: bool = True,
    ) -> None:
        self.run_id = run_id
        self.placeholder = placeholder
        self.hint = hint
        self.allow_empty = allow_empty
        self.announce_submissions = announce_submissions
        self.log_submissions = log_submissions
        self._loop: asyncio.AbstractEventLoop | None = None
        self._fd: int | None = None
        self._original_termios: list | None = None
        self._buffer = ""
        self._pending: Deque[str] = deque()
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._stream_buffer = ""
        self._paste_mode = False
        self._submission_event = asyncio.Event()
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def start(self) -> bool:
        """Register stdin with the running asyncio loop when it is a TTY."""
        fd: int | None = None
        original: list | None = None
        bracketed_paste_enabled = False
        try:
            if not sys.stdin.isatty():
                return False
            import termios
            import tty

            loop = asyncio.get_running_loop()
            fd = sys.stdin.fileno()
            original = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            # Keep Enter (CR) distinct from Ctrl-J (LF).  ``setcbreak``
            # normally leaves ICRNL enabled, which maps both keys to LF and
            # makes a portable multiline shortcut impossible to detect.
            cbreak = termios.tcgetattr(fd)
            cbreak[0] &= ~termios.ICRNL
            termios.tcsetattr(fd, termios.TCSANOW, cbreak)
            loop.add_reader(fd, self._read_ready)
            # Ask compatible terminals to mark a paste as one bracketed block.
            # This prevents embedded newlines from acting like Enter presses.
            sys.stderr.write("\x1b[?2004h")
            sys.stderr.flush()
            bracketed_paste_enabled = True
        except (AttributeError, ImportError, OSError, RuntimeError, ValueError):
            # ``setcbreak`` can succeed before ``add_reader`` fails (for
            # example on an unsupported event loop). Never strand the user's
            # terminal in no-echo mode on that partial setup path.
            if fd is not None and original is not None:
                try:
                    import termios

                    termios.tcsetattr(fd, termios.TCSADRAIN, original)
                except (ImportError, OSError, ValueError):
                    pass
            if bracketed_paste_enabled:
                try:
                    sys.stderr.write("\x1b[?2004l")
                    sys.stderr.flush()
                except (OSError, ValueError):
                    pass
            return False

        self._loop = loop
        self._fd = fd
        self._original_termios = original
        self._active = True
        from src.observability.live import LIVE

        LIVE.operator_input_start(placeholder=self.placeholder, hint=self.hint)
        return True

    def stop(self) -> None:
        """Restore normal terminal behavior and detach the stdin reader."""
        if not self._active:
            return
        self._active = False
        if self._loop is not None and self._fd is not None:
            try:
                self._loop.remove_reader(self._fd)
            except (OSError, RuntimeError, ValueError):
                pass
        if self._fd is not None and self._original_termios is not None:
            try:
                import termios

                termios.tcsetattr(
                    self._fd,
                    termios.TCSADRAIN,
                    self._original_termios,
                )
            except (ImportError, OSError, ValueError):
                pass
        try:
            sys.stderr.write("\x1b[?2004l")
            sys.stderr.flush()
        except (OSError, ValueError):
            pass
        from src.observability.live import LIVE

        LIVE.operator_input_stop()

    def drain(self) -> list[str]:
        """Return all submitted guidance in arrival order."""
        items = list(self._pending)
        self._pending.clear()
        self._submission_event.clear()
        return items

    async def next_submission(self) -> str:
        """Wait for and return the next submitted message."""
        while not self._pending:
            await self._submission_event.wait()
            if not self._pending:
                self._submission_event.clear()
        item = self._pending.popleft()
        if not self._pending:
            self._submission_event.clear()
        return item

    def applied(self, count: int) -> None:
        from src.observability.live import LIVE

        LIVE.operator_input_applied(count, queued=len(self._pending))

    def _read_ready(self) -> None:
        if self._fd is None:
            return
        try:
            raw = os.read(self._fd, 4096)
        except (BlockingIOError, OSError):
            return
        if not raw:
            self.stop()
            return
        self._consume_text(self._decoder.decode(raw))

    def _consume_text(self, text: str) -> None:
        """Parse ordinary keys and terminal bracketed-paste sequences."""
        self._stream_buffer += text
        while self._stream_buffer:
            if self._paste_mode:
                end = self._stream_buffer.find(_BRACKETED_PASTE_END)
                if end >= 0:
                    self._insert_paste(self._stream_buffer[:end])
                    self._stream_buffer = self._stream_buffer[
                        end + len(_BRACKETED_PASTE_END):
                    ]
                    self._paste_mode = False
                    continue
                keep = _possible_marker_suffix(
                    self._stream_buffer, _BRACKETED_PASTE_END
                )
                if len(self._stream_buffer) > keep:
                    self._insert_paste(
                        self._stream_buffer[: len(self._stream_buffer) - keep]
                    )
                    self._stream_buffer = self._stream_buffer[-keep:] if keep else ""
                return

            if self._stream_buffer.startswith(_BRACKETED_PASTE_START):
                self._stream_buffer = self._stream_buffer[len(_BRACKETED_PASTE_START):]
                self._paste_mode = True
                continue

            newline_sequence = next(
                (
                    sequence
                    for sequence in _MULTILINE_KEY_SEQUENCES
                    if self._stream_buffer.startswith(sequence)
                ),
                None,
            )
            if newline_sequence is not None:
                self._stream_buffer = self._stream_buffer[len(newline_sequence):]
                self._insert_newline()
                continue

            control_sequences = (_BRACKETED_PASTE_START, *_MULTILINE_KEY_SEQUENCES)
            if any(
                sequence.startswith(self._stream_buffer)
                for sequence in control_sequences
            ):
                # A terminal escape sequence may be split across reads.
                return

            char = self._stream_buffer[0]
            self._stream_buffer = self._stream_buffer[1:]
            self._accept_char(char)

    def _accept_ordinary(self, text: str) -> None:
        for char in text:
            self._accept_char(char)

    def _accept_char(self, char: str) -> None:
        if char == "\r":
            self._submit_buffer()
            return
        if char == "\n":  # Ctrl-J after ICRNL is disabled.
            self._insert_newline()
            return
        if char in {"\x7f", "\b"}:
            self._buffer = self._buffer[:-1]
        elif char == "\x15":  # Ctrl-U: clear the edit buffer.
            self._buffer = ""
        elif char == "\x04":  # Ctrl-D: leave it to session shutdown.
            return
        elif char == "\x16":  # Ctrl-V / Command-V forwarded by some terminals.
            self._paste_clipboard()
            return
        elif char == "\t":
            self._buffer += " "
        elif char.isprintable():
            self._buffer += char
        else:
            return

        from src.observability.live import LIVE

        LIVE.operator_input_update(self._buffer, queued=len(self._pending))

    def _insert_newline(self) -> None:
        """Add an intentional line break without submitting the message."""
        self._buffer += "\n"
        from src.observability.live import LIVE

        LIVE.operator_input_update(self._buffer, queued=len(self._pending))

    def _insert_paste(self, text: str) -> None:
        """Insert a paste literally; only a later physical Enter submits it."""
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        if not normalized:
            return
        self._buffer += normalized
        from src.observability.live import LIVE

        LIVE.operator_input_update(self._buffer, queued=len(self._pending))

    def _paste_clipboard(self) -> None:
        """Paste the macOS clipboard when the terminal forwards Ctrl-V."""
        try:
            result = subprocess.run(
                ["pbpaste"],
                check=False,
                capture_output=True,
                text=True,
                timeout=2,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            return
        if result.returncode == 0:
            self._insert_paste(result.stdout)

    def _submit_buffer(self) -> None:
        text = self._buffer.strip()
        self._buffer = ""
        if not text and not self.allow_empty:
            from src.observability.live import LIVE

            LIVE.operator_input_update("", queued=len(self._pending))
            return
        self._pending.append(text)
        self._submission_event.set()

        from src.observability.live import LIVE

        if self.announce_submissions:
            LIVE.operator_input_submitted(text, queued=len(self._pending))
        else:
            LIVE.operator_input_update("", queued=len(self._pending))
        if self.log_submissions and self.run_id:
            from src.observability.writers import append_event

            append_event(
                self.run_id,
                "operator_message_queued",
                text=text,
                queued=len(self._pending),
            )


def _possible_marker_suffix(text: str, marker: str) -> int:
    """Length of ``text``'s suffix that could begin ``marker``."""
    max_len = min(len(text), len(marker) - 1)
    for length in range(max_len, 0, -1):
        if text.endswith(marker[:length]):
            return length
    return 0


async def read_operator_instruction(
    *,
    placeholder: str,
    hint: str,
    allow_empty: bool = False,
) -> str | None:
    """Use the same editor as live guidance for an initial TUI message."""
    channel = LiveOperatorInput(
        run_id="",
        placeholder=placeholder,
        hint=hint,
        allow_empty=allow_empty,
        announce_submissions=False,
        log_submissions=False,
    )
    if not channel.start():
        return None
    try:
        return await channel.next_submission()
    finally:
        channel.stop()


__all__ = ["LiveOperatorInput", "read_operator_instruction"]
