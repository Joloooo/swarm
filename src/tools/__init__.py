"""LangChain tools exposed to agents and the supervisor planner.

- ``bash`` (``shell/bash.py``) — one-shot non-interactive commands via
  a persistent bash subprocess per agent. Use for nmap, curl, sqlmap,
  gobuster, etc.
- ``run_command`` (``shell/tmux.py``) — interactive tmux pane. Use only
  for things that need a real TTY (msfconsole, ssh shells, listeners).
- ``read_file`` (``shell/tmux.py``) — read a file the agent's commands
  produced or discovered.
- ``normalize_url`` / ``validate_website`` (``url.py``) — planner-only
  tools for turning user input into a canonical URL and checking
  reachability.
"""

from src.tools.crawler import (
    CrawlBatchResult,
    CrawlResult,
    CrawlerOptions,
    crawl,
    crawl_many,
)
from src.tools.shell import bash, read_file, run_command
from src.tools.url import normalize_url, validate_website

__all__ = [
    "bash",
    "read_file",
    "run_command",
    "normalize_url",
    "validate_website",
    "crawl",
    "crawl_many",
    "CrawlResult",
    "CrawlBatchResult",
    "CrawlerOptions",
]
