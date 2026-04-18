"""TypedDict schema shared by every nmap tool.

All nmap_* tools return a ScanResult. The normalizer in _engine.py
walks python-nmap's internal dict and builds this structure. Optional
fields are omitted entirely when empty to save tokens in LLM context.
"""

from __future__ import annotations

from typing import Literal, NotRequired, TypedDict


class ScriptResult(TypedDict):
    id: str
    output: str
    elements: NotRequired[dict]


class PortResult(TypedDict):
    port: int
    protocol: Literal["tcp", "udp"]
    state: Literal["open", "filtered", "closed", "open|filtered", "unfiltered"]
    service: NotRequired[str]
    product: NotRequired[str]
    version: NotRequired[str]
    extrainfo: NotRequired[str]
    cpe: NotRequired[list[str]]
    scripts: NotRequired[list[ScriptResult]]


class HostResult(TypedDict):
    host: str
    hostnames: NotRequired[list[str]]
    state: Literal["up", "down"]
    os: NotRequired[str]
    os_accuracy: NotRequired[int]
    ports: list[PortResult]
    host_scripts: NotRequired[list[ScriptResult]]


class ErrorInfo(TypedDict):
    code: Literal[
        "binary_missing",
        "permission_denied",
        "invalid_target",
        "invalid_args",
        "timeout",
        "unknown",
    ]
    hint: str
    stderr: NotRequired[str]


class ScanResult(TypedDict):
    ok: bool
    tool: str
    target: str
    command: str
    elapsed_seconds: float
    hosts: list[HostResult]
    summary: str
    error: NotRequired[ErrorInfo]
    warnings: NotRequired[list[str]]
