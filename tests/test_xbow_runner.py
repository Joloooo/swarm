"""Tier 1 — XBEN runner port-mapping tests.

Pins the per-VM-IP host-port logic in ``benchmarks/xbow_runner.py`` that
two real failures (2026-06-04, see ``tests/FAILURES.md``) traced back to:

- ``_free_host_port`` must NOT remap privileged ports (80, 22). A non-root
  socket bind to a port <1024 always raises ``PermissionError``, which an
  earlier version misread as "busy" and remapped ``:80 -> :10080`` — the
  app then sat on a port the agent's scan never reached (XBEN-020 crash).
- When a port IS genuinely squatted (macOS AirPlay holds *:5000 / *:7000),
  the fallback must land BELOW 10000 so a normal recon scan still finds it
  (no more 15000), and two squatted ports in one benchmark must not collide.
- ``_ports_leak_onto`` backs the clean-slate guard that removes stale
  containers whose published ports would answer on a run's target IP
  (XBEN-096 false flag-capture off a leftover container).

Pure logic — no LLM, no Docker, no network. ``_bindable`` is monkeypatched
to simulate a squatter instead of actually holding a socket.
"""

from __future__ import annotations

import pytest

from benchmarks import xbow_runner as xr


# ── _free_host_port: privileged ports stay real ──────────────────────

@pytest.mark.parametrize("port", [22, 80, 443, 1023])
def test_privileged_ports_are_kept_real(port):
    # <1024 is returned unchanged WITHOUT probing — Docker's privileged
    # publisher binds it even though this non-root process cannot.
    assert xr._free_host_port("127.0.0.2", port) == port


def test_privileged_port_not_probed(monkeypatch):
    # If _bindable were consulted for port 80 it would (as non-root) say
    # "busy" and trigger a remap — the regression we are guarding against.
    def boom(ip, p):  # pragma: no cover - must never be called for <1024
        raise AssertionError(f"_bindable should not be probed for privileged port {p}")
    monkeypatch.setattr(xr, "_bindable", boom)
    assert xr._free_host_port("127.0.0.2", 80) == 80


# ── _free_host_port: non-privileged behaviour ────────────────────────

def test_free_nonprivileged_port_is_kept(monkeypatch):
    monkeypatch.setattr(xr, "_bindable", lambda ip, p: True)
    assert xr._free_host_port("127.0.0.2", 8080) == 8080


def test_squatted_port_remaps_into_pool_below_10000(monkeypatch):
    # Simulate AirPlay holding 5000: preferred is unbindable, pool is free.
    monkeypatch.setattr(xr, "_bindable", lambda ip, p: p != 5000)
    h = xr._free_host_port("127.0.0.2", 5000)
    assert h in xr._REMAP_POOL
    assert h < 10000


def test_sibling_squatted_ports_do_not_collide(monkeypatch):
    # Both 5000 and 7000 squatted; the caller threads the shared `taken`
    # set so the two services get DISTINCT pool ports.
    monkeypatch.setattr(xr, "_bindable", lambda ip, p: p not in (5000, 7000))
    taken: set[int] = set()
    h1 = xr._free_host_port("127.0.0.2", 5000, taken=taken); taken.add(h1)
    h2 = xr._free_host_port("127.0.0.2", 7000, taken=taken); taken.add(h2)
    assert h1 != h2
    assert {h1, h2} <= set(xr._REMAP_POOL)


# ── pool invariants ──────────────────────────────────────────────────

def test_remap_pool_is_20_ports_all_below_10000():
    assert len(xr._REMAP_POOL) == 20
    assert all(1024 <= p < 10000 for p in xr._REMAP_POOL)
    assert len(set(xr._REMAP_POOL)) == len(xr._REMAP_POOL)  # no dupes


# ── _ports_leak_onto: clean-slate guard detector ─────────────────────

@pytest.mark.parametrize("ports,ip,expected", [
    ("0.0.0.0:5099->5000/tcp", "127.0.0.2", True),    # wildcard IPv4
    (":::5099->5000/tcp",      "127.0.0.2", True),    # wildcard IPv6
    ("[::]:5099->5000/tcp",    "127.0.0.2", True),    # wildcard IPv6 (bracket form)
    ("127.0.0.2:9001->5000/tcp", "127.0.0.2", True),  # same leased IP reused
    ("127.0.0.5:9001->5000/tcp", "127.0.0.2", False), # sibling on its own IP
    ("", "127.0.0.2", False),                          # nothing published
])
def test_ports_leak_onto(ports, ip, expected):
    assert xr._ports_leak_onto(ports, ip) is expected


# ── _primary_target_url: hand the agent the exact app URL ────────────

@pytest.mark.parametrize("host_map,expected", [
    ({5000: 9001}, "http://127.0.0.2:9001"),       # remapped 5000 → exact URL
    ({80: 80}, "http://127.0.0.2"),                # real :80 → no port in URL
    ({22: 22, 80: 80}, "http://127.0.0.2"),        # web chosen over SSH
    ({80: 80, 8081: 8081}, "http://127.0.0.2"),    # primary web port wins
    ({443: 443}, "https://127.0.0.2"),             # 443 → https, no port
    ({}, "http://127.0.0.2"),                      # empty map → bare IP
    ({22: 10022}, "http://127.0.0.2:10022"),       # only SSH → still addressable
])
def test_primary_target_url(host_map, expected):
    assert xr._primary_target_url("127.0.0.2", host_map) == expected
