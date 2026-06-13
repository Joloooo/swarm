"""Experimental subsystems — research scaffolds.

Currently live:
    experimental/stealth/  — WAF/IDS detection (no evasion behavior).
        Wired into the executor: ``_stealth_check`` runs StealthMonitor
        over every finding to flag WAF/IDS responses and raise the
        ``stealth_level`` on the run state.

The earlier ``experience/`` (cross-run guide store) and ``rag/``
(FAISS knowledge store) scaffolds were removed — they were never
wired into the graph.
"""
