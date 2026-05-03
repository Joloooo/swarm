"""Experimental subsystems — research scaffolds, off by default.

Modules in this directory are kept around as evidence of design
exploration but are NOT part of the default agent loop. None of them
are registered as graph nodes.

Currently shelved:
    experimental/experience/  — cross-run guide store (Jaccard match)
    experimental/rag/         — knowledge vector store (FAISS)
    experimental/stealth/     — WAF/IDS detection (no evasion behavior)

Why shelved (not deleted):
    Each one is referenced in the literature-review chapter and may be
    revived for the thesis differentiator (M4 in the milestone plan).
    Keeping the code in tree documents the design choice rather than
    erasing it.
"""
