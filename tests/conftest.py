"""Pytest configuration.

Legacy standalone check-scripts (module-level ``sys.exit``/``__main__``,
not pytest-collectable) are excluded from discovery. Everything else under
``tests/test_*.py`` runs in the full suite — the previous explicit
``python_files`` allowlist silently excluded 28 real test files (Mode 1/2/3,
portal, RAG, FD-006/007, Phase 4 APIs) from full runs.
"""

collect_ignore_glob = [
    "test_detection.py",
    "test_hunt_parser.py",
    "test_integration.py",
    "test_portal.py",
    "test_ti.py",
]
