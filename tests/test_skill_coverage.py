"""WP 9.3 — skill coverage gate.

Fails when a *prioritized* evidence class or ATT&CK technique has no skill.
The ledger of record is `Docs/internal/SKILL-COVERAGE.md`; this test enforces
it so coverage cannot silently regress. Deliberately deferred items live in
`DEFERRED` with a reason.
"""
from __future__ import annotations

from nexus.knowledge.loader import get_skills

# Evidence classes every SD/enterprise investigation should be able to start
# from. Each maps to trigger families/keywords some skill must claim.
PRIORITY_FAMILIES: dict[str, set[str]] = {
    "windows_event_logs": {"evtx", "hayabusa", "evtxecmd"},
    "windows_execution": {"prefetch", "pecmd", "amcache", "appcompat"},
    "windows_registry": {"registry", "recmd"},
    "linux": {"linux", "authlog", "journal", "auditd"},
    "macos": {"macos", "apfs", "launchd"},
    "cloud": {"azure", "cloudtrail", "m365"},
    "containers": {"docker", "container", "kubernetes"},
    "memory": {"vol", "volatility", "memprocfs", "memory"},
    "network": {"zeek", "netstat", "conn", "wireshark"},
    "mobile": {"android", "ios", "mobile"},
    "ics_ot": {"modbus", "ics", "scada", "plc"},
    "email": {"email", "eml", "headers"},
}

# Prioritized ATT&CK techniques — each must appear in some skill's `mitre`.
PRIORITY_TECHNIQUES: set[str] = {
    "T1003.001",  # LSASS memory
    "T1003.003",  # NTDS
    "T1055",      # process injection
    "T1053.005",  # scheduled task
    "T1547.001",  # run key
    "T1071",      # C2 application-layer
    "T1566.001",  # phishing attachment
    "T1486",      # data encrypted for impact
    "T1490",      # inhibit recovery
    "T1070.004",  # file deletion
    "T1027",      # obfuscation
    "T1543.001",  # macOS launchd
    "T1611",      # container escape
    "T1078.004",  # cloud accounts
    "T0816",      # ICS device restart/shutdown
    "T1533",      # mobile local data
}

# Deliberately deferred (documented) — never silently "covered".
DEFERRED: dict[str, str] = {
    "memory_acquisition": "Phase 7 owns acquisition; analysis skill exists",
    "aws_gcp_offensive": "DET dictionaries (SK-7), not an examiner procedure",
    "zeek_rita_longtail": "network_session_analysis covers the sequence",
}


def _triggers() -> tuple[set[str], set[str], set[str]]:
    families: set[str] = set()
    keywords: set[str] = set()
    techniques: set[str] = set()
    for s in get_skills():
        trig = s.get("trigger") or {}
        families.update(str(x).lower() for x in (trig.get("families") or []))
        keywords.update(str(x).lower() for x in (trig.get("keywords") or []))
        techniques.update(str(x).upper() for x in (s.get("mitre") or []))
        techniques.update(str(x).upper() for x in (trig.get("techniques") or []))
    return families, keywords, techniques


def test_priority_evidence_classes_covered():
    families, keywords, _ = _triggers()
    have = families | keywords
    missing = [name for name, toks in PRIORITY_FAMILIES.items() if not (toks & have)]
    assert not missing, f"uncovered priority evidence classes: {missing}"


def test_priority_techniques_covered():
    _, _, techniques = _triggers()
    missing = sorted(t for t in PRIORITY_TECHNIQUES if t not in techniques)
    assert not missing, f"uncovered priority ATT&CK techniques: {missing}"


def test_deferred_items_are_documented():
    """Every deferred class must carry a reason."""
    assert DEFERRED, "deferred map should not be empty"
    assert all(reason.strip() for reason in DEFERRED.values())
