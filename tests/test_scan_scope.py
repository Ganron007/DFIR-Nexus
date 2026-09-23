"""Proof: the needle scan reads ONLY the case's processed evidence.

Live report (2026-09-23): repo path fragments (`STUDY\\Github`,
`CADRE-Platform\\DFIR-Nexus`) appeared next to scan needles. Root causes were
hypothesis vocabulary (intake/Explore terms persisted to CASE.yaml) and the
DOMAIN\\user regex matching path segments — NOT an out-of-scope file scan.
This test pins the scope so a future change cannot silently widen it.
"""

from __future__ import annotations

from pathlib import Path

CANARY = "CANARYOUTSIDESTOPIC9001"


def _case_with_evidence(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-SCOPE"
    (case / "extractions" / "hayabusa").mkdir(parents=True)
    (case / "extractions" / "hayabusa" / "timeline.csv").write_text(
        "Timestamp,RuleTitle,Computer\n"
        "2020-11-14 03:56:46,sdelete usage,WS01\n",
        encoding="utf-8",
    )
    return case


def test_scan_reads_only_case_evidence(tmp_path):
    from nexus.langgraph.query_pack import parse_window, scan_extractions

    case = _case_with_evidence(tmp_path)
    # A canary lives OUTSIDE the case (repo/temp area) — the scan must not see it.
    outside = tmp_path / "outside-the-case.txt"
    outside.write_text(f"{CANARY} not evidence\n", encoding="utf-8")

    start, end = parse_window("")
    in_scope = scan_extractions(case, ["sdelete"], (start, end))
    out_scope = scan_extractions(case, [CANARY], (start, end))

    assert in_scope, "case evidence must be searched"
    assert out_scope == [], "a file outside the case must never be searched"


def test_briefing_needles_are_evidence_vocabulary(tmp_path):
    """Vocabulary must not contain machine paths — even when intake does."""
    from nexus.langgraph import briefing
    from nexus.langgraph.case_intake import persist_case_intake

    case = _case_with_evidence(tmp_path)
    persist_case_intake(case, {
        "question": r"triage C:\STUDY\Github\CADRE-Platform\DFIR-Nexus evidence",
        "subjects": r"C:\STUDY\Github\CADRE-Platform\DFIR-Nexus\Evidence-files",
        "query_extra": "\n".join([
            "domain_user",
            r"STUDY\Github",
            r"CADRE-Platform\DFIR-Nexus",
        ]),
    })

    needles = briefing._scan_needles(case, ["hayabusa"], [])

    assert needles, "the scan still proposes real needles (e.g. playbook terms)"
    assert all("\\" not in k and "/" not in k and ":" not in k for k in needles)
    assert "domain_user" not in needles
    assert CANARY not in " ".join(needles)


def test_persistable_needles_blocks_paths_and_labels():
    from nexus.langgraph.query_pack import persistable_needles

    kept = persistable_needles([
        "domain_user", r"STUDY\Github", r"CADRE-Platform\DFIR-Nexus",
        "C:\\Windows\\Temp", "sdelete", "4624", "lsass",
    ])
    assert kept == ["sdelete", "4624", "lsass"]
