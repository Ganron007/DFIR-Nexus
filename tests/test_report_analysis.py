"""N8 report-layer analysis — LLM dissection + deterministic fallback."""

from __future__ import annotations

import json

from nexus.integration.dfir_report import build_dfir_markdown
from nexus.langgraph.report_analysis import (
    analyze_cluster,
    case_assessment,
    category_for,
)


def _mshta_finding(**kw):
    base = {
        "id": "F-1",
        "title": "Signal: mshta — 5 hit(s) across hayabusa",
        "status": "APPROVED",
        "severity": "high",
        "technique_ids": ["T1218"],
        "evidence": [{
            "time": "2019-05-21T15:32:57",
            "source": "hayabusa/evtx.csv",
            "detail": 'RuleTitle: MSHTA exec · CommandLine: mshta http://x/y.hta',
            "loc": "hayabusa\\evtx.csv:3",
        }],
    }
    base.update(kw)
    return base


_ROWS = [{
    "detail": "CommandLine: mshta http://x",
    "time": "2019-05-21T15:32:57",
    "source": "hayabusa/evtx.csv",
}]


def test_heuristic_category_from_technique_id():
    """No model → deterministic category from technique IDs / keywords."""
    a = analyze_cluster([_mshta_finding()], _ROWS, model=None)
    assert a["source"] == "heuristic"
    assert a["category"] == "defense_evasion"  # T1218 → tactic map
    assert category_for([{"title": "schtasks /Create MSOFFICE_"}], []) == "persistence"


def test_llm_block_overrides_category_and_adds_narrative():
    class _Fake:
        def invoke(self, msgs):
            class R:
                content = json.dumps({
                    "category": "execution",
                    "what": "mshta.exe pulled a remote HTA payload",
                    "why": "living-off-the-land proxy execution",
                    "how": "inferred: remote HTA via mshta",
                    "who_when": "host row 2019-05-21T15:32:57",
                    "verify": ["pull parent process"],
                    "caveats": ["could be admin tooling"],
                })
            return R()

    a = analyze_cluster([_mshta_finding()], _ROWS, model=_Fake())
    assert a["source"] == "llm"
    assert a["category"] == "execution"  # LLM category overrides heuristic
    assert a["what"] == "mshta.exe pulled a remote HTA payload"
    assert a["verify"] == ["pull parent process"]


def test_llm_bad_json_falls_back_to_heuristic():
    class _Bad:
        def invoke(self, msgs):
            class R:
                content = "not json at all"
            return R()

    a = analyze_cluster([_mshta_finding()], _ROWS, model=_Bad())
    assert a["source"] == "heuristic"


def test_llm_exception_falls_back():
    """An LLM that raises mid-report must not break report generation."""
    class _Boom:
        def invoke(self, msgs):
            raise RuntimeError("endpoint down")

    a = analyze_cluster([_mshta_finding()], _ROWS, model=_Boom())
    assert a["source"] == "heuristic"
    assert a["category"] == "defense_evasion"


def test_case_assessment_heuristic_scope():
    clusters = [[_mshta_finding()]]
    analyses = {0: analyze_cluster(clusters[0], _ROWS, model=None)}
    assess = case_assessment(clusters, analyses, {0: _ROWS}, model=None)
    assert assess["source"] == "heuristic"
    assert "hayabusa" in assess["scope"]
    assert "defense_evasion" in assess["categories"]


def test_report_renders_assessment_and_analyst_read():
    md = build_dfir_markdown(
        case_id="CASE-X", case_name="X",
        findings=[_mshta_finding()],
        evidence=[], timeline=[],
        include_draft=True, llm=False,
    )
    assert "## Assessment" in md
    assert "**Analyst read**" in md
    assert "`defense_evasion`" in md
    assert "not examiner-approved" in md


def test_report_llm_banner_marks_assisted_sections():
    """When any analysis ran through the LLM the banner must say so."""
    import nexus.langgraph.report_analysis as ra

    class _Fake:
        def invoke(self, msgs):
            class R:
                content = json.dumps({
                    "category": "execution", "what": "w", "why": "y",
                    "how": "h", "who_when": "u",
                    "verify": [], "caveats": [],
                    "sequence": "s", "scope": "sc", "confidence": "low",
                    "gaps": [], "recommended": [],
                })
            return R()

    orig = ra.resolve_model
    ra.resolve_model = lambda: _Fake()
    try:
        md = build_dfir_markdown(
            case_id="CASE-X", case_name="X",
            findings=[_mshta_finding()],
            evidence=[], timeline=[],
            include_draft=True, llm=True,
        )
    finally:
        ra.resolve_model = orig
    assert "LLM-assisted" in md
    assert "Probable sequence" in md or "s" in md


def test_steer_instruction_reaches_cluster_prompt():
    """4j.5i — examiner steering must be injected into the LLM prompt."""
    import nexus.langgraph.report_analysis as ra

    seen: list[str] = []

    class _Spy:
        def invoke(self, msgs):
            seen.append(str(msgs[-1].get("content") or msgs[-1]))
            class R:
                content = json.dumps({"category": "execution", "what": "w"})
            return R()

    ra.analyze_cluster(
        [_mshta_finding()], _ROWS, model=_Spy(),
        steer="dig into the mshta chain",
    )
    assert any("dig into the mshta chain" in m for m in seen)


def test_cluster_blob_collapses_duplicate_signatures():
    """Scale: 30 identical rows → one signature row in the prompt."""
    import nexus.langgraph.report_analysis as ra

    rows = [dict(_ROWS[0]) for _ in range(30)]
    blob = ra._cluster_blob([_mshta_finding()], rows)
    assert "30 rows grouped into" in blob
    assert blob.count("\n- ") <= 17  # 16 sig cap + trailing 'more' line


def test_merge_duplicate_findings_collapses_same_signal():
    """Re-run duplicates (same needle, approved twice) render once."""
    from nexus.integration.dfir_report import build_dfir_markdown

    f1 = _mshta_finding()
    f1["id"] = "F-001"
    f2 = dict(_mshta_finding())
    f2["id"] = "F-009"
    f2["title"] = "Signal: mshta — 42 hit(s) across hayabusa"
    md = build_dfir_markdown(
        case_id="CASE-X", case_name="X",
        findings=[f1, f2], evidence=[], llm=False, include_draft=True,
    )
    assert "`F-001`" in md and "`F-009`" in md
    assert md.count("#### Signal: mshta") == 1  # one section, both IDs


def test_extract_iocs_pulls_indicators_from_rows():
    from nexus.integration.dfir_report import _extract_iocs

    rows = [{"detail": "Cmdline: mshta.exe https://hotelesms.com/talsk.txt "
                       "/TN MSOFFICE_ — C:\Windows\System32\Tasks\MSOFFICE_"}]
    iocs = _extract_iocs(rows)
    assert "https://hotelesms.com/talsk.txt" in iocs["urls"]
    assert "hotelesms.com" in iocs["domains"]
    assert "MSOFFICE_" in iocs["tasks"]
    assert any("Tasks" in p for p in iocs["paths"])


def test_timeline_label_extracts_salient_text():
    from nexus.integration.dfir_report import _timeline_label

    assert "EDR-Freeze" in _timeline_label(
        {"description": "detections: Hacktool - EDR-Freeze Execution;Other"})
    assert "Proc Exec" in _timeline_label(
        {"description": "RuleTitle: Proc Exec · Details: Cmdline: mshta"})
    assert "Process creation" in _timeline_label(
        {"description": r"MapDescription: Process creation · UserName: IEWIN7\IEUser"})
    assert "event record" in _timeline_label(
        {"description": "1,4125,2019-05-21 15:32:57.2,1,Info,Sysmon"})
