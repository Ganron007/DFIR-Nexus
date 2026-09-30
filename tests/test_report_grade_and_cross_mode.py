"""WP 10.0a / 10.0b - report grade and cross-mode consistency.

Acceptance criteria from the plan:

* 10.0a - the same report graded twice is stable; a seeded overclaim drops the
  class.
* 10.0b - on one case, every cross-mode contradiction is surfaced with both
  citations.
"""
from __future__ import annotations

import json

from nexus.analysis.cross_mode import (
    check_cross_mode,
    check_cross_mode_group,
    collect_mode_claims,
    render_consistency_markdown,
    sibling_cases,
    write_consistency,
)
from nexus.analysis.report_grade import (
    AXES,
    classify_finding,
    grade_report,
    render_grade_markdown,
    write_grade,
)

AUDIT = {"nx-audit-0001", "nx-audit-0002"}


def _finding(fid="F1", n_art=1, n_audit=1, **extra):
    f = {
        "id": fid,
        "title": "powershell.exe executed from a temp directory",
        "status": "APPROVED",
        "artifacts": [{"audit_id": f"nx-audit-{i:04d}"} for i in range(1, n_art + 1)],
        "sources": [f"family-{i}" for i in range(1, n_art + 1)],
    }
    f.update(extra)
    return f


# --------------------------------------------------------------------------
# 10.0a - grading
# --------------------------------------------------------------------------

def test_grading_is_stable():
    """Acceptance: the same report graded twice is stable."""
    md = "## Findings\n\n### powershell.exe execution\n\nBecause a prefetch row shows it.\n\n## Limitations\n\nOnly 3 files were registered; 40 were unregistered and unparsed."
    f = [_finding(n_art=2, n_audit=2)]
    a = grade_report(markdown=md, findings=f, known_audit_ids=AUDIT, evidence_count=3)
    b = grade_report(markdown=md, findings=f, known_audit_ids=AUDIT, evidence_count=3)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert a["report_class"] in {"A", "B"}


# --------------------------------------------------------------------------
# WO-11 - the grade consumes the L1 ledger and contradictions
# --------------------------------------------------------------------------

_A_MD = (
    "## Scope\n\n"
    "12 files were registered from evtx and tasks; 40 items were unparsed.\n\n"
    "## Findings\n\n"
    "### a.exe executed from a temporary directory\n\n"
    "Prefetch and the task XML agree, so it executed. Consistent with an earlier LNK row.\n\n"
    "### archive staging on the endpoint\n\n"
    "Because the MFT row shows the write, an archive was staged.\n\n"
    "## Limitations\n\n"
    "Prefetch deletion means execution counts are a lower bound; no memory image "
    "was acquired, so injected code is not covered.\n\n"
    "## Next steps\n\n"
    "Preserve the endpoint; recommend imaging memory and isolating the host before "
    "remediation.\n"
)


def _a_grade(**over):
    return grade_report(
        markdown=_A_MD,
        findings=[
            _finding(fid="F1", n_art=2, n_audit=2),
            _finding(fid="F2", n_art=2, n_audit=2),
        ],
        known_audit_ids=AUDIT,
        evidence_count=12,
        **over,
    )


def _ledger(*verdicts: str) -> dict:
    counts: dict[str, int] = {}
    for v in verdicts:
        counts[v] = counts.get(v, 0) + 1
    return {
        "claims": [
            {"finding_id": f"F{i}", "verdict": v} for i, v in enumerate(verdicts, 1)
        ],
        "verdict_counts": counts,
        "overall": (
            "PROVEN" if verdicts and all(v == "PROVEN" for v in verdicts) else "MIXED"
        ),
    }


def test_wo11_fixture_grades_a_at_35():
    base = _a_grade()
    assert base["total"] == 35, base["why_not_higher"]
    assert base["report_class"] == "A"
    assert base["l1_cap"] is None


def test_wo11_unsupported_one_of_five_caps_at_b():
    g = _a_grade(l1_ledger=_ledger("PROVEN", "PROVEN", "PROVEN", "PROVEN", "UNSUPPORTED"))
    assert g["report_class"] == "B"
    assert g["l1_cap"] == {"cap": "B", "reason": "1 UNSUPPORTED claim(s) of 5"}
    assert any("caps the class at B" in n for n in g["why_not_higher"])
    assert "Capped at B" in render_grade_markdown(g)

    unver = _a_grade(l1_ledger=_ledger("PROVEN", "PROVEN", "UNVERIFIABLE"))
    assert unver["report_class"] == "B"
    assert "UNVERIFIABLE" in unver["l1_cap"]["reason"]


def test_wo11_unsupported_ratio_caps_at_c():
    g = _a_grade(
        l1_ledger=_ledger("UNSUPPORTED", "UNSUPPORTED", "PROVEN", "PROVEN", "PROVEN")
    )
    assert g["report_class"] == "C"
    assert g["l1_cap"]["cap"] == "C"


def test_wo11_contradicted_or_live_contradiction_caps_at_d():
    g = _a_grade(l1_ledger=_ledger("PROVEN", "PROVEN", "CONTRADICTED"))
    assert g["report_class"] == "D"
    assert g["l1_cap"]["cap"] == "D"
    g2 = _a_grade(contradictions=2)
    assert g2["report_class"] == "D"
    assert "contradiction" in g2["l1_cap"]["reason"]


def test_wo11_all_proven_keeps_a():
    g = _a_grade(l1_ledger=_ledger("PROVEN", "PROVEN", "PROVEN"))
    assert g["report_class"] == "A"
    assert g["l1_cap"] is None


def test_seeded_overclaim_drops_the_class():
    """Acceptance: a seeded overclaim drops the class."""
    honest = (
        "## Scope\n\n12 files were registered from evtx and tasks.\n\n"
        "## Findings\n\n### a.exe execution\n\nPrefetch shows it ran, consistent with the task XML.\n\n"
        "## Limitations\n\nPrefetch deletion means execution counts are a lower bound; "
        "no memory was acquired."
    )
    f = [_finding(n_art=2, n_audit=2)]
    base = grade_report(markdown=honest, findings=f, known_audit_ids=AUDIT, evidence_count=12)

    overclaim = (
        "## Findings\n\n### a.exe execution\n\n"
        "This **proves** the attacker executed a.exe. It **definitely** ran, and this is the "
        "**complete picture**: it **fully reconstructed** the whole intrusion, and we have "
        "**ruled out** any other activity.\n"
    )
    worse = grade_report(markdown=overclaim, findings=f, known_audit_ids=AUDIT, evidence_count=12)

    assert worse["report_class"] not in {"A", "B"}, "overclaim must not grade as sound"
    assert worse["total"] < base["total"], f"overclaim scored {worse['total']} vs {base['total']}"


def test_fabricated_citation_is_class_f():
    md = "## Findings\n\n### a.exe\n\nBecause the prefetch row shows it.\n"
    f = [_finding(n_art=1, n_audit=1)]
    f[0]["artifacts"] = [{"audit_id": "nx-audit-9999"}]  # never happened
    g = grade_report(markdown=md, findings=f, known_audit_ids=AUDIT, evidence_count=1)
    assert g["report_class"] == "F"
    assert g["axes"]["non_fabrication"]["score"] == 0


def test_no_findings_is_class_d():
    g = grade_report(markdown="## Scope\n\n4 files.\n\n## Limitations\n\nNone parsed.",
                     findings=[], known_audit_ids=set(), evidence_count=4)
    assert g["report_class"] == "D"


def test_all_axes_present_and_bounded():
    md = "## Findings\n\n### x\n\nBecause a row shows it.\n"
    g = grade_report(markdown=md, findings=[_finding()], known_audit_ids=AUDIT, evidence_count=1)
    assert set(g["axes"]) == set(AXES)
    for a in g["axes"].values():
        assert 0 <= a["score"] <= 5


def test_missing_limitations_caps_the_class_at_c():
    md = (
        "## Scope\n\n12 files were registered.\n\n"
        "## Findings\n\n### a.exe\n\nPrefetch and the task XML agree, so it executed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=12)
    assert g["report_class"] == "C"
    assert g["axes"]["limitations"]["score"] < 5


def test_hedged_prove_is_not_an_overclaim():
    """`prove` in a limiting sentence is the careful statement, not the overclaim.

    Every one of these is real corpus text. Scoring them as overclaims would
    penalise the report for saying what it could not show.
    """
    md = (
        "## Findings\n\n### LSA registration\n\n"
        "The current evidence only proves a Winlogon-to-LSA registration occurred.\n\n"
        "These rows do not by themselves prove data staging or exfiltration.\n\n"
        "The cluster is insufficient to prove phishing delivery, user interaction, or host-side effects.\n\n"
        "## Limitations\n\nNothing in these rows supports an outcome claim.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=2)
    assert g["axes"]["non_fabrication"]["score"] == 5, g["why_not_higher"]


def test_prove_in_methodology_and_general_rules_is_not_an_overclaim():
    """`prove` is not an overclaim signal at all.

    These are also verbatim corpus text: methodology instruction, a general
    DMARC rule, and an imperative to the analyst. None of them asserts anything
    about this case, so none of them is an overclaim. Invented entities and
    invented counts are L1.1/L1.3's job, not this axis's.
    """
    md = (
        "## Method\n\n"
        "Systematic event-log examination: inventory the logs present, map the "
        "hypothesis to the event IDs that prove it, then correlate across channels.\n\n"
        "## Findings\n\n### Header analysis\n\n"
        "Failures prove spoofing; passes on a lookalike domain still prove the "
        "infrastructure used.\n\n"
        "**Interpretation** Prove what was deleted, when, and by which path.\n\n"
        "## Scope\n\n2 files were registered as evidence.\n\n"
        "## Limitations\n\nOther families were not parsed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=2)
    assert g["axes"]["non_fabrication"]["score"] == 5, g["why_not_higher"]


def test_unhedged_absolute_still_counts():
    md = (
        "## Findings\n\n### Execution\n\n"
        "The event log **definitely** establishes that the compromise occurred "
        "and this is the **complete picture** of the intrusion.\n\n"
        "## Scope\n\n2 files were registered as evidence.\n\n"
        "## Limitations\n\nOther families were not parsed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=2)
    assert g["axes"]["non_fabrication"]["score"] < 5
    assert any("overclaiming" in n for n in g["why_not_higher"])


def test_event_ids_are_identifiers_not_scope_counts():
    """`EventID 4611 row` is an identifier. Reading it as a count accused a
    22-file case of claiming 4611 examined sources."""
    md = (
        "## Findings\n\n### LSA registration\n\n"
        "The EventID 4611 row does not include the registered DLL path.\n\n"
        "Retrieve the complete EventID 4611 record and compare Event ID 4624 events.\n\n"
        "## Scope\n\n22 files were registered as evidence.\n\n"
        "## Limitations\n\nSome families were not parsed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=22)
    assert g["axes"]["scope_honesty"]["score"] == 5, g["why_not_higher"]


def test_knowledge_base_statistics_are_not_a_scope_claim():
    """`1160 capa-YARA rules (50 families)` is a KB figure, not this case's scope.

    Reading it as an evidence-scope count accused a graded report of
    overstating a scope it never claimed.
    """
    md = (
        "## Findings\n\n### Execution\n\nA prefetch row shows it ran.\n\n"
        "## Attack knowledge\n\n"
        "MITRE ATT&CK: 170 techniques / 35 mitigations / 57 case studies.\n"
        "MITRE MBC: 150 behaviors / 482 methods / 1160 capa-YARA rules (50 families).\n\n"
        "## Scope\n\n22 files were registered as evidence.\n\n"
        "## Limitations\n\nSome families were not parsed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=22)
    assert g["axes"]["scope_honesty"]["score"] == 5, g["why_not_higher"]
    assert not any("50" in n for n in g["why_not_higher"])


def test_a_real_scope_mismatch_is_still_caught():
    md = (
        "## Findings\n\n### Execution\n\nA row shows it ran.\n\n"
        "## Scope\n\n3 files were registered as evidence.\n\n"
        "## Limitations\n\nOther families were not parsed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=200)
    assert g["axes"]["scope_honesty"]["score"] <= 2
    assert any("200" in n or "3" in n for n in g["why_not_higher"])


def test_grading_a_graded_report_is_idempotent():
    """Acceptance, the hard form: the grader must not read its own output.

    Its own note says "report states 50 source(s); 22 were registered", which a
    re-grade would otherwise pick up as a scope claim - a self-referential
    finding that grows on every regeneration.
    """
    md = (
        "## Findings\n\n### Execution\n\nA prefetch row shows it ran.\n\n"
        "## Scope\n\n22 files were registered as evidence.\n\n"
        "## Limitations\n\nSome families were not parsed.\n"
    )
    first = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                         known_audit_ids=AUDIT, evidence_count=22)
    once = f"{md}\n---\n\n{render_grade_markdown(first)}"
    second = grade_report(markdown=once, findings=[_finding(n_art=2, n_audit=2)],
                          known_audit_ids=AUDIT, evidence_count=22)
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert not any("50" in n for n in second["why_not_higher"])


def test_scope_count_mismatch_is_penalised():
    md = (
        "## Scope\n\n3 files were registered.\n\n"
        "## Findings\n\n### a.exe\n\nA row shows it, so it executed.\n\n"
        "## Limitations\n\nOther families were not parsed.\n"
    )
    g = grade_report(markdown=md, findings=[_finding(n_art=2, n_audit=2)],
                     known_audit_ids=AUDIT, evidence_count=200)
    assert g["axes"]["scope_honesty"]["score"] <= 2
    assert any("scope_honesty" in n for n in g["why_not_higher"])


# --------------------------------------------------------------------------
# 10.0a - per-finding classes
# --------------------------------------------------------------------------

def test_finding_confirmed_needs_two_sources():
    assert classify_finding(_finding(n_art=2, n_audit=2))["class"] == "CONFIRMED"


def test_finding_indicated_with_one_source():
    assert classify_finding(_finding(n_art=1, n_audit=1))["class"] == "INDICATED"


def test_finding_unresolved_without_artifacts():
    assert classify_finding({"id": "F9", "title": "something happened"})["class"] == "UNRESOLVED"


def test_finding_refuted_by_verifier():
    g = classify_finding(_finding(verdict="refuted"))
    assert g["class"] == "REFUTED"


def test_finding_refuted_by_invented_audit_id():
    g = classify_finding(_finding(n_art=1, n_audit=1), known_audit_ids=set())
    assert g["class"] == "REFUTED"
    assert g["invented_audit_ids"] == ["nx-audit-0001"]


def test_render_and_write(tmp_path):
    g = grade_report(markdown="## Findings\n\n### x\n\nBecause a row shows it.\n",
                     findings=[_finding()], known_audit_ids=AUDIT, evidence_count=1)
    md = render_grade_markdown(g)
    assert "Report quality grade" in md and "| Analytical soundness |" in md
    p = write_grade(tmp_path, g)
    assert json.loads(p.read_text(encoding="utf-8"))["report_class"] == g["report_class"]


# --------------------------------------------------------------------------
# 10.0b - cross-mode consistency
# --------------------------------------------------------------------------

def _claims(mode, title, polarity="affirm", audit=("nx-audit-0001",)):
    return [{
        "mode": mode, "source": f"finding:{mode}-1",
        "key": ["process", "powershell.exe", "observation"],
        "polarity": polarity, "audit_ids": list(audit), "title": title,
        "confidence": "high",
    }]


# --------------------------------------------------------------------------
# WO-12 - the single-case check is intra-case; siblings are compared as a group
# --------------------------------------------------------------------------

def _mk_case(root, name, mode, findings):
    case = root / name
    case.mkdir(parents=True)
    (case / "CASE.yaml").write_text(
        f"investigation_mode: '{mode}'\nmode_scheme: 2\n", encoding="utf-8"
    )
    (case / "findings.json").write_text(json.dumps(findings), encoding="utf-8")
    return case


def test_wo12_group_check_compares_siblings(tmp_path, monkeypatch):
    from nexus.config import settings

    root = tmp_path / "cases"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "cases_root", root)

    ev = tmp_path / "staged-evidence.bin"
    ev.write_bytes(b"same bytes for all three")

    from nexus.case.compat import get_sqlite_manager
    from nexus.case.evidence_service import register_evidence

    specs = (
        ("CASE-AAA0001", "1", {
            "id": "F1", "title": "beacon to ghosthost.example.com observed",
            "polarity": "affirm", "audit_ids": ["nx-audit-aaaa0001"],
        }),
        ("CASE-BBB0002", "2", {
            "id": "F2", "title": "host reviewed; no signal row found",
            "polarity": "deny", "audit_ids": ["nx-audit-bbbb0002"],
        }),
        ("CASE-CCC0003", "3", {
            "id": "F3", "title": "beacon to ghosthost.example.com did not occur",
            "polarity": "deny", "audit_ids": ["nx-audit-cccc0003"],
        }),
    )
    mgr = get_sqlite_manager()
    for name, mode, finding in specs:
        case = root / name
        case.mkdir(parents=True, exist_ok=True)
        mgr.create_case(name=name, created_by="t", case_id=name)
        register_evidence(case, str(ev))
        # Case files go in AFTER the registry/evidence calls: those sync the
        # flat mirrors and would blank a findings.json written before them.
        (case / "CASE.yaml").write_text(
            f"investigation_mode: '{mode}'\nmode_scheme: 2\n", encoding="utf-8"
        )
        (case / "findings.json").write_text(
            json.dumps([finding]), encoding="utf-8"
        )
    a = root / "CASE-AAA0001"
    b = root / "CASE-BBB0002"
    c = root / "CASE-CCC0003"

    assert {p.name for p in sibling_cases(a)} == {"CASE-BBB0002", "CASE-CCC0003"}

    r = check_cross_mode_group([a, b, c])
    assert r["scope"] == "group"
    assert r["verdict"] == "contradictory"
    assert len(r["contradictions"]) == 1
    con = r["contradictions"][0]
    assert con["key"]["entity_value"] == "ghosthost.example.com"
    assert [x["audit_ids"] for x in con["affirms"]] == [["nx-audit-aaaa0001"]]
    assert [x["audit_ids"] for x in con["denials"]] == [["nx-audit-cccc0003"]]
    assert {x["case_id"] for x in r["cases"]} == {
        "CASE-AAA0001", "CASE-BBB0002", "CASE-CCC0003"
    }

    from typer.testing import CliRunner

    from nexus.cli.main import app as cli_app

    r2 = CliRunner().invoke(cli_app, ["cross-mode", str(a), str(c)])
    assert r2.exit_code == 1, r2.output
    assert "Cross-case consistency" in r2.output


def test_wo12_mode2_findings_are_not_reported_as_mode1(tmp_path):
    case = _mk_case(tmp_path, "CASE-M2SELF01", "2", [{
        "id": "F1", "title": "powershell.exe did not execute",
        "polarity": "deny", "audit_ids": ["nx-audit-1111"],
    }])
    runs = case / "analysis" / "mode2_runs"
    runs.mkdir(parents=True)
    (runs / "M2-20260930T00.json").write_text(json.dumps({
        "candidates": [{
            "id": "C1", "title": "powershell.exe executed from a temp directory",
            "polarity": "affirm", "audit_ids": ["nx-audit-2222"],
        }],
    }), encoding="utf-8")

    claims = collect_mode_claims(case)
    assert claims["1"] == [], "a Mode 2 case's findings must not be labelled Mode 1"
    assert claims["2"], claims
    r = check_cross_mode(case_dir=case)
    assert r["modes_present"] == ["Mode 2 (multi-role)"]
    assert r["contradictions"] == []
    assert r["scope"] == "intra-case"


def test_contradiction_is_surfaced_with_both_citations():
    """Acceptance: every cross-mode contradiction carries both citations."""
    r = check_cross_mode(claims_by_mode={
        "1": _claims("1", "powershell.exe executed"),
        "2": _claims("2", "powershell.exe did not execute", polarity="deny"),
        "3": [],
    })
    assert r["verdict"] == "contradictory"
    assert len(r["contradictions"]) == 1
    c = r["contradictions"][0]
    assert c["affirms"][0]["mode"] == "1"
    assert c["denials"][0]["mode"] == "2"
    assert c["affirms"][0]["audit_ids"] and c["denials"][0]["audit_ids"]
    assert "powershell.exe" in render_consistency_markdown(r)


def test_agreement_is_reported_as_shared_not_contradiction():
    r = check_cross_mode(claims_by_mode={
        "1": _claims("1", "powershell.exe executed"),
        "2": _claims("2", "powershell.exe executed"),
        "3": _claims("3", "powershell.exe executed"),
    })
    assert r["verdict"] == "consistent"
    assert r["counts"]["shared"] == 1
    assert r["counts"]["contradictions"] == 0
    assert r["entity_overlap"]["1-2"] == 1.0


def test_a_missing_mode_is_unknown_not_agreement():
    r = check_cross_mode(claims_by_mode={"1": _claims("1", "x.exe ran"), "2": [], "3": []})
    assert r["verdict"] == "incomplete"
    assert r["modes_missing"]
    assert "not agreement" in render_consistency_markdown(r)


def test_no_modes_at_all_is_unknown():
    assert check_cross_mode(claims_by_mode={"1": [], "2": [], "3": []})["verdict"] == "unknown"


def test_row_contradiction_detected():
    rows = (
        "Query result for powershell.exe: no matching records found in the indexed rows.\n"
    )
    r = check_cross_mode(
        claims_by_mode={"1": _claims("1", "powershell.exe executed"), "2": [], "3": []},
        rows_text=rows,
    )
    assert r["counts"]["row_contradictions"] == 1
    assert r["verdict"] == "contradictory"
    assert r["row_contradictions"][0]["audit_ids"] == ["nx-audit-0001"]


def test_denial_detected_from_prose_when_no_polarity_field():
    """A claim row with no explicit polarity must take its polarity from prose.

    This is the projection layer a real case artifact goes through, so a title
    that says "did not execute" is read as a denial even when the run never set
    a polarity field. If it were read as an affirmation, a contradiction would
    be silently lost.
    """
    from nexus.analysis.cross_mode import _claim_from_finding

    rows = _claim_from_finding("2", {
        "id": "F7", "title": "powershell.exe did not execute on this host",
        "artifacts": [{"audit_id": "nx-audit-0002"}],
    })
    assert rows and rows[0]["polarity"] == "deny"
    r = check_cross_mode(claims_by_mode={
        "1": _claims("1", "powershell.exe executed"),
        "2": rows,
        "3": _claims("3", "powershell.exe executed"),
    })
    assert r["counts"]["contradictions"] == 1
    assert r["verdict"] == "contradictory"


def test_collect_mode_claims_from_a_case(tmp_path):
    case = tmp_path / "CASE-X"
    (case / "analysis" / "mode3_runs").mkdir(parents=True)
    (case / "findings.json").write_text(json.dumps([
        {"id": "F1", "title": "powershell.exe ran from temp",
         "artifacts": [{"audit_id": "nx-audit-0001"}]},
    ]), encoding="utf-8")
    (case / "analysis" / "mode3_runs" / "M3-1.json").write_text(json.dumps({
        "candidates": [{"title": "powershell.exe did not run", "claim_kind": "observation",
                        "audit_ids": ["nx-audit-0002"]}],
    }), encoding="utf-8")
    got = collect_mode_claims(case)
    assert got["1"] and got["3"]
    r = check_cross_mode(case_dir=case)
    assert r["verdict"] == "contradictory"
    p = write_consistency(case, r)
    assert json.loads(p.read_text(encoding="utf-8"))["verdict"] == "contradictory"


def test_tenancy_of_entity_extraction_is_case_insensitive():
    a = check_cross_mode(claims_by_mode={"1": _claims("1", "POWERSHELL.EXE executed"),
                                         "2": _claims("2", "powershell.exe executed"), "3": []})
    assert a["counts"]["shared"] == 1


def test_zero_overlap_is_disjoint_not_consistent():
    """No shared entity with no contradiction is not agreement.

    This is the real result: Modes 1, 2 and 3 ran over the same 81,115 indexed
    rows and named not one entity in common - Mode 1 reported needle terms,
    Mode 2 reported host and process conclusions, Mode 3 reported parser family
    names. There was no shared subject, so nothing could be agreed or disagreed
    about, and reporting "consistent" would be false assurance in the exact
    direction that matters.
    """
    r = check_cross_mode(claims_by_mode={
        "1": [{"mode": "1", "source": "f1", "key": ["process", "sdelete", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0001"], "title": "sdelete ran"}],
        "2": [{"mode": "2", "source": "f2", "key": ["ipv4", "srl-forge", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0002"], "title": "host SRL-FORGE"}],
        "3": [{"mode": "3", "source": "f3", "key": ["process", "evtxecmd", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0001"], "title": "evtxecmd: presence"}],
    })
    assert r["verdict"] == "disjoint", r["verdict"]
    assert r["counts"]["contradictions"] == 0
    assert r["shared_entities"] == []
    md = render_consistency_markdown(r)
    assert "DISJOINT" in md
    assert "not agreement" in md


def test_a_contradiction_outranks_disjointness():
    r = check_cross_mode(claims_by_mode={
        "1": [{"mode": "1", "source": "f1", "key": ["process", "a.exe", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0001"], "title": "a.exe ran"}],
        "2": [{"mode": "2", "source": "f2", "key": ["process", "a.exe", "observation"],
               "polarity": "deny", "audit_ids": ["nx-audit-0002"], "title": "a.exe did not run"}],
        "3": [{"mode": "3", "source": "f3", "key": ["process", "z.exe", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0001"], "title": "z.exe ran"}],
    })
    assert r["verdict"] == "contradictory"
    assert r["shared_entities"] == ["a.exe"]


def test_different_entities_do_not_collide():
    r = check_cross_mode(claims_by_mode={
        "1": [{"mode": "1", "source": "f1", "key": ["process", "a.exe", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0001"], "title": "a.exe ran"}],
        "2": [{"mode": "2", "source": "f2", "key": ["process", "b.exe", "observation"],
               "polarity": "affirm", "audit_ids": ["nx-audit-0002"], "title": "b.exe ran"}],
        "3": [],
    })
    assert r["counts"]["contradictions"] == 0
    assert r["entity_overlap"]["1-2"] == 0.0


# --------------------------------------------------------------------------
# structure: a report of search terms is navigable and useless
# --------------------------------------------------------------------------

_TITLED_MD = (
    "## Scope\n\n22 files were registered as evidence.\n\n"
    "## Findings\n\n### Execution\n\nThe rows show a prefetch entry.\n\n"
    "## Limitations\n\nOther families were not parsed.\n"
)


def test_raw_needle_titles_cost_the_structure_axis():
    """The Mode 1 scribe titles findings after the needle that matched.

    All eleven titles on the first real case read "Signal: <needle> - N hit(s)".
    That is an inventory of search terms, not a set of conclusions, and the
    grader scored structure 5/5 on it until the expert review flagged it.
    """
    needles = ["sdelete", "pid_", "vid_", "usbstor", "onedrive", "usb",
               "rdp", "scriptblock", "winlogon", "my drive", "sdelete"]
    findings = [
        {"id": f"F{i}", "title": f"Signal: {n} - 2+ hit(s) across evtxecmd",
         "artifacts": [{"audit_id": f"nx-audit-{i:04d}"}], "sources": ["f1", "f2"]}
        for i, n in enumerate(needles, 1)
    ]
    g = grade_report(markdown=_TITLED_MD, findings=findings,
                     known_audit_ids=AUDIT, evidence_count=22)
    assert g["axes"]["structure"]["score"] < 5, g["axes"]["structure"]
    assert any("raw needle" in n for n in g["why_not_higher"])
    # The penalty is bounded - unreadable is not the same as absent.
    assert g["axes"]["structure"]["score"] >= 1


def test_analyst_readable_titles_keep_the_structure_score():
    findings = [
        {"id": f"F{i}",
         "title": "powershell.exe executed from C:\\Users\\bob\\AppData\\Local\\Temp",
         "artifacts": [{"audit_id": f"nx-audit-{i:04d}"}], "sources": ["f1", "f2"]}
        for i in (1, 2, 3)
    ]
    g = grade_report(markdown=_TITLED_MD, findings=findings,
                     known_audit_ids=AUDIT, evidence_count=22)
    assert g["axes"]["structure"]["score"] == 5, g["why_not_higher"]


def test_a_mix_of_title_quality_is_diagnosed():
    findings = [
        {"id": "F1", "title": "Signal: sdelete - 1 hit(s) across evtxecmd",
         "artifacts": [{"audit_id": "nx-audit-0001"}], "sources": ["f1", "f2"]},
        {"id": "F2", "title": "powershell.exe executed from a temp directory",
         "artifacts": [{"audit_id": "nx-audit-0002"}], "sources": ["f1", "f2"]},
    ]
    g = grade_report(markdown=_TITLED_MD, findings=findings,
                     known_audit_ids=AUDIT, evidence_count=22)
    assert any("1/2 finding title" in n for n in g["why_not_higher"]), g["why_not_higher"]
