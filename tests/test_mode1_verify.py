"""Mode 1 verifier classes, without touching a live index."""
from nexus.modes.mode1_verify import classify_draft


def test_examiner_draft_is_not_verified():
    out = classify_draft({"examiner_selected": True, "audit_ids": ["a1"]})
    assert out["verdict"] == "skipped"


def test_model_draft_without_audit_is_refuted():
    out = classify_draft({
        "provenance": {"origin": "llm", "path": "full_run"},
        "audit_ids": [],
    })
    assert out["verdict"] == "REFUTED"


def test_cited_query_with_no_rows_is_refuted():
    out = classify_draft(
        {"provenance": {"origin": "llm"}, "audit_ids": ["a1"]},
        search=lambda _draft: [],
    )
    assert out["verdict"] == "REFUTED"


def test_cited_query_with_rows_is_confirmed():
    out = classify_draft(
        {"provenance": {"origin": "llm"}, "audit_ids": ["a1"]},
        search=lambda _draft: [{"line": "1"}],
    )
    assert out["verdict"] == "CONFIRMED"
