"""Mode 1 verifier classes, without touching a live index."""
from nexus.analysis.negative_space import read_events
from nexus.modes.mode1_verify import apply_verifier, classify_draft


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


def test_apply_verifier_reruns_cited_needles(tmp_path, monkeypatch):
    (tmp_path / "CASE.yaml").write_text("id: t\n", encoding="utf-8")
    monkeypatch.setattr(
        "nexus.langgraph.query_pack.n4_hits",
        lambda *_args, **_kwargs: ([{"line": "1"}], "csv"),
    )
    out = apply_verifier(tmp_path, {
        "title": "still there",
        "needles": ["sdelete"],
        "provenance": {"origin": "llm"},
        "audit_ids": ["a1"],
    })
    assert out["verdict"] == "CONFIRMED"
    assert read_events(tmp_path) == []


def test_apply_verifier_refuted_is_audited_and_kept(tmp_path, monkeypatch):
    (tmp_path / "CASE.yaml").write_text("id: t\n", encoding="utf-8")
    monkeypatch.setattr(
        "nexus.langgraph.query_pack.n4_hits",
        lambda *_args, **_kwargs: ([], "csv"),
    )
    draft = {
        "title": "gone",
        "needles": ["sdelete"],
        "provenance": {"origin": "llm"},
        "audit_ids": ["a1"],
    }
    out = apply_verifier(tmp_path, draft)
    assert out["verdict"] == "REFUTED"
    events = read_events(tmp_path)
    assert events and events[0]["kind"] == "refuted"


def test_supplied_hits_are_not_a_second_scan(tmp_path, monkeypatch):
    (tmp_path / "CASE.yaml").write_text("id: t\n", encoding="utf-8")

    def _boom(*_args, **_kwargs):
        raise AssertionError("index must not be queried when hits were supplied")

    monkeypatch.setattr("nexus.langgraph.query_pack.n4_hits", _boom)
    out = apply_verifier(
        tmp_path,
        {
            "title": "in hand",
            "needles": ["sdelete"],
            "provenance": {"origin": "llm"},
            "audit_ids": ["a1"],
        },
        hits=[{"line": "1"}],
    )
    assert out["verdict"] == "CONFIRMED"


def test_search_failure_stays_inferred(tmp_path, monkeypatch):
    (tmp_path / "CASE.yaml").write_text("id: t\n", encoding="utf-8")

    def _down(*_args, **_kwargs):
        raise RuntimeError("index down")

    monkeypatch.setattr("nexus.langgraph.query_pack.n4_hits", _down)
    out = apply_verifier(tmp_path, {
        "needles": ["sdelete"],
        "provenance": {"origin": "llm"},
        "audit_ids": ["a1"],
    })
    assert out["verdict"] == "INFERRED"
    assert read_events(tmp_path) == []
