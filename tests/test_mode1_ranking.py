"""WO-R1F item 7d — Mode 1 keeps its strength with fewer blind spots.

Mode 1 ranks strong signals first for interpretation, while preserving every
matching N4 row. Ranking must never discard evidence.
"""

from __future__ import annotations

from pathlib import Path


def _hit(family: str, level: str = "", terms: list[str] | None = None) -> dict:
    return {
        "family": family,
        "level": level,
        "terms_list": terms or ["sdelete"],
        "file": f"{family}.csv",
        "line": "1",
    }


def test_a_crit_row_outranks_a_generic_needle_row():
    from nexus.langgraph.query_pack import _severity_rank

    assert _severity_rank(_hit("hayabusa", "crit")) == 0
    assert _severity_rank(_hit("hayabusa", "high")) == 0
    assert _severity_rank(_hit("mftecmd")) == 1


def test_a_rule_engine_row_outranks_a_keyword_row_even_unlevelled():
    from nexus.langgraph.query_pack import _severity_rank

    assert _severity_rank(_hit("chainsaw")) == 0
    assert _severity_rank(_hit("pecmd")) == 1


def test_severity_is_ranked_before_the_keyword_rank():
    from nexus.langgraph.query_pack import finalize_hits

    generic = _hit("mftecmd", "", ["sdelete"])         # strong keyword, weak row
    crit = _hit("hayabusa", "crit", ["unrelated"])     # weak keyword, crit row
    ordered = finalize_hits([generic, crit], ["sdelete"])
    assert ordered[0]["family"] == "hayabusa", ordered


def test_finalize_hits_keeps_every_row_and_ranks_critical_first():
    from nexus.langgraph import query_pack

    hits = [_hit(f"f{i}") for i in range(5)] + [_hit("hayabusa", "crit")]
    ranked = query_pack.finalize_hits(hits, ["sdelete"])
    assert len(ranked) == len(hits)
    assert ranked[0]["family"] == "hayabusa"
    assert not any("_cap_dropped_total" in hit for hit in ranked)


def test_finalize_hits_preserves_all_critical_rows():
    from nexus.langgraph import query_pack

    hits = [_hit("hayabusa", "crit"), _hit("chaini", "crit")]
    ranked = query_pack.finalize_hits(hits, ["sdelete"])
    assert len(ranked) == 2
    assert {hit["family"] for hit in ranked} == {"hayabusa", "chaini"}


def test_empty_pack_has_no_truncation_warning(tmp_path: Path, monkeypatch):
    from nexus.langgraph import query_pack

    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: ([], "test"))
    case = tmp_path / "CASE-CAP0001"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-CAP0001\n", encoding="utf-8")
    md = query_pack.build_query_pack_markdown(case)
    # No hits: the header is the ordinary no-match text, not a cap warning.
    assert "CAP:" not in md


def test_intake_can_set_the_interpretation_rounds(tmp_path: Path):
    """Item 7d: "the examiner can raise them in intake"."""
    from typer.testing import CliRunner

    from nexus.cli.main import app
    from nexus.config import settings

    # conftest redirects settings.cases_root per test; build the case there.
    case = settings.cases_root / "CASE-ROUND01"
    case.mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text(
        "case_id: CASE-ROUND01\nstatus: created\n", encoding="utf-8"
    )

    res = CliRunner().invoke(
        app, ["case", "intake", "--case", "CASE-ROUND01", "--interpret-rounds", "4"]
    )
    assert res.exit_code == 0, res.output
    body = (case / "CASE.yaml").read_text(encoding="utf-8")
    assert "interpret_rounds: '4'" in body or 'interpret_rounds: "4"' in body, body


def test_interpret_rounds_are_clamped(tmp_path: Path):
    from typer.testing import CliRunner

    from nexus.cli.main import app
    from nexus.config import settings

    case = settings.cases_root / "CASE-ROUND02"
    case.mkdir(parents=True, exist_ok=True)
    (case / "CASE.yaml").write_text(
        "case_id: CASE-ROUND02\nstatus: created\n", encoding="utf-8"
    )

    res = CliRunner().invoke(
        app, ["case", "intake", "--case", "CASE-ROUND02", "--interpret-rounds", "99"]
    )
    assert res.exit_code == 0, res.output
    body = (case / "CASE.yaml").read_text(encoding="utf-8")
    assert "interpret_rounds: '5'" in body or 'interpret_rounds: "5"' in body, body
