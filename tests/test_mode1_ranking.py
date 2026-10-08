"""WO-R1F item 7d — Mode 1 keeps its strength with fewer blind spots.

Mode 1 works because the deterministic scan and the digest put the strong signals
in front of the LLM. Its limits were a 400-hit cap (the SC1 run was flagged
TRUNCATED and a crit detection sat below the cut), 8 rows x 300 chars, and a
fixed 3 rounds.
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


def test_the_cap_records_what_it_dropped_and_whether_it_was_severe(monkeypatch):
    from nexus.langgraph import query_pack

    monkeypatch.setattr(query_pack, "_MAX_HITS_TOTAL", 3)
    hits = [_hit(f"f{i}") for i in range(5)] + [_hit("hayabusa", "crit")]
    kept = query_pack.finalize_hits(hits, ["sdelete"])
    assert len(kept) == 3
    # The crit row survived; the 3 dropped rows are all generic.
    assert kept[0]["family"] == "hayabusa"
    assert kept[0]["_cap_dropped_total"] == 3
    assert kept[0]["_cap_dropped_severe"] == []


def test_the_cap_names_severe_rows_it_had_to_drop(monkeypatch):
    from nexus.langgraph import query_pack

    monkeypatch.setattr(query_pack, "_MAX_HITS_TOTAL", 1)
    hits = [_hit("hayabusa", "crit"), _hit("chaini", "crit")]
    kept = query_pack.finalize_hits(hits, ["sdelete"])
    assert len(kept) == 1
    assert kept[0]["_cap_dropped_severe"], kept[0]


def test_the_pack_header_names_the_dropped_severe_rows(tmp_path: Path, monkeypatch):
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
