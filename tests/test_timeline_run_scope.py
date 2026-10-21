"""A run-bound timeline must only search the named run's tool outputs."""

from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph.timeline_merge import rebuild_case_timeline

OLD_RUN = "RUN-20261021T181816877304Z-tools-df2fcfda"
NEW_RUN = "RUN-20261021T200436383843Z-tools-a641ce8b"
EMPTY_RUN = "RUN-20261022T000000000000Z-tools-empty0001"


def _run(case_dir: Path, run_id: str, rows: str, *, previous: str = "") -> Path:
    run_dir = case_dir / "runs" / run_id
    extraction = run_dir / "extractions" / "evtxecmd"
    extraction.mkdir(parents=True)
    if rows:
        (extraction / "Events.csv").write_text(
            "Timestamp,Computer,EventId,Details\n" + rows,
            encoding="utf-8",
        )
    (run_dir / "manifest.json").write_text(json.dumps({
        "run_id": run_id,
        "mode": "tools",
        "status": "running",
        "parent_run_id": "",
        "previous_active_run_id": previous,
    }), encoding="utf-8")
    return run_dir / "extractions"


def test_timeline_reads_and_enriches_only_the_named_run(tmp_path, monkeypatch):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions
    from nexus.langgraph.query_pack import attach_hit_fields, n4_hits

    case_dir = tmp_path / "CASE-RUN-SCOPE"
    _run(
        case_dir,
        OLD_RUN,
        '2026-10-21 12:00:00,old-host,4688,"rundll32.exe R5_ONLY_MARKER"\n',
    )
    new = _run(
        case_dir,
        NEW_RUN,
        '2026-10-21 12:01:00,new-host,4688,"rundll32.exe R7_ONLY_MARKER"\n',
        previous=OLD_RUN,
    )
    (case_dir / "active_runs.json").write_text(
        json.dumps({"tools": NEW_RUN}), encoding="utf-8",
    )
    (case_dir / "CASE.yaml").write_text(
        "intake:\n  query_extra: rundll32\n", encoding="utf-8",
    )
    # A run-scoped lookup cannot use the case-wide index, even if configured.
    monkeypatch.setenv("NEXUS_N4_BACKEND", "elasticsearch")

    hits, backend = n4_hits(
        case_dir, ["rundll32"], (None, None), run_id=NEW_RUN,
    )
    enriched = attach_hit_fields(case_dir, hits, run_id=NEW_RUN)
    events = rebuild_case_timeline(case_dir, run_id=NEW_RUN)
    serialized = json.dumps(events)

    assert resolve_tools_extractions(case_dir, NEW_RUN) == new
    assert backend == "csv"
    assert enriched[0]["fields"]["Computer"] == "new-host"
    assert "R7_ONLY_MARKER" in enriched[0]["fields"]["Details"]
    assert "R5_ONLY_MARKER" not in json.dumps(enriched)
    assert "2026-10-21T12:01:00Z" in serialized
    assert "2026-10-21T12:00:00Z" not in serialized


def test_empty_named_tools_run_does_not_fall_back_to_previous_run(tmp_path):
    from nexus.langgraph.pipeline_runs import resolve_tools_extractions
    from nexus.langgraph.query_pack import n4_hits

    case_dir = tmp_path / "CASE-EMPTY-RUN"
    old = _run(
        case_dir,
        OLD_RUN,
        '2026-10-21 12:00:00,old-host,4688,"rundll32.exe R5_ONLY_MARKER"\n',
    )
    empty = _run(case_dir, EMPTY_RUN, "", previous=OLD_RUN)

    assert resolve_tools_extractions(case_dir, EMPTY_RUN) == empty
    hits, backend = n4_hits(
        case_dir, ["rundll32"], (None, None), run_id=EMPTY_RUN,
    )
    assert backend == "csv"
    assert hits == []
    assert old != empty
