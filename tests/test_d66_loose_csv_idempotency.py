"""Tests for D66 loose CSV idempotency and indexing walks.

D66: place_loose_csvs leaves original loose CSVs in ingest/ for preservation.
The indexer (iter_index_files) and extraction walks (iter_extraction_files)
must skip the root copy so rows are not duplicated and the file is indexed only
under its assigned family folder.
"""

from __future__ import annotations

from pathlib import Path

from nexus.ingest.fingerprint import is_placed_loose_csv, place_loose_csvs
from nexus.langgraph.case_index import iter_index_files
from nexus.langgraph.query_pack import iter_extraction_files


def test_d66_loose_csv_preserved_and_idempotent(tmp_path: Path):
    ingest = tmp_path / "ingest"
    ingest.mkdir()

    loose_csv = ingest / "prefetch.csv"
    content = "ExecutableName,RunCount,LastRun\npowershell.exe,1,2026-01-01\n"
    loose_csv.write_text(content, encoding="utf-8")

    # First run of place_loose_csvs
    placed1 = place_loose_csvs(ingest)
    assert len(placed1) == 1
    placed_path = placed1[0]
    assert placed_path.parent.name == "pecmd"
    assert placed_path.is_file()

    # D66: Original loose CSV must NOT be unlinked
    assert loose_csv.is_file()
    assert loose_csv.read_text(encoding="utf-8") == content

    # Re-running place_loose_csvs is idempotent
    placed2 = place_loose_csvs(ingest)
    assert len(placed2) == 1
    assert placed2[0] == placed_path
    assert loose_csv.is_file()


def test_d66_is_placed_loose_csv_detection(tmp_path: Path):
    ingest = tmp_path / "ingest"
    ingest.mkdir()

    loose_csv = ingest / "prefetch.csv"
    loose_csv.write_text("ExecutableName,RunCount,LastRun\npowershell.exe,1,2026-01-01\n", encoding="utf-8")

    # Before placement: not placed
    assert not is_placed_loose_csv(loose_csv, ingest)

    # Place it
    place_loose_csvs(ingest)

    # After placement: loose CSV at root is marked as placed
    assert is_placed_loose_csv(loose_csv, ingest)

    # Placed CSV in subfolder is NOT marked as loose-placed
    placed_csv = ingest / "pecmd" / "prefetch.csv"
    assert not is_placed_loose_csv(placed_csv, ingest)


def test_d66_iter_extraction_and_index_files_skip_root_duplicate(tmp_path: Path):
    case_dir = tmp_path / "CASE-D66TEST"
    ingest = case_dir / "ingest"
    ingest.mkdir(parents=True)

    loose_csv = ingest / "prefetch.csv"
    loose_csv.write_text("ExecutableName,RunCount,LastRun\npowershell.exe,1,2026-01-01\n", encoding="utf-8")

    # Place into pecmd
    place_loose_csvs(ingest)
    assert (ingest / "pecmd" / "prefetch.csv").is_file()
    assert loose_csv.is_file()

    # iter_extraction_files should only yield the placed copy under pecmd, not the loose root copy
    extractions = iter_extraction_files(case_dir)
    extracted_paths = [p for p, _root, _fam in extractions]
    assert ingest / "pecmd" / "prefetch.csv" in extracted_paths
    assert loose_csv not in extracted_paths

    families = {p.name: fam for p, _root, fam in extractions}
    assert families["prefetch.csv"] == "pecmd"

    # iter_index_files should also skip the root copy
    indexed_paths = iter_index_files(case_dir)
    assert ingest / "pecmd" / "prefetch.csv" in indexed_paths
    assert loose_csv not in indexed_paths
