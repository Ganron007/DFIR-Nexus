"""The index does not read the lane's staging copies (index, 2026-10-11).

The lane copies ESE databases and their logs into staging folders (srum/workdir, bitsparser/workdir,
_staged/sru) so that the parsers can replay them. Those copies are not tool output. The index read the
raw logs as text rows: 11,051 documents on CASE-C5B04D31 (run RUN-20261011T084105445874Z-tools-b4c9add7).
Both index walks must skip them, and nothing else.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture()
def run_extractions(tmp_path, monkeypatch) -> Path:
    from nexus.langgraph import pipeline_runs

    extractions = tmp_path / "runs" / "RUN-1" / "extractions"
    files = {
        "srum/SrumECmd_AppResourceUseInfo_Output.csv": "a,b\n1,2\n",
        "srum/workdir/SRU03FBA.log": "binary-ish log\n",
        "srum/workdir/SRU.chk": "checkpoint\n",
        "bitsparser/bits.json": "[]\n",
        "bitsparser/workdir/edb.log": "replayed log\n",
        "_staged/sru/SRUDB.dat.log": "staged log\n",
        "workdir.csv": "a,b\n3,4\n",  # a file named like the folder is not a staging folder
    }
    for rel, text in files.items():
        p = extractions / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    monkeypatch.setattr(pipeline_runs, "resolve_tools_extractions", lambda case_dir, run_id="": extractions)
    return extractions


def _rels(paths, root: Path) -> set[str]:
    return {str(Path(p).relative_to(root)).replace("\\", "/") for p in paths}


def test_the_extraction_walk_skips_staging_copies_and_keeps_tool_output(tmp_path, run_extractions):
    from nexus.langgraph.query_pack import iter_extraction_files

    found = iter_extraction_files(tmp_path)
    rels = _rels([path for path, _root, _fam in found], run_extractions)
    assert rels == {
        "srum/SrumECmd_AppResourceUseInfo_Output.csv",
        "bitsparser/bits.json",
        "workdir.csv",
    }


def test_the_index_file_list_skips_staging_copies_too(tmp_path, run_extractions):
    from nexus.langgraph.case_index import iter_index_files

    rels = _rels(iter_index_files(tmp_path), run_extractions)
    assert "srum/workdir/SRU03FBA.log" not in rels
    assert "bitsparser/workdir/edb.log" not in rels
    assert "_staged/sru/SRUDB.dat.log" not in rels
    assert "srum/SrumECmd_AppResourceUseInfo_Output.csv" in rels


def test_the_predicate_names_only_the_staging_folders(tmp_path):
    from nexus.langgraph.query_pack import is_staging_copy

    root = tmp_path / "extractions"
    assert is_staging_copy(root / "srum" / "workdir" / "SRU.log", root)
    assert is_staging_copy(root / "_staged" / "sru" / "x.log", root)
    assert not is_staging_copy(root / "srum" / "out.csv", root)
    assert not is_staging_copy(root / "workdir.csv", root)
    assert not is_staging_copy(tmp_path / "elsewhere" / "workdir" / "x.log", root)
