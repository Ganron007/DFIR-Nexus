"""The targeted re-index counts what the current readers produce for the files named, without writing anything.

The count is taken on a temporary case that holds one real public-sample output (tests/fixtures/d117), so the test
needs no Elasticsearch. Applying the re-index is exercised on the case index, not here.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from nexus.langgraph.targeted_reindex import new_documents

FIX = Path(__file__).resolve().parent / "fixtures" / "d117"


def test_new_documents_counts_what_the_readers_produce_without_writing(tmp_path: Path):
    case = tmp_path / "CASE-REINDEX1"
    eve = case / "runs" / "RUN-T" / "extractions" / "suricata" / "eve.json"
    eve.parent.mkdir(parents=True)
    shutil.copyfile(FIX / "suricata" / "conn-size" / "eve.json", eve)
    records = sum(1 for line in eve.read_text(encoding="utf-8").splitlines() if line.strip())
    assert new_documents(case, {"suricata/eve.json"}) == {"suricata/eve.json": records}


def test_a_file_that_is_not_in_the_case_counts_zero(tmp_path: Path):
    case = tmp_path / "CASE-REINDEX2"
    (case / "runs" / "RUN-T" / "extractions").mkdir(parents=True)
    assert new_documents(case, {"vol/vol-windows-missing.txt"}) == {"vol/vol-windows-missing.txt": 0}
