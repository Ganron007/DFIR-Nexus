"""D285: a Magnet AXIOM case is read from its Case.mfdb, without writing to it (2026-10-18).

Sample S09 registers an AXIOM case folder; the importer pass read none of it and reported 43 of its files as of no
known format: the case database, its write-ahead log, AXIOM's search index, logs and attachment store. The tests run
on S09's own case where the sample is present (no AXIOM database small enough to keep in the repository exists).
"""
from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import pytest

from nexus.ingest.detect import detect_format
from nexus.ingest.df.axiom import AxiomCaseImporter, case_parts, find_axiom_cases, part_gate_rows
from nexus.ingest.schemas import ArtifactSource
from nexus.langgraph.evidence_archives import find_archives

REPO = Path(__file__).resolve().parents[1]
S09_CASE = REPO / "Evidence-files" / "_samples" / "S09" / "processed" / "Rocba_Email_Precooked"
pytestmark = pytest.mark.skipif(not (S09_CASE / "Case.mfdb").is_file(), reason="sample S09 is not on this host")


def _state(folder: Path) -> dict[str, tuple[int, int, str]]:
    out = {}
    for f in folder.glob("Case.mfdb*"):
        out[f.name] = (f.stat().st_size, f.stat().st_mtime_ns, hashlib.sha256(f.read_bytes()).hexdigest())
    return out


def test_every_hit_is_read_from_a_copy_and_the_case_is_not_written():
    db = S09_CASE / "Case.mfdb"
    before = _state(S09_CASE)
    assert detect_format(db) == ArtifactSource.AXIOM
    rows = list(AxiomCaseImporter().parse(db))
    assert _state(S09_CASE) == before, "the database, its log and its index are as they were"
    by_artifact = Counter(r.raw["artifact"] for r in rows)
    # AXIOM's own summary of this case: 1,474 emails, 330 attachments, 282 identifiers, 179 appointments,
    # 54 pictures, 21 contacts (Case Information.txt, "Final results of search").
    assert by_artifact == {"Outlook Emails": 1474, "Email Attachments": 330, "Identifiers - People": 282,
                           "Outlook Appointments": 179, "Pictures": 54, "Outlook Contacts": 21}
    mail = [r for r in rows if r.raw["artifact"] == "Outlook Emails"]
    assert not any(r.ts_synthesized for r in mail) and all(r.timestamp.tzinfo for r in mail)
    assert all(not k.startswith("_") for r in rows for k in r.raw), "AXIOM's internal fields and blobs are not read"


def test_the_case_folder_s_own_files_are_named_and_kept_out_of_the_expansion():
    [db] = find_axiom_cases([str(S09_CASE.parent)])
    parts = case_parts(db)
    names = {f.relative_to(S09_CASE).as_posix() for f in parts}
    assert {"Case.mfdb-wal", "Case.mfdb-shm", "Case.timeline", "Case Information.xml", "artifacts.log"} <= names
    assert any(n.startswith("index/ArtifactHits/") for n in names)
    assert any(n.endswith(".attachments") for n in names)
    archives = find_archives([str(S09_CASE)])
    assert archives and all(a in parts for a in archives), "AXIOM's log archive is its own, not evidence to expand"
    rows = part_gate_rows(db, parts)
    assert {r["status"] for r in rows} == {"SKIP"} and all("Magnet AXIOM case" in r["reason"] for r in rows)
