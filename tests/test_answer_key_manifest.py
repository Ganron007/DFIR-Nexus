"""WO-V10 — the operator manifest as an answer key, scoped by SHA-256.

GATE-H uses random, unknown samples chosen by the operator, and such a sample is
often named after what it is. A key built from folder or file names would
therefore put the answer inside the case. The manifest labels by content hash
instead, so the evidence may be renamed freely, and the scorer matches it
against the case's own evidence registry.

The two required tests are `test_a_manifest_of_renamed_files_scores_only_their_techniques`
and `test_a_registered_file_with_no_entry_is_unlabelled`.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from nexus.validation.answer_keys import AnswerKey


def _write(path: Path, content: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return hashlib.sha256(content).hexdigest()


def _manifest(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "manifest.yaml"
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return path


def _case(tmp_path: Path, registered: dict[str, str]) -> Path:
    """A case dir whose evidence registry names the given hashes."""
    case = tmp_path / "cases" / "CASE-M"
    case.mkdir(parents=True)
    (case / "evidence.json").write_text(
        json.dumps([
            {"name": name, "path": f"/evidence/{name}", "sha256": digest}
            for digest, name in registered.items()
        ]),
        encoding="utf-8",
    )
    return case


def test_a_manifest_of_renamed_files_scores_only_their_techniques(tmp_path):
    """Three files renamed to neutral names score exactly their techniques."""
    # Neutral names: nothing in them says what the sample is.
    h1 = _write(tmp_path / "src" / "a.dat", b"powershell -enc ABC")
    h2 = _write(tmp_path / "src" / "b.dat", b"lsass dump via comsvcs")
    h3 = _write(tmp_path / "src" / "c.dat", b"cmd.exe /c whoami")

    manifest = _manifest(tmp_path, [
        {"sha256": h1, "techniques": ["T1059.001"], "notes": "step 1"},
        {"sha256": h2, "techniques": ["T1003.001"], "notes": "step 2"},
        {"sha256": h3, "entities": ["whoami.exe"]},
    ])
    key = AnswerKey.from_manifest(manifest)

    assert key.kind == "operator-manifest"
    assert key.techniques() == {"T1059.001", "T1003.001"}
    assert key.entities() == {"whoami.exe"}
    assert not key.excluded, key.excluded

    # Scoped to a case holding the same three files by hash: all three match.
    case = _case(tmp_path, {h1: "a.dat", h2: "b.dat", h3: "c.dat"})
    scoped = key.restrict_to(case)
    assert scoped.matched == 3
    assert scoped.techniques() == {"T1059.001", "T1003.001"}
    assert not scoped.unlabelled
    assert not scoped.ignored

    # The evidence may be RENAMED: same hashes, different names, same score.
    renamed = _case(tmp_path / "renamed", {h1: "sample-1", h2: "sample-2", h3: "sample-3"})
    rescored = key.restrict_to(renamed)
    assert rescored.techniques() == scoped.techniques()
    assert rescored.matched == 3

    # A file NOT in the case is ignored, and does not contribute a label.
    absent = AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": h1, "techniques": ["T1059.001"]},
        {"sha256": "0" * 64, "techniques": ["T9999"]},
    ]))
    scoped_absent = absent.restrict_to(case)
    assert scoped_absent.matched == 1
    assert scoped_absent.techniques() == {"T1059.001"}
    assert [i["sha256"] for i in scoped_absent.ignored] == ["0" * 64]


def test_a_registered_file_with_no_entry_is_unlabelled(tmp_path):
    """A registered file the manifest does not label is reported, never silent."""
    h1 = _write(tmp_path / "src" / "labelled.dat", b"labelled")
    h2 = _write(tmp_path / "src" / "unlabelled.dat", b"unlabelled")
    case = _case(tmp_path, {h1: "labelled.dat", h2: "unlabelled.dat"})

    key = AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": h1, "techniques": ["T1003"]},
    ]))
    scoped = key.restrict_to(case)

    assert scoped.matched == 1
    assert [u.sha256 for u in scoped.unlabelled] == [h2]
    assert scoped.unlabelled[0].names == ["unlabelled.dat"]
    # The reported shape is loadable, so a JSON report carries the reason.
    assert scoped.to_dict()["counts"]["unlabelled"] == 1


def test_an_unreadable_manifest_entry_is_reported_not_dropped(tmp_path):
    """Same rule as the file-derived keys: exclusions are stated, not silent."""
    h1 = _write(tmp_path / "src" / "ok.dat", b"ok")
    key = AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": h1, "techniques": ["T1003"]},
        {"sha256": "not-a-hash", "techniques": ["T1055"]},
        {"sha256": "1" * 64, "techniques": [], "entities": []},
        "not-a-mapping",
    ]))
    reasons = " | ".join(x.reason for x in key.excluded)
    assert "malformed sha256" in reasons
    assert "nothing to score" in reasons
    assert "not a mapping" in reasons
    assert key.techniques() == {"T1003"}, "a bad entry must not contribute a label"


def test_a_manifest_is_read_from_yaml_as_well_as_json(tmp_path):
    pytest.importorskip("yaml")
    path = tmp_path / "manifest.yaml"
    path.write_text(
        "entries:\n"
        f"  - sha256: {'a' * 64}\n"
        "    techniques: [T1059.001]\n"
        "    window: '2026-09-01..2026-09-02'\n",
        encoding="utf-8",
    )
    key = AnswerKey.from_manifest(path)
    assert key.techniques() == {"T1059.001"}
    assert key.entries[0].window == "2026-09-01..2026-09-02"


def test_a_manifest_that_is_not_a_mapping_is_refused(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError):
        AnswerKey.from_manifest(path)
    with pytest.raises(FileNotFoundError):
        AnswerKey.from_manifest(tmp_path / "missing.yaml")


def test_blind_evidence_neutralises_names_and_keeps_the_map_outside_the_case(tmp_path):
    """The optional companion script: neutral names, map outside the case.

    A sample named after its technique is the answer walking into the case. The
    hash is unchanged by the rename, so the manifest still scores it.
    """
    import importlib.util

    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "blind_evidence", repo / "scripts" / "blind_evidence.py"
    )
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    spec.loader.exec_module(module)  # type: ignore[union-attr]

    src = tmp_path / "src"
    original = b"T1003 lsass dump"
    digest = _write(src / "T1003_lsass_dump.evtx", original)

    out = tmp_path / "blinded"
    rows = module.blind([src / "T1003_lsass_dump.evtx"], out)
    assert len(rows) == 1
    assert rows[0]["blind"] == "sample-0001.evtx", "the stem must be neutral"
    assert rows[0]["sha256"] == digest, "a rename must not change the hash"
    assert (out / "sample-0001.evtx").read_bytes() == original
    assert "T1003" not in rows[0]["blind"]

    # The map is written beside the output, never inside a case.
    case = tmp_path / "cases" / "CASE-B"
    case.mkdir(parents=True)
    (case / "evidence.json").write_text("[]", encoding="utf-8")
    assert module.main([str(src), "--out", str(case / "blinded")]) == 2, (
        "writing the output inside a case must be refused"
    )


def test_restrict_to_does_not_mutate_the_original(tmp_path):
    h1 = _write(tmp_path / "src" / "x.dat", b"x")
    case = _case(tmp_path, {h1: "x.dat"})
    key = AnswerKey.from_manifest(_manifest(tmp_path, [
        {"sha256": h1, "techniques": ["T1003"]},
        {"sha256": "2" * 64, "techniques": ["T1055"]},
    ]))
    before = len(key.entries)
    key.restrict_to(case)
    assert len(key.entries) == before, "restrict_to must return a new key"
    assert not key.ignored and not key.unlabelled
