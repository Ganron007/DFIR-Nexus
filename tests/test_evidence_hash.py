"""Custody: one evidence hash rule, and what could not be read is recorded, never dropped.

The registry used to abort on the first unreadable entry. Registering the operator's H:\
failed on ``H:\System Volume Information`` (PermissionError), so no digest could be recorded
at all. The rule now records every unreadable file or directory with its reason, as a line
of the manifest, so the digest commits to the fact that it was not hashed.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from nexus.case import evidence_service
from nexus.case.evidence_service import hash_evidence_path, hash_evidence_tree


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(lines: list[str]) -> str:
    manifest = hashlib.sha256()
    for line in sorted(lines, key=lambda item: item.split("\0", 1)[0]):
        manifest.update(line.encode())
    return manifest.hexdigest()


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "evidence"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_bytes(b"alpha")
    (root / "sub" / "b.bin").write_bytes(b"bravo!")
    return root


def test_a_readable_tree_keeps_the_registry_manifest_format(tmp_path):
    root = _tree(tmp_path)
    expected = _manifest([
        f"a.txt\0{len(b'alpha')}\0{_sha(b'alpha')}\n",
        f"sub/b.bin\0{len(b'bravo!')}\0{_sha(b'bravo!')}\n",
    ])
    result = hash_evidence_tree(root)
    assert result.digest == expected
    assert (result.files, result.total_bytes, result.unreadable) == (2, 11, ())
    assert hash_evidence_path(root) == (expected, 2, 11)


def test_an_unreadable_file_is_recorded_with_its_reason_and_not_dropped(tmp_path, monkeypatch):
    root = _tree(tmp_path)
    (root / "locked.bin").write_bytes(b"secret")
    real_hash = evidence_service._hash_file

    def _hash(path: Path) -> str:
        if path.name == "locked.bin":
            raise PermissionError(13, "Access is denied", str(path))
        return real_hash(path)

    monkeypatch.setattr(evidence_service, "_hash_file", _hash)
    result = hash_evidence_tree(root)

    assert [item["path"] for item in result.unreadable] == ["locked.bin"]
    assert "PermissionError" in result.unreadable[0]["reason"]
    assert result.files == 2, "the unreadable file is not counted as hashed"
    readable_only = _manifest([
        f"a.txt\0{len(b'alpha')}\0{_sha(b'alpha')}\n",
        f"sub/b.bin\0{len(b'bravo!')}\0{_sha(b'bravo!')}\n",
    ])
    assert result.digest != readable_only, "the digest commits to the skipped entry"
    assert result.digest == _manifest([
        f"a.txt\0{len(b'alpha')}\0{_sha(b'alpha')}\n",
        f"locked.bin\0UNREADABLE\0{result.unreadable[0]['reason']}\n",
        f"sub/b.bin\0{len(b'bravo!')}\0{_sha(b'bravo!')}\n",
    ])


def test_an_unlistable_directory_is_recorded_and_the_walk_continues(tmp_path, monkeypatch):
    root = _tree(tmp_path)
    locked = root / "System Volume Information"
    locked.mkdir()
    (locked / "inside.bin").write_bytes(b"hidden")
    real_scandir = os.scandir

    def _scandir(path):
        if Path(os.fspath(path)).name == "System Volume Information":
            raise PermissionError(13, "Access is denied", os.fspath(path))
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", _scandir)
    result = hash_evidence_tree(root)

    assert [item["path"] for item in result.unreadable] == ["System Volume Information"]
    assert result.files == 2, "the walk went on past the locked directory"
    assert "inside.bin" not in " ".join(item["path"] for item in result.unreadable)


def test_the_legacy_manager_hash_is_the_same_rule(tmp_path, monkeypatch):
    """One rule: the flat-JSON manager and the registry produce the same digest, including
    when an entry is unreadable."""
    from nexus.case_manager import _hash_evidence_path

    root = _tree(tmp_path)
    real_hash = evidence_service._hash_file

    def _hash(path: Path) -> str:
        if path.name == "a.txt":
            raise PermissionError(13, "Access is denied", str(path))
        return real_hash(path)

    monkeypatch.setattr(evidence_service, "_hash_file", _hash)
    assert _hash_evidence_path(root) == hash_evidence_path(root)
