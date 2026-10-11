"""A standalone binary is versioned by its pinned hash when it has no version resource (2026-10-11).

Reproduced on CASE-C5B04D31: mplog, dhparser and sidr are standalone executables with no version resource,
so every row they wrote recorded only the SHA-256 (``version_source: "sha256-only"``). The pin file records
the version each binary was fetched and verified at, by that same hash, so the lineage now carries it.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

PINNED = {
    "695555a3f493eddeb02976d66a37de932c04150ad3abb561e1b9480c188cfcb3": "v1.0",  # mplog_parser.exe
    "989038da175c80bee12b59427bc01c57347cfe168fe911e2b9669ef291dfafe6": "v1.0.1",  # dhparser.exe
    "634be2a03263f0c83cc6ca5dfb1a582f3072bbc320490418dcb0dcebe0474c97": "v0.9.2",  # sidr.exe
}


def test_the_pin_file_names_the_version_of_each_pinned_standalone_tool():
    from nexus.tools import lineage

    for sha, version in PINNED.items():
        assert lineage.pinned_version(sha) == version
    assert lineage.pinned_version(sha.upper()) == version, "the pin file's hashes are upper-case"


def test_an_unpinned_or_empty_hash_names_no_version():
    from nexus.tools import lineage

    assert lineage.pinned_version("00" * 32) == ""
    assert lineage.pinned_version("") == ""


def _standalone(tmp_path: Path) -> tuple[Path, str]:
    binary = tmp_path / "standalone_tool.exe"
    binary.write_bytes(b"MZ-less standalone tool body, not a version resource\n" * 64)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def test_a_standalone_binary_gets_its_pinned_version_from_its_hash(tmp_path, monkeypatch):
    from nexus.tools import lineage

    binary, sha = _standalone(tmp_path)
    pins = tmp_path / "VERSIONS.txt"
    pins.write_text(f"header\nstandalone\tv2.1\thttps://example.invalid/tool.exe\t{sha.upper()}\tMIT\n",
                    encoding="utf-8")
    monkeypatch.setattr(lineage, "PINS_FILE", pins)

    row = lineage.binary_lineage(binary, cache=False)

    assert row["binary_sha256"] == sha
    assert row["version"] == "v2.1"
    assert row["version_source"] == "pinned-versions-file"
    assert row["file_version"] == "", "the PE resource is still reported as empty, not replaced"


def test_a_binary_whose_hash_is_not_pinned_stays_sha256_only(tmp_path, monkeypatch):
    from nexus.tools import lineage

    binary, _sha = _standalone(tmp_path)
    pins = tmp_path / "VERSIONS.txt"
    pins.write_text("header\nother\tv9.9\thttps://example.invalid/x\t" + "ab" * 32 + "\tMIT\n",
                    encoding="utf-8")
    monkeypatch.setattr(lineage, "PINS_FILE", pins)

    row = lineage.binary_lineage(binary, cache=False)

    assert row["version"] == ""
    assert row["version_source"] == "sha256-only", "never a guess"


def test_a_real_pinned_tool_is_versioned_from_its_own_binary():
    from nexus.tools import lineage

    binary = Path(lineage.__file__).resolve().parents[3] / "tools" / "windows" / "extra" / "sidr.exe"
    if not binary.is_file():
        pytest.skip("sidr.exe is not installed on this host (tools/windows/extra)")

    row = lineage.binary_lineage(binary, cache=False)

    assert row["binary_sha256"] == "634be2a03263f0c83cc6ca5dfb1a582f3072bbc320490418dcb0dcebe0474c97"
    assert row["version"] == "v0.9.2"
    assert row["version_source"] == "pinned-versions-file"
