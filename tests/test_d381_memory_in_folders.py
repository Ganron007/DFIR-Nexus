"""D381 (2026-10-24): the memory jobs find an image inside a registered folder or an archive's expansion.

The lane passes folders as often as files: tiny case T22 registers ``memory/`` (holding ``mem.zip``), and the archive
expansion adds ``evidence/_expanded/<name>-<digest>/``. The memory jobs planned only paths that were themselves image
files, so T22's ``mem.raw`` would have had none. The one rule (memory suffix, at least 512 MiB) is unchanged; only
where it looks. The image here is an empty 512 MiB file: these are planning tests, and no tool reads it.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph import tool_lane as tl

REPO = Path(__file__).resolve().parents[1]
TINY = REPO / "Evidence-files" / "_tiny"


@pytest.fixture(scope="module")
def expansion(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("case") / "evidence" / "_expanded" / "mem-0123456789ab"
    root.mkdir(parents=True)
    with (root / "mem.raw").open("wb") as fh:
        fh.truncate(tl._MEMORY_MIN_BYTES)
    (root / "small.raw").write_bytes(b"\0" * 4096)
    return root


def test_an_image_inside_an_expansion_folder_gets_vol3_and_memprocfs_jobs(expansion, tmp_path, monkeypatch):
    monkeypatch.setattr(tl, "_windows_tool_available", lambda _key: True)
    image = expansion / "mem.raw"
    assert tl._memory_images([str(expansion)]) == [image]
    vol = tl._memory_vol3_jobs([str(expansion)], tmp_path / "extractions")
    mpf = tl._memory_image_jobs([str(expansion)], tmp_path / "extractions")
    assert vol and all(j.tool == "vol" and str(image) in j.argv for j in vol)
    assert [j.tool for j in mpf] == ["memprocfs"] and str(image) in mpf[0].argv


def test_an_image_reached_twice_is_planned_once(expansion):
    image = expansion / "mem.raw"
    assert tl._memory_images([str(image), str(expansion), str(expansion.parent)]) == [image]


def test_the_rule_is_unchanged_a_small_file_or_a_disk_format_is_no_image(tmp_path):
    folder = tmp_path / "disks"
    folder.mkdir()
    with (folder / "disk.vhdx").open("wb") as fh:  # a disk format, whatever its size
        fh.truncate(tl._MEMORY_MIN_BYTES)
    (folder / "leftover.mem").write_bytes(b"\0" * 4096)
    assert tl._memory_images([str(folder)]) == []


@pytest.mark.skipif(not TINY.is_dir(), reason="the tiny cases are not staged on this host")
def test_no_staged_tiny_case_holds_anything_the_rule_takes_for_an_image():
    """Measured before and after D381 (2026-10-24): none of the 22 staged folders, the drive trees T01, T03, T04,
    T05 and T07 included, gets a memory job; T22's image is inside its zip until the lane expands it."""
    for case in sorted(TINY.iterdir()):
        assert tl._memory_images([str(p) for p in case.iterdir()]) == [], case.name
