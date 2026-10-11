"""Volatility 3 on Windows memory (WO-TA item 6; operator decision 2026-10-11: run on Windows, not SIFT).

Each plugin of the pack, and each registry printkey, is one job on the Windows host through the pinned
``vol3`` wrapper, in the ``vol`` family. The image is read in place. Without the wrapper every image gets
a named SKIP, so the gate shows the gap.
"""

from __future__ import annotations

from pathlib import Path

from nexus.langgraph import tool_lane


def _touch(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_each_plugin_and_printkey_is_one_windows_vol_job_read_in_place(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_MEMORY_MIN_BYTES", 4)
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: key == "vol3")
    image = _touch(tmp_path / "evidence" / "rd01-memory.img", "MEMORYIMAGE")

    jobs = tool_lane._memory_vol3_jobs([str(image)], tmp_path / "extractions")

    plugin_jobs = [j for j in jobs if "windows.registry.printkey" not in j.argv]
    key_jobs = [j for j in jobs if "windows.registry.printkey" in j.argv]
    assert [j.argv[-1] for j in plugin_jobs] == [name for name, _floor in tool_lane._VOL_WINDOWS_PLUGINS]
    assert len(key_jobs) == len(tool_lane._VOL_WINDOWS_REGISTRY_KEYS)
    for job in jobs:
        assert job.host == "windows" and job.tool == "vol" and job.status == "PENDING"
        assert job.argv[0] == "vol3"
        assert job.argv[1:3] == ["-f", str(image)]
        assert job.argv[3:5] == ["-r", "jsonl"]
        assert job.timeout >= 1800
    assert image.read_text(encoding="utf-8") == "MEMORYIMAGE"


def test_without_the_wrapper_each_image_is_a_named_skip(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_MEMORY_MIN_BYTES", 4)
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: False)
    image = _touch(tmp_path / "evidence" / "rd01-memory.img", "MEMORYIMAGE")

    jobs = tool_lane._memory_vol3_jobs([str(image)], tmp_path / "extractions")

    assert len(jobs) == 1
    assert jobs[0].status == "SKIP" and jobs[0].argv == []
    assert "vol3 not installed" in jobs[0].reason


def test_a_file_that_is_not_memory_gets_no_vol3_job(tmp_path, monkeypatch):
    monkeypatch.setattr(tool_lane, "_MEMORY_MIN_BYTES", 4)
    monkeypatch.setattr(tool_lane, "_windows_tool_available", lambda key: True)
    notes = _touch(tmp_path / "evidence" / "notes.txt", "not memory")

    assert tool_lane._memory_vol3_jobs([str(notes)], tmp_path / "extractions") == []


def test_the_vol3_wrapper_is_in_the_windows_catalog_under_its_own_name():
    from nexus.tools import windows

    assert windows._WIN_CATALOG["vol3"]["name"] == "run-vol3.py"
