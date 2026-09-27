"""Per-file parser jobs must not share an output name — regression.

Found by the debug-mode format sweep: registering 12 ``.pf`` files produced 12
PECmd jobs, all ``OK``, and **one** row of evidence. Zimmerman tools write
``--csvf <name>`` verbatim, so a fixed name means every job after the first
overwrites the previous one and 11 of 12 files' rows are silently lost. Silent
evidence loss is exactly the class this project forbids, and the ledger said
everything succeeded.

The same applies to ``.lnk``, ``.mft``, Amcache, hives and AppCompat, all of
which are scheduled one-file-per-job.
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.tool_lane import _plan_single_artifact

EXTRACTIONS = Path("extractions_out")


def _csvf(jobs) -> list[str]:
    out = []
    for job in jobs:
        for i, arg in enumerate(job.argv):
            if arg == "--csvf" and i + 1 < len(job.argv):
                out.append(job.argv[i + 1])
    return out


def test_prefetc_jobs_get_distinct_output_names(tmp_path):
    """Three .pf files, three jobs, three distinct CSV names."""
    src = tmp_path / "prefetch"
    src.mkdir()
    for name in ("ACCOUNTSCONTROLHOST.EXE-00EAE375.pf", "ACRORD32.EXE-F7519AA2.pf", "ADOBEARM.EXE-F9223367.pf"):
        (src / name).write_bytes(b"\x17PfsS")

    jobs = _plan_single_artifact(src / "ACCOUNTSCONTROLHOST.EXE-00EAE375.pf", tmp_path / "extractions")
    other = _plan_single_artifact(src / "ACRORD32.EXE-F7519AA2.pf", tmp_path / "extractions")
    third = _plan_single_artifact(src / "ADOBEARM.EXE-F9223367.pf", tmp_path / "extractions")

    names = _csvf(jobs) + _csvf(other) + _csvf(third)
    assert len(names) == 3
    assert len(set(names)) == 3, f"output names collide: {names}"
    assert all(n.endswith(".csv") for n in names)


def test_lnk_jobs_get_distinct_output_names(tmp_path):
    for n in ("Airwolf-ARL.lnk", "ADAMANTIUM-Background.lnk"):
        (tmp_path / n).write_bytes(b"L\x00\x00\x00")
    a = _csvf(_plan_single_artifact(tmp_path / "Airwolf-ARL.lnk", tmp_path / "extractions"))
    b = _csvf(_plan_single_artifact(tmp_path / "ADAMANTIUM-Background.lnk", tmp_path / "extractions"))
    assert a and b
    assert a[0] != b[0], f"output names collide: {a[0]} == {b[0]}"


def test_same_stem_from_two_roots_does_not_collide(tmp_path):
    """Two evidence roots can each hold the same filename (two staged machines).

    On a case-insensitive filesystem these are distinct *paths*, so the stem alone
    is not a unique key - a path-derived suffix has to break the tie.
    """
    a_root = tmp_path / "hostA" / "config"
    b_root = tmp_path / "hostB" / "config"
    a_root.mkdir(parents=True)
    b_root.mkdir(parents=True)
    (a_root / "NTUSER.DAT").write_bytes(b"regf")
    (b_root / "NTUSER.DAT").write_bytes(b"regf")

    a = _csvf(_plan_single_artifact(a_root / "NTUSER.DAT", tmp_path / "extractions"))
    b = _csvf(_plan_single_artifact(b_root / "NTUSER.DAT", tmp_path / "extractions"))
    assert a and b, "no --csvf emitted for a hive"
    assert a[0] != b[0], f"same-stem sources still collide: {a[0]} vs {b[0]}"


def test_output_name_is_filesystem_safe(tmp_path):
    """A source name with spaces and odd characters must still produce a usable name."""
    weird = tmp_path / "ACME Prog v1.2 (final).pf"
    weird.write_bytes(b"\x17PfsS")
    names = _csvf(_plan_single_artifact(weird, tmp_path / "extractions"))
    assert names, "no --csvf emitted"
    name = names[0]
    assert not any(ch in name for ch in '<>:"/\\|?*')
    assert name.endswith(".csv")
    assert len(name) <= 80, f"name too long: {name}"


def test_same_file_planned_twice_gets_the_same_name(tmp_path):
    """Re-planning the same source must be idempotent, or a re-run writes a new file."""
    src = tmp_path / "X.EXE-1.pf"
    src.write_bytes(b"\x17PfsS")
    a = _csvf(_plan_single_artifact(src, tmp_path / "extractions"))
    b = _csvf(_plan_single_artifact(src, tmp_path / "extractions"))
    assert a[0] == b[0]


def test_batch_folder_path_keeps_the_shared_name(tmp_path):
    """The folder path is one invocation over many files, so a fixed name is correct there."""
    folder = tmp_path / "prefetch"
    folder.mkdir()
    for n in ("A.EXE-1.pf", "B.EXE-2.pf", "C.EXE-3.pf"):
        (folder / n).write_bytes(b"\x17PfsS")
    jobs = _plan_single_artifact(folder, tmp_path / "extractions")
    assert len(jobs) == 1, "a folder should be one job, not one per file"
    assert _csvf(jobs) == ["prefetch.csv"]
