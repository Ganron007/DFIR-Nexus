"""WO-TA lane coverage on real file names (tool review, 2026-10-09; implementer, 2026-10-11).

Each test names the defect it guards, so a regression reads as the original finding:

* DeepBlueCLI ran on a directory and on every .evtx on the volume (361 jobs). It now runs
  once per channel that its own switch handles (DeepBlue.ps1 lines 672-680).
* A stdout-only capture was promoted to the run's extractions root, which the indexer
  reads as a family of its own. It now lands in the job's family folder.
* RECmd's user-hive batch was UserActivity.reb (45 key paths on tdungan's NTUSER.DAT),
  not DFIRBatch.reb (224 key paths on the same hive).
"""
from __future__ import annotations

from pathlib import Path

from nexus.langgraph.tool_lane import (
    DEEPBLUE_LOGNAMES,
    ToolJob,
    _deepblue_channel_files,
    _find_recmd_user_batch,
    _promotion_dir,
    lineage_version,
)

# The file names Windows writes for the channels DeepBlueCLI handles, plus the ones it does not.
CHANNEL_FILES = [
    "Security.evtx",
    "System.evtx",
    "Application.evtx",
    "Microsoft-Windows-AppLocker%4EXE and DLL.evtx",
    "Microsoft-Windows-PowerShell%4Operational.evtx",
    "Microsoft-Windows-Sysmon%4Operational.evtx",
    "Microsoft-Windows-WMI-Activity%4Operational.evtx",
]
NOT_HANDLED = [
    "Windows PowerShell.evtx",  # DeepBlue exits with "Logic error 3" on it
    "Amazon EC2Launch.evtx",
    "EC2ConfigService.evtx",
    "Microsoft-Windows-TaskScheduler%4Operational.evtx",
]


def _logs(tmp_path: Path, names: list[str]) -> Path:
    logs = tmp_path / "H" / "C" / "Windows" / "System32" / "winevt" / "Logs"
    logs.mkdir(parents=True)
    for name in names:
        (logs / name).write_bytes(b"ElfFile\x00")
    return tmp_path / "H" / "C"


def test_deepblue_runs_once_per_channel_its_switch_handles(tmp_path):
    root = _logs(tmp_path, CHANNEL_FILES + NOT_HANDLED)

    picked = sorted(p.name for p in _deepblue_channel_files(root))

    assert picked == sorted(CHANNEL_FILES), "one file per DeepBlue channel, nothing else"


def test_deepblue_channel_list_is_the_switch_in_deepblue_ps1():
    # DeepBlue.ps1 lines 672-680: the LogName values its switch maps (WMI-Activity included).
    assert "Microsoft-Windows-WMI-Activity/Operational" in DEEPBLUE_LOGNAMES
    assert "Windows PowerShell" not in DEEPBLUE_LOGNAMES
    assert len(DEEPBLUE_LOGNAMES) == 7


def test_a_stdout_capture_is_promoted_into_its_own_family_folder(tmp_path):
    root = tmp_path / "extractions"
    job = ToolJob(
        host="windows", tool="lecmd", purpose="LNK",
        argv=["lecmd", "-d", str(tmp_path / "Recent"), "--csv", str(root / "lecmd")],
    )

    assert _promotion_dir(job, root) == root / "lecmd"


def test_a_job_with_no_output_folder_is_promoted_into_a_folder_named_for_its_tool(tmp_path):
    root = tmp_path / "extractions"
    job = ToolJob(host="windows", tool="strings", purpose="strings", argv=["strings", "x.exe"])

    assert _promotion_dir(job, root) == root / "strings"


def test_no_run_root_means_no_promotion_folder(tmp_path):
    job = ToolJob(host="windows", tool="strings", purpose="strings", argv=["strings"])

    assert _promotion_dir(job, None) is None


def test_the_user_hive_batch_is_dfirbatch(monkeypatch):
    batch = _find_recmd_user_batch()

    assert batch is not None and batch.name == "DFIRBatch.reb"


def test_lineage_version_reads_the_declared_version_fields():
    assert lineage_version({"version": "2.0"}) == "2.0"
    assert lineage_version({"file_version": "1.2.3.4"}) == "1.2.3.4"
    assert lineage_version({"product_version": "9"}) == "9"
    assert lineage_version({"version_source": "undeclared"}) == ""
    assert lineage_version({}) == ""
