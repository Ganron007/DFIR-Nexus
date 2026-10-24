"""TA-Z (TIER1-WORK-ORDERS 11.12, D376): the lane runs the pinned Zimmerman .NET 10 builds, and MFTECmd parses $LogFile.

Operator decision OD-T13 (2026-10-24): MFTECmd 2026.10 parses `$LogFile` itself (`-f $LogFile`, with `-m $MFT` to
resolve paths; pinned MFTECmd README at 2919ded, "$LogFile"), so LogFileParser is no longer planned. Its CSV is still
recognised when an examiner registers one.

The header fixtures are the first line of MFTECmd 2026.10.2's own output on tiny case T06 (2026-10-24), byte for byte.
The real-path tests run the installed MFTECmd on T06's staged `$LogFile`, `$J` and `$MFT` in place; they skip where the
staged evidence or the tool is absent, and nothing from the evidence is copied into the repository.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from nexus.ingest.fingerprint import family_for_csv_header
from nexus.langgraph import tool_lane as tl
from nexus.langgraph.case_index import _index_header, _open_text_auto, iter_indexable_rows
from nexus.langgraph.mft_join import TOOL_PARENT_SOURCE, resolve_usn_row
from nexus.langgraph.timestamps import NO_EVENT_TIME_FIELD, extract_event_ts
from nexus.tools import windows as win

REPO = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / "fixtures"
T06 = REPO / "Evidence-files" / "_tiny" / "T06" / "ntfs"
PINS = REPO / "devtools" / "runbook" / "zimmerman-net10.json"


def _write(path: Path, head: bytes, size: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.write(head)
        fh.truncate(size)
    return path


def _volume(root: Path, *, mft: bool = True) -> Path:
    _write(root / "$LogFile", b"RSTR", 8192)
    _write(root / "$Extend" / "$J", b"\x60\x00\x00\x00", 8192)
    if mft:
        _write(root / "$MFT", b"FILE0", 8192)
    return root


def _after(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


def _mftecmd_jobs(jobs, name: str):
    return [j for j in jobs if j.tool == "mftecmd" and j.argv and Path(_after(j.argv, "-f")).name == name]


def test_a_logfile_is_parsed_by_mftecmd_with_the_volumes_mft(tmp_path):
    root = _volume(tmp_path / "vol")
    jobs = tl._plan_single_artifact(root / "$LogFile", tmp_path / "run" / "extractions")
    assert [j.tool for j in jobs] == ["mftecmd"]
    argv = jobs[0].argv
    assert _after(argv, "-f") == str(root / "$LogFile")
    assert _after(argv, "-m") == str(root / "$MFT")
    assert Path(_after(argv, "--csv")).name == "mftecmd-logfile"
    assert _after(argv, "--csvf").endswith(".csv")


def test_a_logfile_without_its_mft_is_parsed_without_m(tmp_path):
    root = _volume(tmp_path / "vol", mft=False)
    jobs = tl._plan_single_artifact(root / "$LogFile", tmp_path / "run" / "extractions")
    assert [j.tool for j in jobs] == ["mftecmd"]
    assert "-m" not in jobs[0].argv


def test_a_usn_journal_under_extend_takes_the_mft_of_the_volume_root(tmp_path):
    root = _volume(tmp_path / "vol")
    jobs = tl._plan_single_artifact(root / "$Extend" / "$J", tmp_path / "run" / "extractions")
    assert [j.tool for j in jobs] == ["mftecmd"]
    assert _after(jobs[0].argv, "-m") == str(root / "$MFT")
    assert Path(_after(jobs[0].argv, "--csv")).name == "mftecmd-usn"  # where its -m by-product is recognised


def test_the_m_by_product_mft_table_is_left_out_only_in_the_m_job_folders():
    """With -m, MFTECmd also exports the $MFT under its default name (pinned README); on T06 that was two more
    byte-identical copies of the run's 303 MB $MFT table. An examiner's default-named output under mftecmd/ stays."""
    from nexus.langgraph.tool_output_policy import is_tool_own_log_name

    name = "20261024115540_MFTECmd_$MFT_Output.csv"
    assert is_tool_own_log_name("mftecmd", Path("x") / "mftecmd-logfile" / name)
    assert is_tool_own_log_name("mftecmd", Path("x") / "mftecmd-usn" / name)
    assert not is_tool_own_log_name("mftecmd", Path("x") / "mftecmd" / name)
    assert not is_tool_own_log_name("mftecmd", Path("x") / "mftecmd-logfile" / "LogFile-07aeb1fa.csv")
    assert not is_tool_own_log_name("recmd", Path("x") / "mftecmd-usn" / name)


def test_the_drive_tree_plans_mftecmd_for_logfile_and_usn_and_never_logfileparser(tmp_path, monkeypatch):
    root = _volume(tmp_path / "host" / "C")
    (root / "Windows" / "System32").mkdir(parents=True)
    monkeypatch.setattr(tl, "_windows_tool_available", lambda _key: True)
    jobs = tl.plan_windows_triage(str(root), tmp_path / "run" / "extractions")
    assert not [j for j in jobs if j.tool == "logfileparser"]
    logfile = _mftecmd_jobs(jobs, "$LogFile")
    usn = _mftecmd_jobs(jobs, "$J")
    assert len(logfile) == 1 and len(usn) == 1
    assert _after(logfile[0].argv, "-m") == str(root / "$MFT")
    assert _after(usn[0].argv, "-m") == str(root / "$MFT")


def test_both_logfile_paths_give_one_budget_scaled_by_the_bytes_parsed(tmp_path, monkeypatch):
    """D288's rule, kept for the new parser: the drive tree and a registered $LogFile get the same budget."""
    root = _volume(tmp_path / "host" / "C")
    (root / "Windows" / "System32").mkdir(parents=True)
    _write(root / "$LogFile", b"RSTR", 57_360_384)
    monkeypatch.setattr(tl, "_windows_tool_available", lambda _key: True)
    tree = _mftecmd_jobs(tl.plan_windows_triage(str(root), tmp_path / "tree"), "$LogFile")
    single = tl._plan_single_artifact(root / "$LogFile", tmp_path / "one")
    nbytes = (root / "$LogFile").stat().st_size + (root / "$MFT").stat().st_size
    assert tree[0].timeout == single[0].timeout == tl._mftecmd_timeout(nbytes) > 600


def test_logfileparser_is_no_longer_a_default_skip_and_deepbluecli_still_is():
    assert "logfileparser" not in tl._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS
    assert "deepbluecli" in tl._DEFAULT_OPTIONAL_TOOL_SKIP_REASONS


def test_every_job_of_a_tool_that_copies_evidence_gets_its_own_temp_folder(tmp_path):
    """AmcacheParser, SQLECmd, SrumECmd, SumECmd and WxTCmd 2026.10 copy each database into `--temp` and delete
    that folder when done; its default is one `Temp` beside the tool, which concurrent lane jobs would share."""
    ext = tmp_path / "run" / "extractions"
    def job(tool: str, argv: list[str], **kw) -> tl.ToolJob:
        return tl.ToolJob(host="windows", tool=tool, argv=argv, purpose=f"{tool} job", **kw)

    jobs = [
        job("sqlecmd", ["sqlecmd", "-f", "History", "--csv", str(ext / "a")]),
        job("sqlecmd", ["sqlecmd", "-f", "Web Data", "--csv", str(ext / "a")]),
        job("srumecmd", ["srumecmd", "-f", "SRUDB.dat", "--csv", str(ext / "b")]),
        job("evtxecmd", ["evtxecmd", "-d", "logs", "--csv", str(ext / "c")]),
        job("wxtcmd", [], status="SKIP", reason="absent"),
    ]
    tl._assign_private_temp(jobs, ext)
    tl._assign_private_temp(jobs, ext)  # idempotent: a second pass adds nothing
    temps = [_after(j.argv, "--temp") for j in jobs[:3]]
    assert len(set(temps)) == 3
    for t in temps:
        assert Path(t).parent == ext.parent / "tool-temp"
        assert not Path(t).is_relative_to(ext)  # never inside the folder the index reads
    assert all(j.argv.count("--temp") == 1 for j in jobs[:3])
    assert "--temp" not in jobs[3].argv and jobs[4].argv == []


def test_the_logfile_and_mft_headers_of_mftecmd_2026_10_are_its_family():
    header = (FIXTURES / "mftecmd_2026_10_logfile_header.csv").read_text(encoding="utf-8")
    assert family_for_csv_header(header) == "mftecmd"
    mft = (FIXTURES / "mftecmd_2026_10_mft_header.csv").read_text(encoding="utf-8")
    assert mft.rstrip().endswith(",ParseErrors")  # 2026.10 adds the column; the family rule does not depend on it
    assert family_for_csv_header(mft) == "mftecmd"


def test_the_pins_cover_every_zimmerman_tool_the_catalog_names():
    pins = json.loads(PINS.read_text(encoding="utf-8"))
    names = {name.lower(): pin for name, pin in pins["tools"].items()}
    for key, meta in win._WIN_CATALOG.items():
        if meta.get("category") == "zimmerman":
            assert key in names, f"{key} has no .NET 10 pin"
            assert names[key]["version"].startswith("2026.10.")
            assert names[key]["url"] == f"https://download.ericzimmermanstools.com/net/{meta['name']}.zip"


def test_the_recmd_batches_come_from_the_net10_release():
    batch = tl._find_recmd_dfir_batch()
    if batch is None:
        pytest.skip("RECmd is not installed on this host")
    assert "net10" in batch.parts


T04_SRUM_STDOUT = (REPO / "cases" / "CASE-9C3E4008" / "runs" / "RUN-20261024T115043750453Z-tools-d20bf38a"
                   / "extractions" / "srumecmd" / "20261024T115050_srumecmd_stdout.txt")


@pytest.mark.skipif(not T04_SRUM_STDOUT.is_file(), reason="tiny case T04's R1v lane run is not on this host")
def test_a_srum_parse_the_tool_repaired_is_held_in_the_tools_own_words():
    """R1v on T04 (2026-10-24): SrumECmd 2026.10 repaired its copy with esentutl /p and the job read OK.

    The lane's no-repair policy (D347) holds it as BLOCKED until the operator decides (OD-T14)."""
    def job(**kw) -> tl.ToolJob:
        return tl.ToolJob(host="windows", tool="srumecmd", argv=["srumecmd"], purpose="SRUM database", **kw)

    repaired = job(status="OK", output_saved_to=str(T04_SRUM_STDOUT))
    plain = job(status="OK")  # no output that reports a repair
    other = tl.ToolJob(host="windows", tool="sbecmd", argv=["sbecmd"], purpose="Shellbags", status="OK",
                       output_saved_to=str(T04_SRUM_STDOUT))
    ledger = [{"host": "windows", "tool": "srumecmd", "purpose": "SRUM database", "status": "OK", "reason": ""}]
    held = tl._hold_tool_reported_repairs([repaired, plain, other], ledger)
    assert held == [repaired]
    assert repaired.status == "BLOCKED" and ledger[0]["status"] == "BLOCKED"
    assert "was repaired with esentutl /p" in repaired.reason and "D347" in repaired.reason
    assert plain.status == "OK" and other.status == "OK"


# --- the real path, on T06's staged NTFS files ------------------------------------------------------------------


def _mftecmd() -> str:
    exe = win._find_binary("mftecmd")
    if not exe:
        pytest.skip("MFTECmd is not installed on this host")
    return exe


@pytest.fixture(scope="module")
def t06_outputs(tmp_path_factory):
    if not (T06 / "$LogFile").is_file() or not (T06 / "$MFT").is_file():
        pytest.skip("tiny case T06 is not staged on this host")
    exe = _mftecmd()
    out = tmp_path_factory.mktemp("t06") / "run" / "extractions"
    produced = {}
    for name, target in (("$LogFile", T06 / "$LogFile"), ("$J", T06 / "$Extend" / "$J")):
        jobs = tl._plan_single_artifact(target, out)
        assert [j.tool for j in jobs] == ["mftecmd"]
        argv = jobs[0].argv
        assert _after(argv, "-m") == str(T06 / "$MFT")
        subprocess.run([exe, *argv[1:]], check=True, capture_output=True, timeout=jobs[0].timeout)
        produced[name] = Path(_after(argv, "--csv")) / _after(argv, "--csvf")
    return produced


def test_t06_m_jobs_write_only_their_own_table_into_the_index(t06_outputs):
    from nexus.langgraph.query_pack import is_tool_own_log

    root = t06_outputs["$LogFile"].parents[1]
    by_products = sorted(root.rglob("*_MFTECmd_$MFT_Output.csv"))
    assert by_products, "MFTECmd 2026.10 exports the -m $MFT beside its output"
    assert all(is_tool_own_log(p, root) for p in by_products)
    assert not any(is_tool_own_log(t06_outputs[k], root) for k in ("$LogFile", "$J"))


def test_t06_logfile_rows_are_written_fingerprinted_and_left_untimed(t06_outputs):
    csv_path = t06_outputs["$LogFile"]
    header = _index_header(csv_path)
    real = (FIXTURES / "mftecmd_2026_10_logfile_header.csv").read_text(encoding="utf-8-sig").strip()
    with csv_path.open(encoding="utf-8-sig") as fh:
        first = fh.readline().strip()
    assert first == real
    assert family_for_csv_header(first) == "mftecmd"
    rows = timed = dated = 0
    with _open_text_auto(csv_path) as fh:
        for _n, raw, fields in iter_indexable_rows(csv_path, fh, header, file_label=csv_path.name):
            rows += 1
            dated += bool(fields.get("CreatedOn"))
            if extract_event_ts(raw, fields) is not None or fields.get(NO_EVENT_TIME_FIELD) != "true":
                timed += 1
            if rows >= 20_000:
                break
    assert rows == 20_000
    assert dated > 0  # some records hold file timestamps; none of them is the record's own time
    assert timed == 0


def test_t06_usn_rows_keep_the_path_mftecmd_resolved(t06_outputs):
    csv_path = t06_outputs["$J"]
    header = _index_header(csv_path)
    seen = 0
    with _open_text_auto(csv_path) as fh:
        for _n, _raw, fields in iter_indexable_rows(csv_path, fh, header, file_label=csv_path.name):
            resolved = resolve_usn_row(csv_path, fields)
            assert resolved["ParentPath"] == fields["ParentPath"] != ""
            assert resolved["FileName"] == fields["Name"]
            assert resolved["ParentPathSource"] == TOOL_PARENT_SOURCE
            seen += 1
            if seen >= 2_000:
                break
    assert seen == 2_000
