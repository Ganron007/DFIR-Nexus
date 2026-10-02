"""SIFT planner profiles: OS-aware Volatility plugins + SleuthKit disk jobs.

The SIFT case set (dmz-www) is a Linux target: vol3 must run linux.* plugins,
and the raw disk image must schedule the SleuthKit tools nothing else in the
pipeline can drive. The Windows profile stays the default for backward
compatibility with the existing KAPE-triage flow.
"""
from __future__ import annotations

from nexus.langgraph.tool_lane import (
    ToolJob,
    mark_missing_vol_plugins,
    parse_vol_plugin_names,
    plan_sift_triage,
    scale_memory_timeout,
    sift_jobs_for_lane,
    sift_unavailable_outcome,
    vol_plugin_name,
)


def _vol_plugins(jobs: list) -> list[str]:
    return [
        vol_plugin_name(j.argv)
        for j in jobs
        if j.tool == "vol" and j.status == "PENDING"
    ]


def test_linux_profile_selects_linux_plugins(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = plan_sift_triage("/evidence/608", sift_os="linux")
    plugins = _vol_plugins(jobs)
    assert "linux.pslist" in plugins
    assert "linux.bash" in plugins
    assert "linux.sockstat" in plugins
    assert not any(p.startswith("windows.") for p in plugins)


def test_default_profile_stays_windows(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    plugins = _vol_plugins(plan_sift_triage("/evidence/pack"))
    assert plugins and all(p.startswith("windows.") for p in plugins)
    for required in (
        "windows.pstree", "windows.psscan", "windows.dlllist",
        "windows.handles", "windows.envars", "windows.netscan",
        "windows.registry.printkey", "windows.malfind", "windows.ldrmodules",
        "windows.psxview",
    ):
        assert required in plugins


def test_memory_timeout_scales_with_image_size(tmp_path, monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    image = tmp_path / "mem.raw"
    image.write_bytes(b"x" * 64)
    small = plan_sift_triage(str(tmp_path), memory_file=str(image))
    pslist = next(j for j in small if vol_plugin_name(j.argv) == "windows.pslist")
    assert pslist.timeout == 3600
    assert scale_memory_timeout(3600, 4 * (1 << 30)) == 14400
    keys = [
        j for j in small
        if vol_plugin_name(j.argv) == "windows.registry.printkey"
    ]
    assert {label for label in ("Run", "RunOnce", "Services") if any(label in j.purpose for j in keys)} == {
        "Run", "RunOnce", "Services",
    }
    assert all("--key" in j.argv for j in keys)
    listed = parse_vol_plugin_names("plugins: windows.pslist windows.malfind linux.bash")
    assert listed == {"windows.pslist", "windows.malfind", "linux.bash"}
    untouched = plan_sift_triage("/evidence/pack")
    mark_missing_vol_plugins(untouched, set())
    assert all(j.status == "PENDING" for j in untouched if j.tool == "vol")


def test_missing_vol_plugin_is_skip_not_fail(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = plan_sift_triage("/evidence/pack")
    mark_missing_vol_plugins(jobs, {"windows.info", "windows.pslist"})
    skipped = [j for j in jobs if j.tool == "vol" and j.status == "SKIP"]
    assert skipped
    assert all("not installed" in j.reason for j in skipped)
    assert any(vol_plugin_name(j.argv) == "windows.malfind" and j.status == "SKIP" for j in jobs)
    assert any(vol_plugin_name(j.argv) == "windows.pslist" and j.status == "PENDING" for j in jobs)


def test_env_profile_is_read_when_param_absent(monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_OS", "linux")
    plugins = _vol_plugins(plan_sift_triage("/evidence/608"))
    assert "linux.pslist" in plugins and not any(p.startswith("windows.") for p in plugins)


def test_disk_image_schedules_sleuthkit_pair(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_DISK", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_BULK", raising=False)
    jobs = plan_sift_triage(
        "/evidence/608", sift_os="linux", disk_image="/evidence/608/disk.img",
    )
    pending = {j.tool for j in jobs if j.status == "PENDING"}
    assert {"mmls", "fls"} <= pending
    assert "bulk_extractor" not in pending
    fls = next(j for j in jobs if j.tool == "fls")
    assert fls.argv == ["fls", "-r", "-p", "/evidence/608/disk.img"]
    mmls = next(j for j in jobs if j.tool == "mmls")
    assert mmls.argv == ["mmls", "/evidence/608/disk.img"]


def test_bulk_extractor_is_opt_in(monkeypatch):
    monkeypatch.setenv("NEXUS_SIFT_BULK", "1")
    jobs = plan_sift_triage("/evidence/608", disk_image="/evidence/608/disk.img")
    bulk = next((j for j in jobs if j.tool == "bulk_extractor"), None)
    assert bulk is not None
    assert bulk.argv[:3] == ["bulk_extractor", "-o", "/evidence/608/bulk_extractor"]


def test_no_disk_image_keeps_fls_out(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_DISK", raising=False)
    monkeypatch.delenv("NEXUS_SIFT_E01", raising=False)
    pending = {j.tool for j in plan_sift_triage("/evidence/608") if j.status == "PENDING"}
    assert "fls" not in pending and "mmls" not in pending


def test_persist_intake_keeps_sift_keys(tmp_path):
    """The portal intake route must forward ALL intake keys - the hardcoded
    subset silently dropped sift_evidence_root/sift_os (found 2026-09-29 when
    the dbg-G7-sift case context came back empty)."""
    import yaml

    from nexus.langgraph.case_intake import persist_case_intake

    case = tmp_path / "CASE-TEST"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-TEST\n", encoding="utf-8")
    written = persist_case_intake(case, {
        "sift_evidence_root": "/ev",
        "sift_memory_file": "/ev/mem.raw",
        "sift_disk_image": "/ev/disk.img",
        "sift_os": "linux",
        "sift_required": "true",
    })
    assert written["sift_evidence_root"] == "/ev"
    assert written["sift_os"] == "linux"
    assert written["sift_required"] == "true"
    meta = yaml.safe_load((case / "CASE.yaml").read_text(encoding="utf-8"))
    assert meta["intake"]["sift_disk_image"] == "/ev/disk.img"
    assert meta["intake"]["sift_memory_file"] == "/ev/mem.raw"


def test_declared_sift_evidence_marks_jobs_critical(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = sift_jobs_for_lane(
        "/evidence/608",
        has_sift_mcp=True,
        sift_os="linux",
        disk_image="/evidence/608/disk.img",
        declared=True,
    )
    pending = [j for j in jobs if j.status == "PENDING"]
    assert pending
    assert all(j.critical for j in pending)


def test_env_only_root_is_not_critical(monkeypatch):
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = sift_jobs_for_lane("/evidence/608", has_sift_mcp=True)
    assert jobs
    assert all(not j.critical for j in jobs)


def test_declared_sift_marks_sift_root_network_jobs_too(monkeypatch):
    """Scoping rule: refusal covers every SIFT-pointed job (incl. network),
    and only SIFT-host jobs - Windows jobs on the same case stay untouched."""
    monkeypatch.setenv("NEXUS_SIFT_ZEEK", "1")
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = sift_jobs_for_lane(
        "/evidence/608",
        has_sift_mcp=True,
        declared=True,
        network_inputs={"pcap": ["/evidence/608/cap.pcap"]},
    )
    zeek = [j for j in jobs if j.tool == "zeek" and j.status == "PENDING"]
    assert zeek, "the SIFT-root capture must get a real Zeek job"
    assert all(j.critical for j in zeek)
    assert all(j.host == "sift" for j in jobs if j.critical)


def test_unavailable_outcome_is_fail_for_declared_evidence():
    declared = ToolJob(
        host="sift",
        tool="vol",
        argv=["vol", "-f", "mem.raw", "linux.pslist"],
        purpose="Volatility3 linux.pslist",
        critical=True,
    )
    status, reason = sift_unavailable_outcome(declared)
    assert status == "FAIL"
    assert "SIFT MCP unreachable" in reason
    assert "examiner skip" in reason

    defaulted = ToolJob(host="sift", tool="vol", argv=[], purpose="x")
    status, reason = sift_unavailable_outcome(defaulted)
    assert status == "SKIP"
    assert "not available" in reason


def test_clear_case_intake_removes_the_selection(tmp_path):
    from nexus.langgraph.case_intake import clear_case_intake, persist_case_intake

    case = tmp_path / "CASE-T"
    case.mkdir()
    (case / "CASE.yaml").write_text("case_id: CASE-T\n", encoding="utf-8")
    persist_case_intake(case, {"sift_required": "true", "sift_evidence_root": "/ev"})

    remaining = clear_case_intake(case, ("sift_required",))

    assert "sift_required" not in remaining
    assert remaining["sift_evidence_root"] == "/ev"


def test_stage_sift_outputs_file_and_zip(tmp_path):
    import zipfile

    from nexus.case.sift_ingest import stage_sift_outputs

    case = tmp_path / "CASE-T"
    case.mkdir()
    csv = tmp_path / "plaso.csv"
    csv.write_text("date,time\n", encoding="utf-8")
    z = tmp_path / "volout.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("pslist.json", "[]")

    staged = stage_sift_outputs(case, [csv, z])

    assert (case / "sift" / "extractions" / "plaso" / "plaso.csv").is_file()
    assert (case / "sift" / "extractions" / "volout" / "pslist.json").is_file()
    assert len(staged) == 2


def test_stage_sift_outputs_family_override(tmp_path):
    from nexus.case.sift_ingest import stage_sift_outputs

    case = tmp_path / "CASE-T"
    case.mkdir()
    f = tmp_path / "whatever.txt"
    f.write_text("x", encoding="utf-8")
    staged = stage_sift_outputs(case, [f], family="bulk_extractor")
    assert staged[0].name == "bulk_extractor"
    assert (staged[0] / "whatever.txt").is_file()


def test_sift_result_has_output_recognises_remote_evidence():
    """G7 finding: SIFT outputs are remote; the result itself is the evidence."""
    from nexus.langgraph.tool_lane import _sift_result_has_output

    assert _sift_result_has_output({"stdout_bytes": 502}) is True
    assert _sift_result_has_output(
        {"output_saved_to": "/home/u/.nexus/cases/CASE-x/extractions/mmls/1_stdout.txt"}
    ) is True
    assert _sift_result_has_output({"stdout": "hello"}) is True
    assert _sift_result_has_output({"output_files": [{"path": "x"}]}) is True
    assert _sift_result_has_output({}) is False
    assert _sift_result_has_output({"stdout_bytes": 0, "stdout": "  "}) is False


def test_disk_offset_reaches_fls(monkeypatch):
    """A whole-disk image needs `fls -o <offset>` (G7: Linux part at 2048)."""
    monkeypatch.delenv("NEXUS_SIFT_DISK_OFFSET", raising=False)
    jobs = plan_sift_triage(
        "/evidence/608", disk_image="/evidence/608/disk.img", disk_offset="2048"
    )
    fls = next(j for j in jobs if j.tool == "fls")
    assert fls.argv[:4] == ["fls", "-o", "2048", "-r"]
    assert "2048" in fls.purpose
    mmls = next(j for j in jobs if j.tool == "mmls")
    assert mmls.argv == ["mmls", "/evidence/608/disk.img"]


def test_vol_jobs_use_the_json_renderer(monkeypatch):
    """vol.yaml maps the JSON renderer; text captures are scratch.

    WO-15: the renderer is ``jsonl`` - the ``json`` renderer emits one pretty
    array whose line fragments the indexer counts as docs (verified on the
    host: ``vol -h`` lists ``pretty, json, jsonl, arrow, parquet``).
    """
    monkeypatch.delenv("NEXUS_SIFT_OS", raising=False)
    jobs = plan_sift_triage("/evidence/608", sift_os="linux")
    vol_jobs = [j for j in jobs if j.tool == "vol"]
    assert vol_jobs
    for j in vol_jobs:
        assert "-r" in j.argv
        assert j.argv[j.argv.index("-r") + 1] == "jsonl"


def test_promote_sift_pull_names_outputs_for_the_index(tmp_path):
    from pathlib import Path as _P

    from nexus.langgraph.tool_lane import _promote_sift_pull

    vol = tmp_path / "vol"
    vol.mkdir()
    (vol / "1_vol_stdout.txt").write_text('[{"PID": 1}]', encoding="utf-8")
    fls = tmp_path / "fls"
    fls.mkdir()
    (fls / "2_fls_stdout.txt").write_text("d/d 5:\tUsers\n", encoding="utf-8")
    (fls / "3_fls_stdout.txt").write_text("", encoding="utf-8")

    promoted = _promote_sift_pull(tmp_path)
    names = {_P(p).name for p in promoted}

    assert "1_vol_out.json" in names
    assert "2_fls_out.csv" in names
    assert not any("3_fls" in n for n in names)
