"""Stage 0 collect — plan/import/auth wiring. No live KAPE/Kansa/network."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from nexus.cli.main import app
from nexus.collect.kape import kape_argv
from nexus.collect.orchestrator import import_dump, plan_or_run
from nexus.collect.transport import SshTransport
from nexus.collect.types import AuthSpec, CollectOptions, HostSpec
from nexus.collect.vr_gate import vr_step

runner = CliRunner()


def test_kape_argv_includes_target_and_module():
    argv = kape_argv(
        Path("kape.exe"),
        tsource="C:",
        tdest=r"C:\out\targets",
        target="!SANS_Triage",
        module="!EZParser",
        mdest=r"C:\out\modules",
    )
    assert "--target" in argv
    assert "!SANS_Triage" in argv
    assert "--module" in argv
    assert "!EZParser" in argv
    assert "--tsource" in argv
    assert "--tdest" in argv
    assert "--msource" in argv
    assert "--mdest" in argv


def test_kansa_ps1_argv_has_no_outputpath():
    from nexus.collect.kansa import kansa_ps1_argv

    argv = kansa_ps1_argv(Path(r"C:\Tools\kansa\kansa.ps1"), "ws01")
    assert "-OutputPath" not in argv
    assert "-Target" in argv
    assert "ws01" in argv
    assert "-Authentication" in argv
    assert "Negotiate" in argv


def test_kape_argv_acquire_only_when_module_empty():
    argv = kape_argv(
        Path("kape.exe"),
        tsource="C:",
        tdest=r"C:\out\targets",
        target="!SANS_Triage",
        module="",
    )
    assert "--module" not in argv
    assert "--mdest" not in argv


def test_orc_argv_uses_out_switch():
    from nexus.collect.orc import orc_argv

    argv = orc_argv(Path(r"C:\Tools\orc\DFIR-ORC.exe"), r"C:\pack\ws01\orc")
    assert argv[0].endswith("DFIR-ORC.exe")
    assert any(a.startswith("/Out=") for a in argv)
    assert "/-Key=ORC_Memory" in argv
    assert "/-Key=GetThis_Default" in argv
    assert "/-Key=NTFSInfo_Details_Current" in argv


def test_plan_windows_localhost_no_network(tmp_path):
    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    opts = CollectOptions()
    manifest = plan_or_run(spec, opts, tmp_path / "pack", dry_run=True, probe=False, examiner="test")
    assert manifest.dry_run is True
    names = {s.name: s.status for s in manifest.hosts[0].steps}
    for expected in (
        "kansa", "sysinternals", "persistencesniper", "wevtutil",
        "hayabusa", "suzaku", "chainsaw", "kape", "dfir_orc", "winpmem", "velociraptor",
    ):
        assert expected in names, expected
    assert names["kansa"] == "skipped"
    assert names["hayabusa"] == "skipped"
    assert names["suzaku"] == "skipped"
    assert names["chainsaw"] == "skipped"
    assert names["dfir_orc"] == "skipped"
    assert names["winpmem"] == "skipped"
    assert names["kape"] in {"planned", "skipped"}
    assert names["sysinternals"] in {"planned", "skipped"}
    assert names["wevtutil"] in {"planned", "skipped"}
    assert names["velociraptor"] in {"skipped", "planned"}
    blob = (tmp_path / "pack" / "manifest.json").read_text(encoding="utf-8")
    data = json.loads(blob)
    assert data["schema"] == "nexus.collect.v1"
    assert "password" not in blob.lower() or "never stored" in blob


def test_plan_windows_full_profile_lists_optional_collectors(tmp_path):
    from nexus.collect.profiles import apply_enabled, enabled_set

    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    opts = CollectOptions(profile="full")
    apply_enabled(opts, enabled_set("full"))
    manifest = plan_or_run(spec, opts, tmp_path / "pack", dry_run=True, probe=False)
    names = {s.name: s.status for s in manifest.hosts[0].steps}
    assert names["kansa"] == "planned"
    assert names["hayabusa"] in {"planned", "skipped"}
    assert names["dfir_orc"] in {"planned", "skipped"}
    assert names["winpmem"] in {"planned", "skipped"}


def test_uac_remote_cmd_cds_into_extracted_tree():
    from nexus.collect.linux import _uac_remote_cmd

    cmd = _uac_remote_cmd("/tmp/nexus-ir-ab/uac", "sudo ", "full")
    assert "cd /tmp/nexus-ir-ab/uac" in cmd
    assert "./uac -p full" in cmd
    assert cmd.startswith("mkdir -p /tmp/nexus-ir-ab/uac/out")


def test_plan_linux_ssh_lists_uac_or_builtin(tmp_path):
    spec = HostSpec(
        os="linux",
        address="192.168.77.40",
        hostname="linux01",
        transport="ssh",
        auth=AuthSpec(user="vagrant", identity=""),
    )
    manifest = plan_or_run(
        spec, CollectOptions(), tmp_path / "pack", dry_run=True, probe=False, examiner="test"
    )
    names = [s.name for s in manifest.hosts[0].steps]
    assert "velociraptor" in names
    assert "linux_volatile" in names
    assert "journal" in names
    assert "avml" in names
    assert any(n in names for n in ("uac", "linux_volatile"))


def test_import_dump_pointer_no_copy(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_VR_USE_MOCK", "1")
    dump = tmp_path / "kansa-out"
    dump.mkdir()
    (dump / "HostInfo.csv").write_text("ComputerName\nWS01\n", encoding="utf-8")
    pack = tmp_path / "pack"
    manifest = import_dump(
        dump, os_name="windows", hostname="rd01", pack_dir=pack, examiner="test", copy=False
    )
    src = json.loads((pack / "hosts" / "rd01" / "import" / "source.json").read_text(encoding="utf-8"))
    assert src["copied"] is False
    assert str(dump.resolve()) == src["source"]
    assert "kansa-out" in src["source"]
    assert "live collect was not run" in src["note"]
    assert manifest.hosts[0].steps[0].name == "import"
    assert manifest.hosts[0].steps[1].name == "velociraptor"
    assert manifest.hosts[0].steps[1].status == "skipped"


def test_vr_step_skipped_when_not_live(monkeypatch):
    monkeypatch.setenv("NEXUS_VR_USE_MOCK", "1")
    step = vr_step(wanted=True)
    assert step.name == "velociraptor"
    assert step.status == "skipped"
    assert "mock" in step.reason.lower() or "not" in step.reason.lower()
    assert "Stage 2" not in step.reason


def test_vr_live_status_mcp_without_grpc_endpoint(monkeypatch):
    from datetime import UTC, datetime

    from nexus.collect.vr import vr_live_status
    from nexus.integration.vql_runner import VQLResult

    monkeypatch.delenv("NEXUS_VR_USE_MOCK", raising=False)
    monkeypatch.delenv("NEXUS_VR_ENDPOINT", raising=False)
    monkeypatch.delenv("NEXUS_VR_API_KEY", raising=False)
    monkeypatch.setenv("NEXUS_VR_MCP_URL", "http://192.168.77.51:8002")
    monkeypatch.setenv("NEXUS_VR_MCP_API_KEY", "lab-mcp-key")

    class _Client:
        def query(self, spec):
            return VQLResult(
                query_name="ping",
                rows=[{"ok": 1}],
                timestamp=datetime.now(UTC),
                duration_ms=1,
            )

        def health(self):
            return {"ok": True}

    class _Svc:
        use_mock = False
        _client = _Client()

        def health(self):
            return {
                "client_type": "RemoteVRMCPClient",
                "mcp_url": "http://192.168.77.51:8002",
                "mcp_health": {"ok": True},
            }

    monkeypatch.setattr("nexus.vr.service.VRService", lambda **_kw: _Svc())
    live, reason = vr_live_status()
    assert live is True
    assert "RemoteVRMCPClient" in reason


def test_match_client_uses_last_ip_without_port():
    from nexus.collect.types import HostSpec
    from nexus.collect.vr import _match_client

    class _Svc:
        pass

    class _Rows:
        def __init__(self, rows):
            self.rows = rows
            self.error = ""

    svc = _Svc()

    def _list(_svc):
        return [
            {
                "client_id": "C.0c83142b7f7ca56b",
                "hostname": "ws01",
                "fqdn": "ws01.child.cadre.local",
                "last_ip": "192.168.77.62:49392",
            }
        ]

    import nexus.collect.vr as vr_mod

    orig = vr_mod._list_clients
    vr_mod._list_clients = _list
    try:
        spec = HostSpec(os="windows", address="192.168.77.62", hostname="")
        assert _match_client(svc, spec) == "C.0c83142b7f7ca56b"
    finally:
        vr_mod._list_clients = orig


def test_default_vr_hunts_are_minimum_ir():
    from nexus.collect.vr import LINUX_HUNTS, WINDOWS_HUNTS

    assert WINDOWS_HUNTS == ("Generic.Client.Info", "CADRE.Hunts.IRTriage")
    assert LINUX_HUNTS == ("Generic.Client.Info", "CADRE.Hunts.LinuxIRTriage")
    assert "FullBreach" not in "".join(WINDOWS_HUNTS + LINUX_HUNTS)
    assert "FilesystemTimeline" not in "".join(WINDOWS_HUNTS)


def test_collect_client_vql_is_client_side():
    from nexus.collect.vr import collect_client_vql

    vql = collect_client_vql("Generic.Client.Info", "C.abc123", timeout=120)
    assert "collect_client" in vql
    assert "C.abc123" in vql
    assert "Generic.Client.Info" in vql
    assert "FROM collect_client" not in vql
    assert "AS Collection FROM scope()" in vql
    assert "wait=TRUE" not in vql
    assert "urgent=TRUE" in vql


def test_collect_client_vql_rejects_injection():
    from nexus.collect.vr import collect_client_vql

    try:
        collect_client_vql("Generic.Client.Info(); DROP", "C.abc")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
    try:
        collect_client_vql("Generic.Client.Info", "ws01")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")


def test_flow_id_and_vfs_source_helpers():
    from nexus.collect.vr import _flow_id_from_rows, _source_from_vfs

    assert (
        _flow_id_from_rows([{"Collection": {"flow_id": "F.DA42QE9BHHO7Q"}}])
        == "F.DA42QE9BHHO7Q"
    )
    assert (
        _source_from_vfs(
            "fs:/clients/C.abc/artifacts/Generic.Client.Info/F.ABC/BasicInformation.json"
        )
        == "Generic.Client.Info/BasicInformation"
    )
    assert _source_from_vfs("fs:/tmp/evil.json") == ""


def test_collect_artifact_uses_function_form_and_fetches_results(monkeypatch):
    from datetime import UTC, datetime

    from nexus.collect.vr import _collect_artifact
    from nexus.integration.vql_runner import VQLResult

    calls: list[str] = []

    class _Client:
        def query(self, spec):
            vql = spec.vql
            calls.append(vql)
            if "FROM collect_client" in vql:
                raise AssertionError("plugin-form collect_client must not be used")
            if "collect_client(" in vql:
                return VQLResult(
                    query_name="start",
                    rows=[{"Collection": {"flow_id": "F.ABC123"}}],
                    timestamp=datetime.now(UTC),
                    duration_ms=5,
                )
            if "FROM flows(" in vql:
                return VQLResult(
                    query_name="status",
                    rows=[
                        {
                            "session_id": "F.ABC123",
                            "state": "FINISHED",
                            "total_collected_rows": 1,
                            "artifacts_with_results": [
                                "Generic.Client.Info/BasicInformation"
                            ],
                        }
                    ],
                    timestamp=datetime.now(UTC),
                    duration_ms=5,
                )
            if "flow_results(" in vql:
                return VQLResult(
                    query_name="rows",
                    rows=[{"Hostname": "ws01"}],
                    timestamp=datetime.now(UTC),
                    duration_ms=5,
                )
            raise AssertionError(f"unexpected vql: {vql}")

    class _Svc:
        _client = _Client()

    monkeypatch.setattr("nexus.collect.vr.time.sleep", lambda _s: None)
    out = _collect_artifact(_Svc(), "Generic.Client.Info", "C.abc123", timeout=30)
    assert out["ok"] is True
    assert out["flow_id"] == "F.ABC123"
    assert out["row_count"] == 1
    assert out["rows"][0]["Hostname"] == "ws01"
    assert any("AS Collection FROM scope()" in vql for vql in calls)
    assert any("flow_results(" in vql for vql in calls)


def test_collect_artifact_harvests_error_flow_with_sources(monkeypatch):
    from datetime import UTC, datetime

    from nexus.collect.vr import _collect_artifact
    from nexus.integration.vql_runner import VQLResult

    class _Client:
        def query(self, spec):
            vql = spec.vql
            if "collect_client(" in vql:
                return VQLResult(
                    query_name="start",
                    rows=[{"Collection": {"flow_id": "F.ERR1"}}],
                    timestamp=datetime.now(UTC),
                    duration_ms=5,
                )
            if "FROM flows(" in vql:
                return VQLResult(
                    query_name="status",
                    rows=[
                        {
                            "session_id": "F.ERR1",
                            "state": "ERROR",
                            "total_collected_rows": 12,
                            "artifacts_with_results": [
                                "CADRE.Hunts.LinuxIRTriage/Pslist"
                            ],
                        }
                    ],
                    timestamp=datetime.now(UTC),
                    duration_ms=5,
                )
            if "flow_results(" in vql:
                return VQLResult(
                    query_name="rows",
                    rows=[{"Pid": 1, "Name": "systemd"}],
                    timestamp=datetime.now(UTC),
                    duration_ms=5,
                )
            raise AssertionError(f"unexpected vql: {vql}")

    class _Svc:
        _client = _Client()

    monkeypatch.setattr("nexus.collect.vr.time.sleep", lambda _s: None)
    out = _collect_artifact(_Svc(), "CADRE.Hunts.LinuxIRTriage", "C.abc123", timeout=30)
    assert out["ok"] is True
    assert out["state"] == "ERROR"
    assert out["row_count"] == 1
    assert "systemd" in str(out["rows"])
    assert "state=ERROR" in out["error"]


def test_windows_sftp_path_normalizes_drive():
    from nexus.collect.transport import windows_sftp_path

    assert windows_sftp_path(r"C:\Windows\Temp\nexus-ir\out") == "/C:/Windows/Temp/nexus-ir/out"
    assert windows_sftp_path("C:/Windows/Temp/nexus-ir/out") == "/C:/Windows/Temp/nexus-ir/out"
    assert windows_sftp_path("/C:/Windows/Temp/nexus-ir/out") == "/C:/Windows/Temp/nexus-ir/out"
    assert windows_sftp_path("/tmp/nexus-ir") == "/tmp/nexus-ir"


def test_windows_ssh_wraps_cmd_default_shell():
    import base64

    from nexus.collect.transport import windows_ssh_encoded_command

    wrapped = windows_ssh_encoded_command("New-Item -ItemType Directory")
    assert "EncodedCommand" in wrapped
    assert "New-Item -ItemType Directory" not in wrapped
    decoded = base64.b64decode(wrapped.split()[-1]).decode("utf-16le")
    assert "ProgressPreference" in decoded
    assert "New-Item -ItemType Directory" in decoded
    already = "powershell.exe -EncodedCommand ABC"
    assert windows_ssh_encoded_command(already) == already


def test_flatten_scp_nest_lifts_contents(tmp_path):
    from nexus.collect.transport import _flatten_scp_nest

    dest = tmp_path / "wevtutil"
    nested = dest / "wevtutil"
    nested.mkdir(parents=True)
    (nested / "Security.evtx").write_bytes(b"evtx")
    _flatten_scp_nest(dest, "C:/Windows/Temp/nexus-ir/wevtutil")
    assert (dest / "Security.evtx").is_file()
    assert not nested.exists()


def test_orc_treats_clixml_progress_as_noise(tmp_path):
    from nexus.collect.orc import _orc_has_archive, _orc_output_files, _strip_clixml

    assert _strip_clixml("#< CLIXML\n<Objs/>") == ""
    assert _strip_clixml("Opening DFIR-ORC") == "Opening DFIR-ORC"
    out = tmp_path / "orc"
    nested = out / "out"
    nested.mkdir(parents=True)
    (nested / "GetSystemInfo.csv").write_text("a,b\n", encoding="utf-8")
    (out / "DFIR-ORC-ready.exe").write_bytes(b"mz")
    empty_7z = nested / "General.7z"
    empty_7z.write_bytes(b"7z" + b"\0" * 100)
    files = _orc_output_files(out)
    assert any(p.name == "GetSystemInfo.csv" for p in files)
    assert not any(p.name.lower().endswith(".exe") for p in files)
    assert _orc_has_archive(files) is False
    empty_7z.write_bytes(b"7z" + b"\0" * 50_000)
    assert _orc_has_archive(_orc_output_files(out)) is True


def test_put_tree_copies_contents_into_dest(tmp_path, monkeypatch):
    from nexus.collect.transport import ExecResult, SshTransport

    captured: list[list[str]] = []

    def fake_run_local(argv, timeout):
        captured.append(list(argv))
        return ExecResult(0, "", "")

    monkeypatch.setattr("nexus.collect.transport._run_local", fake_run_local)
    monkeypatch.setattr("nexus.collect.transport._which", lambda _n: "ssh")
    key = tmp_path / "id_ed25519"
    key.write_text("dummy\n", encoding="utf-8")
    src = tmp_path / "kapehome"
    src.mkdir()
    (src / "kape.exe").write_text("x", encoding="utf-8")
    spec = HostSpec(
        os="windows",
        address="192.168.77.62",
        transport="ssh",
        auth=AuthSpec(user="vagrant", identity=str(key)),
    )
    SshTransport(spec).put_tree(src, "C:/Windows/Temp/nexus-ir/kape-bin")
    scp_calls = [a for a in captured if a and a[0] == "scp"]
    assert scp_calls, captured
    last = scp_calls[-1]
    joined = " ".join(last).replace("\\", "/")
    assert joined.endswith("/C:/Windows/Temp/nexus-ir/kape-bin/kape.exe") or "/kape-bin/kape.exe" in joined


def test_ssh_argv_never_contains_password(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECT_PASSWORD", "super-secret-lab")
    key = tmp_path / "id_ed25519"
    key.write_text("dummy-key\n", encoding="utf-8")
    spec = HostSpec(
        os="windows",
        address="192.168.77.62",
        transport="ssh",
        auth=AuthSpec(user="analyst_t1", identity=str(key)),
    )
    argv = SshTransport(spec)._base_ssh()
    joined = " ".join(argv)
    assert "super-secret-lab" not in joined
    assert "-i" in argv
    assert str(key) in argv
    assert "BatchMode=yes" in joined


def test_ssh_probe_requires_auth(monkeypatch):
    monkeypatch.delenv("NEXUS_COLLECT_PASSWORD", raising=False)
    spec = HostSpec(
        os="linux",
        address="10.0.0.9",
        transport="ssh",
        auth=AuthSpec(user="root"),
    )
    result = SshTransport(spec).probe()
    assert result.ok is False
    assert result.returncode == 2
    low = result.stderr.lower()
    assert "identity" in low or "password" in low


def test_manifest_does_not_store_password_secret(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECT_PASSWORD", "super-secret-lab")
    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    plan_or_run(spec, CollectOptions(), tmp_path / "pack", dry_run=True, probe=False)
    blob = (tmp_path / "pack" / "manifest.json").read_text(encoding="utf-8")
    assert "super-secret-lab" not in blob


def test_cli_collect_help():
    result = runner.invoke(app, ["collect", "--help"])
    assert result.exit_code == 0, result.output
    assert "tools" in result.output
    assert "plan" in result.output
    assert "run" in result.output
    assert "import" in result.output
    plan = runner.invoke(app, ["collect", "plan", "--help"])
    assert plan.exit_code == 0, plan.output
    assert "--profile" in plan.output
    assert "--only" in plan.output


def test_cli_collect_tools():
    result = runner.invoke(app, ["collect", "tools"])
    assert result.exit_code == 0, result.output
    assert "kape" in result.output.lower()
    assert "velociraptor" in result.output.lower()
    assert "dfir_orc" in result.output.lower() or "orc" in result.output.lower()
    assert "hayabusa" in result.output.lower()
    assert "full" in result.output.lower()


def test_cli_collect_plan(tmp_path):
    result = runner.invoke(
        app,
        [
            "collect", "plan",
            "--os", "windows",
            "--host", "localhost",
            "--hostname", "ws01",
            "--out", str(tmp_path / "plan-pack"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "plan-pack" / "manifest.json").is_file()


def test_cli_collect_no_password_flag():
    result = runner.invoke(app, ["collect", "run", "--os", "windows", "--password", "x"])
    assert result.exit_code != 0
    assert "no such option" in result.output.lower() or "unrecognized" in result.output.lower() or result.exit_code != 0


def test_profile_volatile_skips_disk_collectors(tmp_path):
    from nexus.collect.profiles import apply_enabled, enabled_set
    from nexus.collect.types import CollectOptions

    opts = CollectOptions(profile="volatile")
    apply_enabled(opts, enabled_set("volatile"))
    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    manifest = plan_or_run(spec, opts, tmp_path / "pack", dry_run=True, probe=False)
    names = {s.name: s.status for s in manifest.hosts[0].steps}
    assert names["kansa"] == "planned"
    assert names["kape"] == "skipped"
    assert names["dfir_orc"] == "skipped"
    assert names["hayabusa"] == "skipped"
    assert names["winpmem"] == "skipped"


def test_disk_profile_uses_uac_ir_triage_not_full():
    from nexus.collect.profiles import apply_enabled, enabled_set
    from nexus.collect.types import CollectOptions

    disk = CollectOptions(profile="disk")
    apply_enabled(disk, enabled_set("disk"))
    assert disk.uac_profile == "ir_triage"
    full = CollectOptions(profile="full")
    apply_enabled(full, enabled_set("full"))
    assert full.uac_profile == "full"


def test_disk_profile_is_live_ir_spine(tmp_path):
    from nexus.collect.profiles import apply_enabled, enabled_set
    from nexus.collect.types import CollectOptions

    opts = CollectOptions(profile="disk")
    apply_enabled(opts, enabled_set("disk"))
    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    manifest = plan_or_run(spec, opts, tmp_path / "pack", dry_run=True, probe=False)
    names = {s.name: s.status for s in manifest.hosts[0].steps}
    assert names["kansa"] == "skipped"
    assert names["hayabusa"] == "skipped"
    assert names["suzaku"] == "skipped"
    assert names["chainsaw"] == "skipped"
    assert names["dfir_orc"] == "skipped"
    assert names["winpmem"] == "skipped"
    assert names["kape"] in {"planned", "skipped"}
    assert names["wevtutil"] in {"planned", "skipped"}
    assert names["sysinternals"] in {"planned", "skipped"}
    assert names["velociraptor"] in {"planned", "skipped"}


def test_only_kansa(tmp_path):
    from nexus.collect.profiles import apply_enabled, enabled_set
    from nexus.collect.types import CollectOptions

    opts = CollectOptions(profile="full")
    apply_enabled(opts, enabled_set("full", only="kansa"))
    spec = HostSpec(os="windows", address="localhost", hostname="ws01", transport="local")
    manifest = plan_or_run(spec, opts, tmp_path / "pack", dry_run=True, probe=False)
    planned = [s.name for s in manifest.hosts[0].steps if s.status == "planned"]
    assert "kansa" in planned
    assert "kape" not in planned
    assert "hayabusa" not in planned


def test_cli_collect_plan_profile_disk(tmp_path):
    result = runner.invoke(
        app,
        [
            "collect", "plan",
            "--os", "linux",
            "--host", "localhost",
            "--hostname", "linux01",
            "--profile", "disk",
            "--out", str(tmp_path / "plan-disk"),
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads((tmp_path / "plan-disk" / "manifest.json").read_text(encoding="utf-8"))
    names = {c["name"]: c["status"] for c in data["hosts"][0]["collectors"]}
    assert names.get("avml") == "skipped"
    assert names.get("uac") in {"planned", "skipped"}
    assert names.get("linux_volatile") in {"planned", "skipped"}
    assert names.get("journal") in {"planned", "skipped"}


def test_tool_inventory_lists_live_ir_binaries():
    from nexus.collect.paths import tool_inventory

    inv = tool_inventory()
    assert "hayabusa" in inv
    assert "persistencesniper" in inv
    assert "profile_default" in inv
    assert inv["profile_default"] == "disk"
