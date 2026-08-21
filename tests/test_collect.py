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
    assert names["kansa"] == "planned"
    assert names["kape"] in {"planned", "skipped"}
    assert names["dfir_orc"] in {"planned", "skipped"}
    assert names["winpmem"] in {"planned", "skipped"}
    assert names["sysinternals"] in {"planned", "skipped"}
    assert names["hayabusa"] in {"planned", "skipped"}
    assert names["chainsaw"] in {"planned", "skipped"}
    assert names["velociraptor"] in {"skipped", "planned"}
    blob = (tmp_path / "pack" / "manifest.json").read_text(encoding="utf-8")
    data = json.loads(blob)
    assert data["schema"] == "nexus.collect.v1"
    assert "password" not in blob.lower() or "never stored" in blob


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


def test_import_dump_pointer_no_copy(tmp_path):
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


def test_collect_client_vql_is_client_side():
    from nexus.collect.vr import collect_client_vql

    vql = collect_client_vql("Generic.Client.Info", "C.abc123", timeout=120)
    assert "collect_client" in vql
    assert "C.abc123" in vql
    assert "Generic.Client.Info" in vql
    assert "wait=TRUE" in vql


def test_collect_client_vql_rejects_injection():
    from nexus.collect.vr import collect_client_vql

    try:
        collect_client_vql("Generic.Client.Info(); DROP", "C.abc")
        assert False, "expected ValueError"
    except ValueError:
        pass
    try:
        collect_client_vql("Generic.Client.Info", "ws01")
        assert False, "expected ValueError"
    except ValueError:
        pass


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
    assert any(n in names for n in ("uac", "linux_volatile"))


def test_tool_inventory_lists_live_ir_binaries():
    from nexus.collect.paths import tool_inventory

    inv = tool_inventory()
    assert "hayabusa" in inv
    assert "persistencesniper" in inv
    assert "profile_default" in inv
    assert inv["profile_default"] == "full"
