"""DFIR-ORC (ANSSI) — Windows forensic snapshot. Collect only; N2 parses."""

from __future__ import annotations

from pathlib import Path

from nexus.collect.paths import orc_exe
from nexus.collect.transport import LocalTransport, Transport, _run_local
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec


def orc_config(exe: Path) -> Path | None:
    for cand in (
        exe.parent / "config" / "config" / "ORC_config.xml",
        exe.parent / "ORC_config.xml",
    ):
        if cand.is_file():
            return cand
    return None


# Stock ANSSI General walks every volume + VSS (USN/NTFSInfo/GetThis). That
# works on Windows 11 but is a multi-hour job; the outer 7z stays 0 bytes until
# GetThis finishes. Live SSH keeps volatile + builtin commands only.
ORC_DISABLE_KEYS: tuple[str, ...] = (
    "ORC_Memory",
    "ORC_FastFind",
    "ORC_Offline",
    "ORC_Debug",
    "USNInfo",
    "USNInfo_system_noshadow",
    "NTFSInfo_Quick_Shadows",
    "NTFSInfo_Details_Current",
    "NTFSInfo_Details_system_noshadow",
    "NTFSInfoNoLimit",
    "FatInfo",
    "GetThis_Default",
    "GetThis_Default_system_noshadow",
    "GetThis_Additional",
    "GetThis_Additional_system_noshadow",
    "GetThis_Protected",
    "GetThis_Protected_system_noshadow",
    "GetThis_Optional",
    "GetThis_Default_offline",
    "GetThis_additional_offline",
    "GetThis_optional_offline",
    "GetSamples",
    "GetResidents",
    "GetBrowsers_History",
    "GetBrowsers_History_system_noshadow",
    "GetBrowsers_Artefacts",
    "GetExtAttrs",
    "GetYara",
    "GetFuzzyHash",
    "GetCatroot",
    "GetSDS",
    "GetMemoryDmp",
)


def orc_argv(exe: Path, out_dir: str, config: Path | None = None) -> list[str]:
    argv = [str(exe)]
    if config is not None:
        argv.append(f"/Config={config}")
    argv.append(f"/Out={out_dir}")
    argv.extend(f"/-Key={k}" for k in ORC_DISABLE_KEYS)
    return argv


def _strip_clixml(text: str) -> str:
    """PowerShell progress records on stderr start with #< CLIXML — not an ORC failure."""
    raw = (text or "").strip()
    if not raw:
        return ""
    if "#< CLIXML" in raw[:80] or raw.startswith("#< CLIXML"):
        return ""
    return raw


def _orc_output_files(out: Path) -> list[Path]:
    if not out.is_dir():
        return []
    skip = {".git"}
    found: list[Path] = []
    for p in out.rglob("*"):
        if not p.is_file():
            continue
        if any(part in skip for part in p.parts):
            continue
        if p.name.lower() in {"dfir-orc-ready.exe", "dfir-orc.exe", "orc_config.xml"}:
            continue
        found.append(p)
    return found


def _orc_has_archive(files: list[Path]) -> bool:
    """WolfLauncher can exit 0 with a 4KB 7z that only contains Config.xml."""
    for p in files:
        if p.suffix.lower() in {".7z", ".zip"} and p.stat().st_size >= 50_000:
            return True
        if p.suffix.lower() in {".csv", ".xml"} and p.stat().st_size >= 1_000:
            return True
    return False


def run_orc(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("dfir_orc", "skipped", "DFIR-ORC is Windows-only")
    if not opts.orc:
        return CollectorStep("dfir_orc", "skipped", "disabled")
    exe = orc_exe()
    out_local = pack_host / "orc"
    detail = {"engine": "DFIR-ORC", "note": "collect-only snapshot; N2 parses", "disable_keys": list(ORC_DISABLE_KEYS)}
    if not exe:
        return CollectorStep(
            "dfir_orc",
            "skipped",
            "DFIR-ORC.exe not found (Tools/windows/orc or NEXUS_ORC)",
            detail=detail,
        )
    detail["exe"] = str(exe)
    cfg = orc_config(exe)
    if cfg:
        detail["config"] = str(cfg)
    if dry_run:
        detail["argv"] = orc_argv(exe, str(out_local), cfg)
        return CollectorStep("dfir_orc", "planned", path=str(out_local), detail=detail)

    out_local.mkdir(parents=True, exist_ok=True)
    if isinstance(transport, LocalTransport):
        result = _run_local(orc_argv(exe, str(out_local), cfg), opts.timeout_orc)
        files = _orc_output_files(out_local)
        if _orc_has_archive(files):
            detail["files"] = len(files)
            return CollectorStep("dfir_orc", "ok", path=str(out_local), detail=detail)
        err = _strip_clixml(result.stderr) or result.stdout or "orc failed"
        return CollectorStep(
            "dfir_orc",
            "failed",
            err[:500],
            path=str(out_local),
            detail=detail,
        )

    remote_root = transport.remote_temp().rstrip("/\\") + "/orc"
    win_root = remote_root.replace("/", "\\")
    remote_exe = remote_root + "/" + exe.name
    put = transport.put_file(exe, remote_exe, timeout=opts.timeout_orc)
    if not put.ok:
        return CollectorStep("dfir_orc", "failed", f"stage: {put.stderr[:400]}", detail=detail)
    remote_cfg_win = ""
    if cfg:
        put_cfg = transport.put_file(cfg, remote_root + "/" + cfg.name, timeout=opts.timeout_orc)
        if not put_cfg.ok:
            return CollectorStep("dfir_orc", "failed", f"stage config: {put_cfg.stderr[:400]}", detail=detail)
        remote_cfg_win = win_root + "\\" + cfg.name
    remote_out = remote_root + "/out"
    remote_out_win = remote_out.replace("/", "\\")
    remote_exe_win = win_root + "\\" + exe.name

    def _q(path: str) -> str:
        return "'" + path.replace("'", "''") + "'"

    arg_items = [f"/Out={remote_out_win}"]
    arg_items.extend(f"/-Key={k}" for k in ORC_DISABLE_KEYS)
    if remote_cfg_win:
        arg_items.insert(0, f"/Config={remote_cfg_win}")
    cmdline = remote_exe_win + " " + " ".join(arg_items)
    result = transport.run(
        f"New-Item -ItemType Directory -Force -Path {_q(win_root)}, {_q(remote_out_win)} | Out-Null; "
        f"$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{{ "
        f"CommandLine = {_q(cmdline)}; CurrentDirectory = {_q(win_root)} }}; "
        f"if ($r.ReturnValue -ne 0 -or -not $r.ProcessId) {{ "
        f"Write-Output ('ORC_CREATE=' + $r.ReturnValue); exit 1 }}; "
        f"Wait-Process -Id $r.ProcessId -Timeout {max(60, int(opts.timeout_orc))}; "
        f"Write-Output ('ORC_PID=' + $r.ProcessId + ' ORC_CREATE=0')",
        timeout=opts.timeout_orc + 30,
    )
    pull = transport.get_tree(remote_out, out_local, timeout=opts.timeout_orc)
    files = _orc_output_files(out_local)
    if _orc_has_archive(files):
        detail["files"] = len(files)
        if not result.ok:
            detail["orc_exit_note"] = (_strip_clixml(result.stderr) or result.stdout or "")[:200]
        return CollectorStep("dfir_orc", "ok", path=str(out_local), detail=detail)
    err = (
        _strip_clixml(result.stderr)
        or _strip_clixml(result.stdout)
        or (pull.stderr if not pull.ok else "")
        or "ORC produced only logs/empty archive (child processes did not start)"
    )
    return CollectorStep(
        "dfir_orc",
        "failed",
        err[:500],
        path=str(out_local),
        detail=detail,
    )
