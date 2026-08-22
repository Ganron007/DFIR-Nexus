"""Windows live IR extras — Sysinternals, PersistenceSniper, wevtutil, Hayabusa, Suzaku, Chainsaw."""

from __future__ import annotations

from pathlib import Path

from nexus.collect.paths import (
    chainsaw_exe,
    chainsaw_home,
    chainsaw_mapping,
    chainsaw_sigma,
    hayabusa_exe,
    persistencesniper_psm1,
    suzaku_exe,
    sysinternals_exe,
)
from nexus.collect.transport import LocalTransport, Transport, _run_local
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec

WINEVT = r"C:\Windows\System32\winevt\Logs"

_SYSINT_TOOLS = (
    "autorunsc",
    "handle",
    "tcpvcon",
    "listdlls",
    "pslist",
    "psloggedon",
    "logonsessions",
    "pipelist",
)

_WEVTUTIL_LOGS = (
    "Security",
    "System",
    "Application",
    "Setup",
    "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
)


def _ps_quote(path: str) -> str:
    return "'" + path.replace("'", "''") + "'"


def _win_join(*parts: str) -> str:
    return "\\".join(p.replace("/", "\\").rstrip("\\") for p in parts)


def run_sysinternals(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("sysinternals", "skipped", "Windows-only")
    if not opts.sysinternals:
        return CollectorStep("sysinternals", "skipped", "disabled")
    found = {name: sysinternals_exe(name) for name in _SYSINT_TOOLS}
    present = {k: v for k, v in found.items() if v}
    out = pack_host / "sysinternals"
    detail = {k: str(v) if v else "" for k, v in found.items()}
    if not present:
        return CollectorStep(
            "sysinternals",
            "skipped",
            "no Sysinternals IR binaries under Tools/windows/sysinternals",
            detail=detail,
        )
    if dry_run:
        return CollectorStep("sysinternals", "planned", path=str(out), detail=detail)

    out.mkdir(parents=True, exist_ok=True)
    if isinstance(transport, LocalTransport):
        errors = []
        for name, exe in present.items():
            dest = out / f"{name}.txt"
            argv = _sysint_argv(name, exe, dest)
            result = _run_local(argv, 300)
            if not result.ok:
                (out / f"{name}.err.txt").write_text(
                    (result.stderr or result.stdout)[:4000], encoding="utf-8"
                )
                errors.append(name)
            elif result.stdout and dest.stat().st_size == 0:
                dest.write_text(result.stdout, encoding="utf-8")
        status = "ok" if len(errors) < len(present) else "failed"
        return CollectorStep(
            "sysinternals",
            status,
            f"missing output: {errors}" if errors else "",
            path=str(out),
            detail=detail,
        )

    remote = transport.remote_temp().rstrip("/\\") + "/sysint"
    transport.run(f"cmd.exe /c mkdir {_win_join(remote)}", timeout=30)
    staged: dict[str, str] = {}
    for name, exe in present.items():
        remote_exe = remote.replace("\\", "/") + f"/{exe.name}"
        put = transport.put_file(exe, remote_exe)
        if put.ok:
            staged[name] = remote_exe.replace("/", "\\")
    if not staged:
        return CollectorStep("sysinternals", "failed", "could not stage Sysinternals binaries", detail=detail)
    ps_lines = [f"New-Item -ItemType Directory -Force -Path {_ps_quote(_win_join(remote, 'out'))} | Out-Null"]
    for name, rex in staged.items():
        outf = _win_join(remote, "out", f"{name}.txt")
        if name == "autorunsc":
            ps_lines.append(f"& {_ps_quote(rex)} -accepteula -nobanner -a * -c * | Out-File -Encoding utf8 {_ps_quote(outf)}")
        elif name == "handle":
            ps_lines.append(f"& {_ps_quote(rex)} -accepteula -nobanner | Out-File -Encoding utf8 {_ps_quote(outf)}")
        elif name == "tcpvcon":
            ps_lines.append(f"& {_ps_quote(rex)} -accepteula -a -c | Out-File -Encoding utf8 {_ps_quote(outf)}")
        elif name == "pslist":
            ps_lines.append(f"& {_ps_quote(rex)} -accepteula -t | Out-File -Encoding utf8 {_ps_quote(outf)}")
        elif name == "logonsessions":
            ps_lines.append(f"& {_ps_quote(rex)} -accepteula -p | Out-File -Encoding utf8 {_ps_quote(outf)}")
        else:
            ps_lines.append(f"& {_ps_quote(rex)} -accepteula | Out-File -Encoding utf8 {_ps_quote(outf)}")
    result = transport.run("; ".join(ps_lines), timeout=600)
    pull = transport.get_tree(_win_join(remote, "out"), out, timeout=600)
    if not pull.ok:
        return CollectorStep(
            "sysinternals",
            "failed",
            (pull.stderr or result.stderr or "pull failed")[:400],
            path=str(out),
            detail=detail,
        )
    return CollectorStep("sysinternals", "ok", path=str(out), detail=detail)


def _sysint_argv(name: str, exe: Path, dest: Path) -> list[str]:
    if name == "autorunsc":
        return [str(exe), "-accepteula", "-nobanner", "-a", "*", "-c", "*", "-o", str(dest)]
    if name == "handle":
        return [str(exe), "-accepteula", "-nobanner"]
    if name == "tcpvcon":
        return [str(exe), "-accepteula", "-a", "-c"]
    if name == "pslist":
        return [str(exe), "-accepteula", "-t"]
    if name == "logonsessions":
        return [str(exe), "-accepteula", "-p"]
    return [str(exe), "-accepteula"]


def run_persistencesniper(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("persistencesniper", "skipped", "Windows-only")
    if not opts.persistencesniper:
        return CollectorStep("persistencesniper", "skipped", "disabled")
    psm1 = persistencesniper_psm1()
    out = pack_host / "persistencesniper"
    if not psm1:
        return CollectorStep(
            "persistencesniper",
            "skipped",
            "PersistenceSniper.psm1 not found (tools/fetch-ir-collect.ps1)",
        )
    if dry_run:
        return CollectorStep("persistencesniper", "planned", path=str(out), detail={"psm1": str(psm1)})
    out.mkdir(parents=True, exist_ok=True)
    csv = out / "persistence.csv"
    ps = (
        f"Import-Module {_ps_quote(str(psm1))}; "
        f"Find-AllPersistence | Export-Csv -NoTypeInformation -Encoding utf8 {_ps_quote(str(csv))}"
    )
    if isinstance(transport, LocalTransport):
        result = _run_local(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            600,
        )
        if not result.ok:
            return CollectorStep(
                "persistencesniper",
                "failed",
                (result.stderr or result.stdout)[:500],
                path=str(out),
            )
        return CollectorStep("persistencesniper", "ok", path=str(csv if csv.is_file() else out))

    remote = transport.remote_temp().rstrip("/\\") + "/psniper"
    transport.run(f"cmd.exe /c mkdir {_win_join(remote)}", timeout=30)
    put = transport.put_file(psm1, remote.replace("\\", "/") + "/PersistenceSniper.psm1")
    if not put.ok:
        return CollectorStep("persistencesniper", "failed", f"stage: {put.stderr[:300]}")
    remote_csv = _win_join(remote, "persistence.csv")
    rps = (
        f"Import-Module {_ps_quote(_win_join(remote, 'PersistenceSniper.psm1'))}; "
        f"Find-AllPersistence | Export-Csv -NoTypeInformation -Encoding utf8 {_ps_quote(remote_csv)}"
    )
    result = transport.run(
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -Command { _ps_quote(rps) }",
        timeout=600,
    )
    pull = transport.get_tree(remote_csv, csv, timeout=300)
    if not pull.ok:
        return CollectorStep(
            "persistencesniper",
            "failed",
            (pull.stderr or result.stderr)[:400],
            path=str(out),
        )
    return CollectorStep("persistencesniper", "ok", path=str(csv))


def run_wevtutil(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("wevtutil", "skipped", "Windows-only")
    if not opts.wevtutil:
        return CollectorStep("wevtutil", "skipped", "disabled")
    out = pack_host / "wevtutil"
    if dry_run:
        return CollectorStep("wevtutil", "planned", path=str(out), detail={"logs": list(_WEVTUTIL_LOGS)})
    out.mkdir(parents=True, exist_ok=True)

    def _export_cmds(dest_root: str) -> str:
        lines = [f"New-Item -ItemType Directory -Force -Path {_ps_quote(dest_root)} | Out-Null"]
        for log in _WEVTUTIL_LOGS:
            safe = log.replace("/", "_").replace(" ", "_")
            evtx = _win_join(dest_root, f"{safe}.evtx")
            lines.append(f"wevtutil epl {_ps_quote(log)} {_ps_quote(evtx)} /ow:true 2>$null")
        return "; ".join(lines)

    if isinstance(transport, LocalTransport):
        result = _run_local(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", _export_cmds(str(out))],
            600,
        )
        n = len(list(out.rglob("*.evtx")))
        if n == 0:
            return CollectorStep(
                "wevtutil",
                "failed",
                (result.stderr or "no evtx exported — may need elevation")[:400],
                path=str(out),
            )
        return CollectorStep("wevtutil", "ok", path=str(out), detail={"evtx_count": n})

    remote = transport.remote_temp().rstrip("/\\") + "/wevtutil"
    result = transport.run(_export_cmds(_win_join(remote)), timeout=600)
    pull = transport.get_tree(remote, out, timeout=1800)
    n = len(list(out.rglob("*.evtx")))
    if n == 0:
        return CollectorStep(
            "wevtutil",
            "failed",
            (pull.stderr or result.stderr or "no evtx pulled")[:400],
            path=str(out),
        )
    return CollectorStep("wevtutil", "ok", path=str(out), detail={"evtx_count": n})


def run_hayabusa(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    return _run_evtx_hunter(
        spec, transport, pack_host, opts, dry_run=dry_run,
        name="hayabusa",
        enabled=opts.hayabusa,
        exe=hayabusa_exe(),
        argv_for=lambda exe, logs, csv: [
            str(exe), "csv-timeline", "-d", logs, "-o", csv,
            "--no-wizard", "-Q", "--clobber",
        ],
        timeout=opts.timeout_hayabusa,
        missing="hayabusa.exe not found (Tools/windows/hayabusa)",
    )


def run_suzaku(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    return _run_evtx_hunter(
        spec, transport, pack_host, opts, dry_run=dry_run,
        name="suzaku",
        enabled=opts.suzaku,
        exe=suzaku_exe(),
        argv_for=lambda exe, logs, csv: [
            str(exe), "csv-timeline", "-d", logs, "-o", csv, "--clobber",
        ],
        timeout=opts.timeout_hayabusa,
        missing="suzaku.exe not found (Tools/windows/suzaku)",
    )


def run_chainsaw(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("chainsaw", "skipped", "Windows-only")
    if not opts.chainsaw:
        return CollectorStep("chainsaw", "skipped", "disabled")
    exe = chainsaw_exe()
    mapping = chainsaw_mapping()
    sigma = chainsaw_sigma()
    out = pack_host / "chainsaw"
    detail = {
        "exe": str(exe or ""),
        "mapping": str(mapping or ""),
        "sigma": str(sigma or ""),
    }
    if not exe:
        return CollectorStep("chainsaw", "skipped", "chainsaw.exe not found", detail=detail)
    if not mapping or not sigma:
        return CollectorStep(
            "chainsaw",
            "skipped",
            "Chainsaw hunt needs mappings/sigma-event-logs-all.yml and a sigma/ rules tree "
            "(clone SigmaHQ into Tools/windows/extra/chainsaw/sigma)",
            detail=detail,
        )
    if dry_run:
        return CollectorStep("chainsaw", "planned", path=str(out), detail=detail)
    out.mkdir(parents=True, exist_ok=True)
    csv = str(out / "hunt.csv")
    argv = [
        str(exe), "hunt", WINEVT,
        "-s", str(sigma),
        "--mapping", str(mapping),
        "--csv", "--output", csv,
        "--skip-errors",
    ]
    if isinstance(transport, LocalTransport):
        result = _run_local(argv, opts.timeout_hayabusa)
        if not result.ok:
            return CollectorStep(
                "chainsaw",
                "failed",
                (result.stderr or result.stdout)[:500],
                path=str(out),
                detail=detail,
            )
        return CollectorStep("chainsaw", "ok", path=str(out), detail=detail)

    home = chainsaw_home()
    if not home:
        return CollectorStep("chainsaw", "skipped", "chainsaw home missing", detail=detail)
    remote = transport.remote_temp().rstrip("/\\") + "/chainsaw-bin"
    put = transport.put_tree(home, remote, timeout=opts.timeout_hayabusa)
    if not put.ok:
        return CollectorStep("chainsaw", "failed", f"stage: {put.stderr[:300]}", detail=detail)
    remote_out = transport.remote_temp().rstrip("/\\") + "/chainsaw-out"
    transport.run(f"cmd.exe /c mkdir {_win_join(remote_out)}", timeout=30)
    rex = _win_join(remote, exe.name)
    rmap = _win_join(remote, "mappings", mapping.name)
    rsigma = _win_join(remote, sigma.name)
    rcsv = _win_join(remote_out, "hunt.csv")
    cmd = (
        f"{_ps_quote(rex)} hunt { _ps_quote(WINEVT) } -s {_ps_quote(rsigma)} "
        f"--mapping {_ps_quote(rmap)} --csv --output {_ps_quote(rcsv)} --skip-errors"
    )
    result = transport.run(cmd, timeout=opts.timeout_hayabusa)
    pull = transport.get_tree(remote_out, out, timeout=opts.timeout_hayabusa)
    if not pull.ok:
        return CollectorStep(
            "chainsaw",
            "failed",
            (pull.stderr or result.stderr)[:400],
            path=str(out),
            detail=detail,
        )
    return CollectorStep("chainsaw", "ok", path=str(out), detail=detail)


def _run_evtx_hunter(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
    name: str,
    enabled: bool,
    exe: Path | None,
    argv_for,
    timeout: int,
    missing: str,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep(name, "skipped", "Windows-only")
    if not enabled:
        return CollectorStep(name, "skipped", "disabled")
    out = pack_host / name
    if not exe:
        return CollectorStep(name, "skipped", missing)
    if dry_run:
        return CollectorStep(name, "planned", path=str(out), detail={"exe": str(exe)})
    out.mkdir(parents=True, exist_ok=True)
    csv = out / "timeline.csv"
    if isinstance(transport, LocalTransport):
        result = _run_local(argv_for(exe, WINEVT, str(csv)), timeout)
        if not result.ok:
            return CollectorStep(
                name,
                "failed",
                (result.stderr or result.stdout or "evtx hunt failed — may need elevation")[:500],
                path=str(out),
            )
        return CollectorStep(name, "ok", path=str(csv if csv.is_file() else out))

    home = exe.parent
    remote = transport.remote_temp().rstrip("/\\") + f"/{name}-bin"
    put = transport.put_tree(home, remote, timeout=timeout)
    if not put.ok:
        return CollectorStep(name, "failed", f"stage: {put.stderr[:300]}")
    remote_out = transport.remote_temp().rstrip("/\\") + f"/{name}-out"
    transport.run(f"cmd.exe /c mkdir {_win_join(remote_out)}", timeout=30)
    rex = _win_join(remote, exe.name)
    rcsv = _win_join(remote_out, "timeline.csv")
    argv = argv_for(Path(rex), WINEVT, rcsv)
    cmd = " ".join(_ps_quote(a) if " " in a or "\\" in a else a for a in argv)
    result = transport.run(cmd, timeout=timeout)
    pull = transport.get_tree(remote_out, out, timeout=timeout)
    if not pull.ok:
        return CollectorStep(
            name,
            "failed",
            (pull.stderr or result.stderr)[:400],
            path=str(out),
        )
    return CollectorStep(name, "ok", path=str(out))
