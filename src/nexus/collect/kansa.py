"""Kansa live volatile collection — real kansa.ps1 if present, else builtin modules."""

from __future__ import annotations

import shutil
from pathlib import Path

from nexus.collect.paths import kansa_home, sysinternals_exe
from nexus.collect.transport import LocalTransport, Transport, _run_local
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec

# Match the SRL Kansa module set we already have CSVs for (builtin fallback).
DEFAULT_KANSA_MODULES = (
    "Arp",
    "Autorunsc",
    "DNSCache",
    "HostInfo",
    "LocalAdmins",
    "LogUserAssist",
    "Netstat",
    "ProcsWMI",
    "SmbSession",
    "SvcAll",
    "SvcFail",
    "SvcTrigs",
    "Tasklistv",
    "TempDirListing",
    "WMIEvtConsumer",
    "WMIEvtFilter",
    "WMIFltConBind",
)

# Full live-IR module list — no extra args, no FireForget, no MFT/memory/Loki/Rekall.
KANSA_FULL_CONF = """
Process\\Get-PrefetchListing.ps1
Process\\Get-WMIRecentApps.ps1
Net\\Get-Netstat.ps1
Net\\Get-DNSCache.ps1
Net\\Get-Arp.ps1
Net\\Get-SmbSession.ps1
Process\\Get-Tasklistv.ps1
Process\\Get-Handle.ps1
Process\\Get-ProcsWMI.ps1
Process\\Get-InjectedThreads.ps1
Net\\Get-NetRoutes.ps1
Net\\Get-NetIPInterfaces.ps1
Log\\Get-LogUserAssist.ps1
Log\\Get-AppCompatCache.ps1
Log\\Get-OfficeMRU.ps1
Log\\Get-RdpConnectionLogs.ps1
Log\\Get-SysmonProcess.ps1
Log\\Get-SysmonNetwork.ps1
Log\\Get-LogCBS.ps1
Log\\Get-LogOpenSavePidlMRU.ps1
ASEP\\Get-SvcAll.ps1
ASEP\\Get-SvcFail.ps1
ASEP\\Get-SvcTrigs.ps1
ASEP\\Get-WMIEvtFilter.ps1
ASEP\\Get-WMIFltConBind.ps1
ASEP\\Get-WMIEvtConsumer.ps1
ASEP\\Get-PSProfiles.ps1
ASEP\\Get-SchedTasks.ps1
ASEP\\Get-SchedTasksAll.ps1
ASEP\\Get-Autorunsc.ps1
ASEP\\Get-PersistenceFilesAndRegistryKeys.ps1
ASEP\\Get-ImagePathExecutionOptions.ps1
Disk\\Get-TempDirListing.ps1
Disk\\Get-Recent.ps1
Config\\Get-LocalAdmins.ps1
Config\\Get-LocalUsers.ps1
Config\\Get-Products.ps1
Config\\Get-SmbShare.ps1
Config\\Get-Hotfix.ps1
""".lstrip()

KANSA_LOCAL_PS1 = r'''
param(
  [Parameter(Mandatory=$true)][string]$KansaHome,
  [Parameter(Mandatory=$true)][string]$OutDir,
  [Parameter(Mandatory=$true)][string]$ConfFile
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$hostName = $env:COMPUTERNAME
$modulesRoot = Join-Path $KansaHome 'Modules'
Get-Content -Path $ConfFile | ForEach-Object {
  $line = $_.Trim()
  if (-not $line -or $line.StartsWith('#')) { return }
  $rel = ($line -split '\s+', 2)[0]
  $script = Join-Path $modulesRoot $rel
  if (-not (Test-Path $script)) {
    $miss = Join-Path $OutDir '_missing.txt'
    Add-Content -Path $miss -Value $rel
    return
  }
  $name = [IO.Path]::GetFileNameWithoutExtension($rel) -replace '^Get-',''
  $dest = Join-Path $OutDir $name
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  $csv = Join-Path $dest ("{0}-{1}.csv" -f $hostName, $name)
  try {
    Push-Location $KansaHome
    $rows = & $script
    Pop-Location
    if ($null -eq $rows) { "" | Set-Content -Path $csv -Encoding utf8; return }
    $rows | Export-Csv -NoTypeInformation -Path $csv -Encoding utf8
  } catch {
    Pop-Location
    $_ | Out-File (Join-Path $dest 'error.txt')
  }
}
'''

BUILTIN_PS1 = r'''
param(
  [Parameter(Mandatory=$true)][string]$OutDir
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$hostName = $env:COMPUTERNAME
function Write-ModCsv($name, $rows) {
  $dir = Join-Path $OutDir $name
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $path = Join-Path $dir ("{0}-{1}.csv" -f $hostName, $name)
  if ($null -eq $rows) { "" | Set-Content -Path $path -Encoding utf8; return }
  $rows | Export-Csv -NoTypeInformation -Path $path -Encoding utf8
}

Write-ModCsv 'HostInfo' @(
  [pscustomobject]@{
    ComputerName = $hostName
    Domain = $env:USERDOMAIN
    User = $env:USERNAME
    OS = [Environment]::OSVersion.VersionString
    CapturedUtc = [DateTime]::UtcNow.ToString('o')
  }
)

try { Write-ModCsv 'Arp' (Get-NetNeighbor -ErrorAction Stop | Select-Object *) } catch {
  Write-ModCsv 'Arp' (arp -a)
}
try { Write-ModCsv 'DNSCache' (Get-DnsClientCache -ErrorAction Stop) } catch {
  Write-ModCsv 'DNSCache' @()
}
try { Write-ModCsv 'Netstat' (Get-NetTCPConnection -ErrorAction Stop) } catch {
  Write-ModCsv 'Netstat' @()
}
try { Write-ModCsv 'LocalAdmins' (Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop) } catch {
  Write-ModCsv 'LocalAdmins' @()
}
try { Write-ModCsv 'ProcsWMI' (Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,CreationDate,ExecutablePath) } catch {
  Write-ModCsv 'ProcsWMI' @()
}
try { Write-ModCsv 'SvcAll' (Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName) } catch {
  Write-ModCsv 'SvcAll' @()
}
try { Write-ModCsv 'SvcFail' (Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000,7023,7031,7034} -MaxEvents 200 -ErrorAction Stop) } catch {
  Write-ModCsv 'SvcFail' @()
}
try { Write-ModCsv 'SvcTrigs' (Get-ScheduledTask -ErrorAction Stop | Select-Object TaskName,TaskPath,State) } catch {
  Write-ModCsv 'SvcTrigs' @()
}
try { Write-ModCsv 'Tasklistv' (Get-Process | Select-Object Id,ProcessName,Path,StartTime,Company) } catch {
  Write-ModCsv 'Tasklistv' @()
}
try { Write-ModCsv 'SmbSession' (Get-SmbSession -ErrorAction Stop) } catch {
  Write-ModCsv 'SmbSession' @()
}
try {
  $ua = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count' -ErrorAction Stop
  Write-ModCsv 'LogUserAssist' $ua
} catch { Write-ModCsv 'LogUserAssist' @() }

$tmp = @()
try { $tmp = Get-ChildItem -Force $env:TEMP -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTime } catch {}
Write-ModCsv 'TempDirListing' $tmp

function Get-WmiNs($class) {
  try { Get-CimInstance -Namespace 'root\subscription' -ClassName $class -ErrorAction Stop } catch { @() }
}
Write-ModCsv 'WMIEvtConsumer' (Get-WmiNs 'CommandLineEventConsumer')
Write-ModCsv 'WMIEvtFilter' (Get-WmiNs 'EventFilter')
Write-ModCsv 'WMIFltConBind' (Get-WmiNs 'FilterToConsumerBinding')

$ar = Get-Command autorunsc.exe -ErrorAction SilentlyContinue
if ($ar) {
  $dir = Join-Path $OutDir 'Autorunsc'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  & autorunsc.exe -accepteula -nobanner -a * -c * | Out-File -Encoding utf8 (Join-Path $dir ("{0}-Autorunsc.csv" -f $hostName))
} else {
  try {
    Write-ModCsv 'Autorunsc' (Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User)
  } catch { Write-ModCsv 'Autorunsc' @() }
}
'''


def _write_builtin(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(BUILTIN_PS1.strip() + "\n", encoding="utf-8")
    return dest


def _write_local_runner(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(KANSA_LOCAL_PS1.strip() + "\n", encoding="utf-8")
    return dest


def _prepare_kansa_tree(dest: Path) -> Path | None:
    """Copy Kansa Modules + bin deps into dest for a no-WinRM local run."""
    home = kansa_home()
    if not home:
        return None
    dest.mkdir(parents=True, exist_ok=True)
    ps1 = home / "kansa.ps1"
    if ps1.is_file():
        shutil.copy2(ps1, dest / "kansa.ps1")
    src_mod = home / "Modules"
    dst_mod = dest / "Modules"
    if src_mod.is_dir():
        if dst_mod.exists():
            shutil.rmtree(dst_mod)
        shutil.copytree(
            src_mod,
            dst_mod,
            ignore=shutil.ignore_patterns("Output_*", ".git", "__pycache__"),
        )
    bin_dir = dest / "Modules" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    copies = {
        "autorunsc": ("autorunsc.exe", "Autorunsc.exe"),
        "handle": ("Handle.exe", "handle.exe"),
        "listdlls": ("Listdlls.exe", "listdlls.exe"),
        "tcpvcon": ("Tcpvcon.exe", "tcpvcon.exe"),
    }
    for name, aliases in copies.items():
        exe = sysinternals_exe(name)
        if not exe:
            continue
        for alias in aliases:
            shutil.copy2(exe, bin_dir / alias)
    (dest / "Modules" / "Modules.conf").write_text(KANSA_FULL_CONF, encoding="utf-8")
    return dest


def kansa_ps1_argv(real: Path, target: str) -> list[str]:
    """Dave Hull Kansa.ps1 has no -OutputPath; output is Output_<timestamp> next to the script."""
    return [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(real),
        "-Target", target,
        "-ModulePath", str(real.parent / "Modules"),
        "-Authentication", "Negotiate",
        "-Quiet",
    ]


def _harvest_kansa_output(kansa_home: Path, dest: Path) -> Path | None:
    outs = [p for p in kansa_home.glob("Output_*") if p.is_dir()]
    if not outs:
        return None
    src = max(outs, key=lambda p: p.stat().st_mtime)
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / src.name
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(src, target)
    shutil.rmtree(src, ignore_errors=True)
    return target


def run_kansa(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("kansa", "skipped", "Kansa is Windows-only")
    home = kansa_home()
    engine = "kansa-local-full" if home else "builtin_volatile"
    out_local = pack_host / "kansa"
    detail = {
        "engine": engine,
        "modules": list(DEFAULT_KANSA_MODULES) if engine == "builtin_volatile" else "Modules.conf full IR set",
    }
    if dry_run:
        return CollectorStep("kansa", "planned", path=str(out_local), detail=detail)

    out_local.mkdir(parents=True, exist_ok=True)
    script_builtin = _write_builtin(pack_host / "_scripts" / "kansa_volatile.ps1")

    if home:
        stage = _prepare_kansa_tree(pack_host / "_scripts" / "kansa-tree")
        runner = _write_local_runner(pack_host / "_scripts" / "kansa_local.ps1")
        conf = (stage / "Modules" / "Modules.conf") if stage else None
        if stage and conf and conf.is_file():
            step = _run_kansa_local(
                spec, transport, stage, runner, conf, out_local, opts, detail
            )
            if step.status == "ok":
                return step
            detail["kansa_local"] = step.reason
            detail["fallback"] = "builtin after kansa-local-full failed"

    if isinstance(transport, LocalTransport):
        result = _run_local(
            [
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script_builtin), "-OutDir", str(out_local),
            ],
            opts.timeout_kansa,
        )
        if not result.ok:
            return CollectorStep("kansa", "failed", (result.stderr or result.stdout)[:500], path=str(out_local), detail=detail)
        return CollectorStep("kansa", "ok", path=str(out_local), detail={**detail, "engine": "builtin_volatile"})

    remote_root = transport.remote_temp().rstrip("/\\") + "/kansa"
    put = transport.put_file(script_builtin, remote_root.replace("\\", "/") + "/kansa_volatile.ps1")
    if not put.ok:
        return CollectorStep("kansa", "failed", f"stage script: {put.stderr[:400]}", detail=detail)
    remote_out = remote_root + "/out"
    ps = (
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        f"{remote_root}\\kansa_volatile.ps1 -OutDir {remote_out}"
    )
    result = transport.run(ps.replace("/", "\\"), timeout=opts.timeout_kansa)
    if not result.ok:
        return CollectorStep("kansa", "failed", (result.stderr or result.stdout)[:500], detail=detail)
    pull = transport.get_tree(remote_out, out_local, timeout=opts.timeout_kansa)
    if not pull.ok:
        return CollectorStep("kansa", "failed", f"pull: {pull.stderr[:400]}", path=str(out_local), detail=detail)
    return CollectorStep("kansa", "ok", path=str(out_local), detail={**detail, "engine": "builtin_volatile"})


def _run_kansa_local(
    spec: HostSpec,
    transport: Transport,
    tree: Path,
    runner: Path,
    conf: Path,
    out_local: Path,
    opts: CollectOptions,
    detail: dict,
) -> CollectorStep:
    argv = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(runner),
        "-KansaHome", str(tree),
        "-OutDir", str(out_local),
        "-ConfFile", str(conf),
    ]
    if isinstance(transport, LocalTransport):
        result = _run_local(argv, opts.timeout_kansa)
        if not result.ok:
            return CollectorStep("kansa", "failed", (result.stderr or result.stdout)[:500], path=str(out_local), detail=detail)
        return CollectorStep("kansa", "ok", path=str(out_local), detail=detail)

    remote = transport.remote_temp().rstrip("/\\") + "/kansa-full"
    put = transport.put_tree(tree, remote, timeout=opts.timeout_kansa)
    if not put.ok:
        return CollectorStep("kansa", "failed", f"stage kansa tree: {put.stderr[:400]}", detail=detail)
    put_r = transport.put_file(runner, remote.replace("\\", "/") + "/kansa_local.ps1")
    if not put_r.ok:
        return CollectorStep("kansa", "failed", f"stage runner: {put_r.stderr[:300]}", detail=detail)
    remote_out = remote + "/out"
    remote_conf = remote.replace("/", "\\") + "\\Modules\\Modules.conf"
    remote_home = remote.replace("/", "\\")
    ps = (
        f"powershell.exe -NoProfile -ExecutionPolicy Bypass -File "
        f"{remote_home}\\kansa_local.ps1 -KansaHome {remote_home} "
        f"-OutDir {remote_out.replace('/', '\\')} -ConfFile {remote_conf}"
    )
    result = transport.run(ps, timeout=opts.timeout_kansa)
    if not result.ok:
        return CollectorStep("kansa", "failed", (result.stderr or result.stdout)[:500], detail=detail)
    pull = transport.get_tree(remote_out, out_local, timeout=opts.timeout_kansa)
    if not pull.ok:
        return CollectorStep("kansa", "failed", f"pull: {pull.stderr[:400]}", path=str(out_local), detail=detail)
    return CollectorStep("kansa", "ok", path=str(out_local), detail=detail)
