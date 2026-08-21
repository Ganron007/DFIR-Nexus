"""Stage 0 — live IR collect with authentication.

This is a live run against a host (SSH / WinRM / local), not an analysis dump.
`nexus collect import` is the helper when you already have a KAPE/Kansa/UAC tree.

Default profile is **full** (every FOSS collector we can run). Opt out with
`--profile disk|volatile`, `--only kansa,kape,...`, or `--no-*`.
"""

from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="Stage 0 IR orchestrator — live collect with auth")


def _echo_manifest(manifest) -> None:
    import json

    typer.echo(json.dumps(manifest.to_dict(), indent=2))
    typer.echo(f"\nWrote {Path(manifest.pack_dir) / 'manifest.json'}")
    if manifest.next_hint:
        typer.echo(manifest.next_hint)


@app.command("tools")
def tools_cmd() -> None:
    """Show every Stage 0 collector binary and Velociraptor live status."""
    from nexus.collect.paths import kape_list, tool_inventory
    from nexus.collect.profiles import ALL_COLLECTORS, PROFILES
    from nexus.collect.vr import vr_live_status

    inv = tool_inventory()
    live, reason = vr_live_status()
    typer.echo("Stage 0 tool inventory (profile default: full)")
    for k, v in inv.items():
        typer.echo(f"  {k}: {v}")
    typer.echo(f"  velociraptor_live: {live} ({reason})")
    compounds = [r["name"] for r in kape_list("targets") if r["name"].startswith("!")]
    if compounds:
        typer.echo("  kape compound targets: " + ", ".join(compounds))
    mods = [r["name"] for r in kape_list("modules") if r["name"].startswith("!")]
    if mods:
        typer.echo("  kape compound modules: " + ", ".join(mods))
    typer.echo("  collectors: " + ", ".join(ALL_COLLECTORS))
    typer.echo("  profiles: " + ", ".join(f"{n}={len(s)}" for n, s in PROFILES.items()))
    typer.echo("  default windows: Kansa-full + Sysinternals + PersistenceSniper + wevtutil")
    typer.echo("                 + Hayabusa + Suzaku + Chainsaw + KAPE !SANS_Triage/!EZParser")
    typer.echo("                 + DFIR-ORC + WinPmem + live Velociraptor hunts")
    typer.echo("  default linux: POSIX volatile + journalctl + UAC -p full + AVML + VR")
    typer.echo("  opt out: --profile disk|volatile   --only kansa,kape   --no-memory --no-vr")


def _plan_run_opts(
    os_name: str,
    host: str,
    user: str,
    identity: str,
    transport: str,
    hostname: str,
    kape_target: str,
    kape_module: str,
    kape_remote_path: str,
    profile: str,
    only: str,
    no_kansa: bool,
    no_kape: bool,
    no_orc: bool,
    no_uac: bool,
    no_vr: bool,
    no_hayabusa: bool,
    no_suzaku: bool,
    no_chainsaw: bool,
    no_sysinternals: bool,
    no_wevtutil: bool,
    no_psniper: bool,
    no_journal: bool,
    no_volatile: bool,
    memory: bool | None,
    vr_client_id: str,
    tsource: str,
    sudo: bool,
):
    from nexus.collect.profiles import apply_enabled, enabled_set
    from nexus.collect.types import AuthSpec, CollectOptions, HostSpec

    os_l = os_name.strip().lower()
    if os_l not in {"windows", "linux"}:
        typer.echo("--os must be windows or linux", err=True)
        raise typer.Exit(2)
    host_l = host.strip() or "localhost"
    tr = transport.strip().lower()
    if not tr:
        tr = "local" if host_l in {"localhost", "127.0.0.1", "::1"} else "ssh"
    if tr not in {"local", "ssh", "winrm"}:
        typer.echo("--transport must be local, ssh, or winrm", err=True)
        raise typer.Exit(2)
    spec = HostSpec(
        os=os_l,  # type: ignore[arg-type]
        address=host_l,
        hostname=hostname.strip(),
        transport=tr,  # type: ignore[arg-type]
        auth=AuthSpec(user=user.strip(), identity=identity.strip()),
        sudo=sudo,
        tsource=tsource.strip(),
    )
    module = kape_module.strip()
    if module.lower() in {"none", "off", "-"}:
        module = ""
    disable: list[str] = []
    if no_kansa:
        disable.append("kansa")
    if no_kape:
        disable.append("kape")
    if no_orc:
        disable.append("orc")
    if no_uac:
        disable.append("uac")
    if no_vr:
        disable.append("velociraptor")
    if no_hayabusa:
        disable.append("hayabusa")
    if no_suzaku:
        disable.append("suzaku")
    if no_chainsaw:
        disable.append("chainsaw")
    if no_sysinternals:
        disable.append("sysinternals")
    if no_wevtutil:
        disable.append("wevtutil")
    if no_psniper:
        disable.append("persistencesniper")
    if no_journal:
        disable.append("journal")
    if no_volatile:
        disable.append("linux_volatile")
    if memory is False:
        disable.extend(["winpmem", "avml"])
    try:
        enabled = enabled_set(profile, only=only, disable=disable)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc
    if memory is True:
        enabled.add("winpmem")
        enabled.add("avml")
    opts = CollectOptions(
        profile=profile.strip().lower() or "full",
        kape_target=kape_target.strip() or "!SANS_Triage",
        kape_module=module,
        kape_remote_path=kape_remote_path,
        vr_client_id=vr_client_id.strip(),
    )
    apply_enabled(opts, enabled)
    return spec, opts


@app.command("plan")
def plan_cmd(
    os_name: str = typer.Option(..., "--os", help="windows | linux"),
    host: str = typer.Option("localhost", "--host", "-H", help="Target address"),
    user: str = typer.Option("", "--user", "-u"),
    identity: str = typer.Option("", "--identity", "-i", help="SSH private key (never a password)"),
    transport: str = typer.Option("", "--transport", help="local | ssh | winrm (default: local if host is localhost else ssh)"),
    hostname: str = typer.Option("", "--hostname", help="Name for pack/hosts/<name>/"),
    profile: str = typer.Option("full", "--profile", help="full | disk | volatile"),
    only: str = typer.Option("", "--only", help="Comma list of collectors (overrides profile)"),
    kape_target: str = typer.Option("!SANS_Triage", "--kape-target"),
    kape_module: str = typer.Option("!EZParser", "--kape-module", help="none to skip KAPE parse"),
    no_kansa: bool = typer.Option(False, "--no-kansa"),
    no_kape: bool = typer.Option(False, "--no-kape"),
    no_orc: bool = typer.Option(False, "--no-orc"),
    no_uac: bool = typer.Option(False, "--no-uac"),
    no_vr: bool = typer.Option(False, "--no-vr"),
    no_hayabusa: bool = typer.Option(False, "--no-hayabusa"),
    no_suzaku: bool = typer.Option(False, "--no-suzaku"),
    no_chainsaw: bool = typer.Option(False, "--no-chainsaw"),
    no_sysinternals: bool = typer.Option(False, "--no-sysinternals"),
    no_wevtutil: bool = typer.Option(False, "--no-wevtutil"),
    no_psniper: bool = typer.Option(False, "--no-psniper"),
    no_journal: bool = typer.Option(False, "--no-journal"),
    no_volatile: bool = typer.Option(False, "--no-volatile", help="Skip POSIX linux_volatile snapshot"),
    memory: bool | None = typer.Option(None, "--memory/--no-memory", help="Override profile for WinPmem/AVML"),
    vr_client_id: str = typer.Option("", "--vr-client-id"),
    tsource: str = typer.Option("", "--tsource", help="KAPE source (live C: or mounted image)"),
    sudo: bool = typer.Option(False, "--sudo", help="Linux: prefix UAC/AVML with sudo"),
    out: Path = typer.Option(Path("collect-packs/plan"), "--out", help="Pack directory"),
) -> None:
    """Print what would run. Does not collect. Use `run --probe` to test auth."""
    spec, opts = _plan_run_opts(
        os_name, host, user, identity, transport, hostname, kape_target, kape_module, "",
        profile, only, no_kansa, no_kape, no_orc, no_uac, no_vr, no_hayabusa, no_suzaku,
        no_chainsaw, no_sysinternals, no_wevtutil, no_psniper, no_journal, no_volatile, memory,
        vr_client_id, tsource, sudo,
    )
    from nexus.audit import resolve_examiner
    from nexus.collect.orchestrator import plan_or_run

    manifest = plan_or_run(spec, opts, out, dry_run=True, probe=False, examiner=resolve_examiner())
    _echo_manifest(manifest)


@app.command("run")
def run_cmd(
    os_name: str = typer.Option(..., "--os", help="windows | linux"),
    host: str = typer.Option("localhost", "--host", "-H"),
    user: str = typer.Option("", "--user", "-u"),
    identity: str = typer.Option("", "--identity", "-i", help="SSH private key path"),
    transport: str = typer.Option("", "--transport", help="local | ssh | winrm"),
    hostname: str = typer.Option("", "--hostname"),
    profile: str = typer.Option("full", "--profile", help="full | disk | volatile"),
    only: str = typer.Option("", "--only", help="Comma list of collectors (overrides profile)"),
    kape_target: str = typer.Option("!SANS_Triage", "--kape-target"),
    kape_module: str = typer.Option("!EZParser", "--kape-module", help="Pass none to acquire only"),
    kape_remote_path: str = typer.Option("", "--kape-remote-path", help="KAPE already installed on the target"),
    no_kansa: bool = typer.Option(False, "--no-kansa"),
    no_kape: bool = typer.Option(False, "--no-kape"),
    no_orc: bool = typer.Option(False, "--no-orc"),
    no_uac: bool = typer.Option(False, "--no-uac"),
    no_vr: bool = typer.Option(False, "--no-vr"),
    no_hayabusa: bool = typer.Option(False, "--no-hayabusa"),
    no_suzaku: bool = typer.Option(False, "--no-suzaku"),
    no_chainsaw: bool = typer.Option(False, "--no-chainsaw"),
    no_sysinternals: bool = typer.Option(False, "--no-sysinternals"),
    no_wevtutil: bool = typer.Option(False, "--no-wevtutil"),
    no_psniper: bool = typer.Option(False, "--no-psniper"),
    no_journal: bool = typer.Option(False, "--no-journal"),
    no_volatile: bool = typer.Option(False, "--no-volatile", help="Skip POSIX linux_volatile snapshot"),
    memory: bool | None = typer.Option(None, "--memory/--no-memory"),
    vr_client_id: str = typer.Option("", "--vr-client-id", help="Velociraptor client id if hostname match fails"),
    tsource: str = typer.Option("", "--tsource"),
    sudo: bool = typer.Option(False, "--sudo"),
    probe: bool = typer.Option(True, "--probe/--no-probe", help="Auth check before collectors"),
    out: Path | None = typer.Option(None, "--out"),
    case_id: str = typer.Option("", "--case", help="Write pack under this case's collect/"),
    port: int = typer.Option(0, "--port", help="SSH 22 / WinRM 5985 default"),
) -> None:
    """Live collect. Password SSH/WinRM: set NEXUS_COLLECT_PASSWORD (never argv)."""
    spec, opts = _plan_run_opts(
        os_name, host, user, identity, transport, hostname, kape_target, kape_module,
        kape_remote_path, profile, only, no_kansa, no_kape, no_orc, no_uac, no_vr,
        no_hayabusa, no_suzaku, no_chainsaw, no_sysinternals, no_wevtutil, no_psniper,
        no_journal, no_volatile, memory, vr_client_id, tsource, sudo,
    )
    spec.auth.port = port
    from nexus.audit import resolve_examiner
    from nexus.collect.orchestrator import default_pack_dir, plan_or_run
    from nexus.config import settings

    case_dir = None
    if case_id:
        case_dir = settings.cases_root / case_id
        if not case_dir.is_dir():
            typer.echo(f"Case directory missing: {case_dir}", err=True)
            raise typer.Exit(1)
    pack = out or default_pack_dir(case_dir)
    typer.echo(f"Stage 0 live collect profile={opts.profile} → {pack}")
    typer.echo(f"  {spec.os} {spec.transport} {spec.auth.user}@{spec.address}")
    manifest = plan_or_run(
        spec, opts, pack, dry_run=False, probe=probe, examiner=resolve_examiner()
    )
    _echo_manifest(manifest)
    failed = [s for h in manifest.hosts for s in h.steps if s.status == "failed"]
    if failed:
        raise typer.Exit(1)


@app.command("import")
def import_cmd(
    dump: Path = typer.Argument(..., exists=True, readable=True, help="Existing KAPE/Kansa/UAC tree or file"),
    os_name: str = typer.Option("windows", "--os"),
    hostname: str = typer.Option("imported-host", "--hostname"),
    copy: bool = typer.Option(False, "--copy", help="Copy dump into the pack (default: pointer only)"),
    out: Path | None = typer.Option(None, "--out"),
    case_id: str = typer.Option("", "--case"),
) -> None:
    """Turn an existing IR dump into a Stage 0 pack. This is not a live collect."""
    from nexus.audit import resolve_examiner
    from nexus.collect.orchestrator import default_pack_dir, import_dump
    from nexus.config import settings

    case_dir = None
    if case_id:
        case_dir = settings.cases_root / case_id
        if not case_dir.is_dir():
            typer.echo(f"Case directory missing: {case_dir}", err=True)
            raise typer.Exit(1)
    pack = out or default_pack_dir(case_dir)
    manifest = import_dump(
        dump,
        os_name=os_name,
        hostname=hostname,
        pack_dir=pack,
        examiner=resolve_examiner(),
        copy=copy,
    )
    _echo_manifest(manifest)
