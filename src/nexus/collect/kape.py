"""KAPE acquire + optional EZParser module pass."""

from __future__ import annotations

from pathlib import Path

from nexus.collect.paths import kape_exe, kape_home
from nexus.collect.transport import LocalTransport, Transport
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec


def kape_argv(
    exe: Path,
    *,
    tsource: str,
    tdest: str,
    target: str,
    module: str = "",
    msource: str = "",
    mdest: str = "",
) -> list[str]:
    argv = [
        str(exe),
        "--tsource", tsource,
        "--tdest", tdest,
        "--target", target,
    ]
    if module.strip():
        src = msource or tdest
        dst = mdest or str(Path(tdest).parent / "modules")
        argv.extend(["--msource", src, "--mdest", dst, "--module", module])
    return argv


def _ps_join(argv: list[str]) -> str:
    parts = []
    for a in argv:
        if not a:
            continue
        if any(c in a for c in " \t\"'"):
            parts.append("'" + a.replace("'", "''") + "'")
        else:
            parts.append(a)
    return " ".join(parts)


def run_kape(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    exe = kape_exe()
    home = kape_home()
    target = opts.kape_target or "!SANS_Triage"
    raw_mod = (opts.kape_module or "").strip()
    module = "" if raw_mod.lower() in {"none", "off", "-", ""} else raw_mod
    tsource = spec.tsource or ("C:" if spec.os == "windows" else "")
    detail = {"target": target, "module": module or "(acquire only)", "tsource": tsource}

    if spec.os != "windows":
        return CollectorStep("kape", "skipped", "KAPE is Windows-only", detail=detail)
    if not exe or not home:
        return CollectorStep(
            "kape",
            "skipped",
            "kape.exe not found (Tools/windows/kape or NEXUS_KAPE_HOME)",
            detail=detail,
        )

    out_local = pack_host / "kape"
    if dry_run:
        argv = kape_argv(exe, tsource=tsource, tdest=str(out_local / "targets"), target=target, module=module)
        detail["argv"] = argv
        return CollectorStep("kape", "planned", path=str(out_local), detail=detail)

    if isinstance(transport, LocalTransport):
        out_local.mkdir(parents=True, exist_ok=True)
        tdest = str(out_local / "targets")
        mdest = str(out_local / "modules")
        argv = kape_argv(exe, tsource=tsource, tdest=tdest, target=target, module=module, mdest=mdest)
        from nexus.collect.transport import _run_local

        result = _run_local(argv, opts.timeout_kape)
        if not result.ok:
            return CollectorStep(
                "kape",
                "failed",
                (result.stderr or result.stdout or "kape failed")[:500],
                path=str(out_local),
                detail=detail,
            )
        return CollectorStep("kape", "ok", path=str(out_local), detail=detail)

    remote_root = opts.kape_remote_path.strip() or (transport.remote_temp().rstrip("/\\") + "/kape-bin")
    staged = True
    if opts.kape_remote_path.strip():
        staged = False
    else:
        put = transport.put_tree(home, remote_root, timeout=opts.timeout_kape)
        if not put.ok:
            return CollectorStep("kape", "failed", f"stage kape: {put.stderr[:400]}", detail=detail)

    remote_out = transport.remote_temp().rstrip("/\\") + "/kape-out"
    remote_tdest = remote_out + "/targets"
    remote_mdest = remote_out + "/modules"
    remote_exe = remote_root.replace("\\", "/") + "/kape.exe"
    argv = kape_argv(
        Path(remote_exe),
        tsource=tsource,
        tdest=remote_tdest,
        target=target,
        module=module,
        mdest=remote_mdest,
    )
    # Remote process: cmd-style paths for Windows.
    cmd = _ps_join(argv)
    transport.run(f"cmd.exe /c mkdir {remote_out.replace('/', '\\\\')}", timeout=30)
    result = transport.run(cmd, timeout=opts.timeout_kape)
    if not result.ok:
        return CollectorStep(
            "kape",
            "failed",
            (result.stderr or result.stdout or "remote kape failed")[:500],
            detail={**detail, "staged": staged},
        )
    out_local.mkdir(parents=True, exist_ok=True)
    pull = transport.get_tree(remote_out, out_local, timeout=opts.timeout_kape)
    if not pull.ok:
        return CollectorStep("kape", "failed", f"pull: {pull.stderr[:400]}", path=str(out_local), detail=detail)
    return CollectorStep("kape", "ok", path=str(out_local), detail={**detail, "staged": staged})
