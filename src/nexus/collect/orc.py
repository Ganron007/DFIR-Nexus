"""DFIR-ORC (ANSSI) — Windows forensic snapshot. Collect only; N2 parses."""

from __future__ import annotations

from pathlib import Path

from nexus.collect.paths import orc_exe
from nexus.collect.transport import LocalTransport, Transport, _run_local
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec


def orc_argv(exe: Path, out_dir: str) -> list[str]:
    return [str(exe), f"/Out={out_dir}"]


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
    detail = {"engine": "DFIR-ORC", "note": "collect-only snapshot; N2 parses"}
    if not exe:
        return CollectorStep(
            "dfir_orc",
            "skipped",
            "DFIR-ORC.exe not found (Tools/windows/orc or NEXUS_ORC)",
            detail=detail,
        )
    detail["exe"] = str(exe)
    if dry_run:
        detail["argv"] = orc_argv(exe, str(out_local))
        return CollectorStep("dfir_orc", "planned", path=str(out_local), detail=detail)

    out_local.mkdir(parents=True, exist_ok=True)
    if isinstance(transport, LocalTransport):
        result = _run_local(orc_argv(exe, str(out_local)), opts.timeout_orc)
        if not result.ok:
            return CollectorStep(
                "dfir_orc",
                "failed",
                (result.stderr or result.stdout or "orc failed")[:500],
                path=str(out_local),
                detail=detail,
            )
        return CollectorStep("dfir_orc", "ok", path=str(out_local), detail=detail)

    remote_root = transport.remote_temp().rstrip("/\\") + "/orc"
    win_root = remote_root.replace("/", "\\")
    transport.run(f"cmd.exe /c mkdir {win_root}", timeout=30)
    put = transport.put_file(exe, remote_root.replace("\\", "/") + "/DFIR-ORC.exe")
    if not put.ok:
        return CollectorStep("dfir_orc", "failed", f"stage: {put.stderr[:400]}", detail=detail)
    remote_out = remote_root + "/out"
    transport.run(f"cmd.exe /c mkdir {remote_out.replace('/', '\\\\')}", timeout=30)
    remote_exe = remote_root.replace("/", "\\") + "\\DFIR-ORC.exe"
    result = transport.run(
        f"{remote_exe} /Out={remote_out.replace('/', '\\\\')}",
        timeout=opts.timeout_orc,
    )
    if not result.ok:
        return CollectorStep(
            "dfir_orc",
            "failed",
            (result.stderr or result.stdout or "remote orc failed")[:500],
            detail=detail,
        )
    pull = transport.get_tree(remote_out, out_local, timeout=opts.timeout_orc)
    if not pull.ok:
        return CollectorStep("dfir_orc", "failed", f"pull: {pull.stderr[:400]}", path=str(out_local), detail=detail)
    return CollectorStep("dfir_orc", "ok", path=str(out_local), detail=detail)
