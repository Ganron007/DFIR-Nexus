"""WinPmem optional memory step (Windows)."""

from __future__ import annotations

from nexus.collect.paths import winpmem_exe
from nexus.collect.transport import LocalTransport, Transport, _run_local
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec


def run_winpmem(
    spec: HostSpec,
    transport: Transport,
    pack_host,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> CollectorStep:
    if spec.os != "windows":
        return CollectorStep("winpmem", "skipped", "Windows-only")
    if not opts.memory:
        return CollectorStep("winpmem", "skipped", "disabled (profile / --no-memory)")
    exe = winpmem_exe()
    out = pack_host / "memory"
    if not exe:
        return CollectorStep("winpmem", "skipped", "winpmem not found (Tools/windows/memory)")
    if dry_run:
        return CollectorStep("winpmem", "planned", path=str(out / "physical.raw"))
    out.mkdir(parents=True, exist_ok=True)
    dest = out / "physical.raw"
    if isinstance(transport, LocalTransport):
        result = _run_local([str(exe), str(dest)], opts.timeout_memory)
        if not result.ok:
            return CollectorStep(
                "winpmem",
                "failed",
                (result.stderr or result.stdout or "winpmem failed — HVCI may block the driver")[:400],
                path=str(out),
            )
        return CollectorStep("winpmem", "ok", path=str(dest))
    remote = transport.remote_temp().rstrip("/\\") + "/memory"
    transport.run(f"mkdir {remote.replace('/', '\\\\')}", timeout=30)
    put = transport.put_file(exe, remote.replace("\\", "/") + "/winpmem.exe")
    if not put.ok:
        return CollectorStep("winpmem", "failed", f"stage: {put.stderr[:300]}")
    raw = remote + "/physical.raw"
    result = transport.run(
        f"{remote.replace('/', '\\\\')}\\winpmem.exe {raw.replace('/', '\\\\')}",
        timeout=opts.timeout_memory,
    )
    if not result.ok:
        return CollectorStep(
            "winpmem",
            "failed",
            (result.stderr or result.stdout or "remote winpmem failed")[:400],
        )
    pull = transport.get_tree(raw, dest, timeout=opts.timeout_memory)
    if not pull.ok:
        return CollectorStep("winpmem", "failed", f"pull: {pull.stderr[:300]}", path=str(out))
    return CollectorStep("winpmem", "ok", path=str(dest))
