"""Stage 0 IR orchestrator — live collect with auth, pack on disk, no interpretation."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

from nexus.collect.extra_windows import (
    run_chainsaw,
    run_hayabusa,
    run_persistencesniper,
    run_suzaku,
    run_sysinternals,
    run_wevtutil,
)
from nexus.collect.kansa import run_kansa
from nexus.collect.kape import run_kape
from nexus.collect.linux import run_linux
from nexus.collect.memory import run_winpmem
from nexus.collect.orc import run_orc
from nexus.collect.paths import tool_inventory
from nexus.collect.transport import connect
from nexus.collect.types import (
    CollectManifest,
    CollectOptions,
    CollectorStep,
    HostResult,
    HostSpec,
)
from nexus.collect.vr import run_vr, vr_step


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_pack_dir(case_dir: Path | None = None) -> Path:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    if case_dir is not None:
        return Path(case_dir) / "collect" / f"pack-{stamp}"
    return Path.cwd() / "collect-packs" / f"pack-{stamp}"


def _safe_hostname(spec: HostSpec, probe_stdout: str) -> str:
    if spec.hostname.strip():
        return spec.hostname.strip()
    line = (probe_stdout or "").strip().splitlines()
    if line and line[0].strip() and " " not in line[0].strip():
        return line[0].strip()
    if spec.address and spec.address not in {"localhost", "127.0.0.1"}:
        return spec.address.replace(".", "-")
    import socket
    return socket.gethostname()


def plan_or_run(
    spec: HostSpec,
    opts: CollectOptions,
    pack_dir: Path,
    *,
    dry_run: bool,
    probe: bool,
    examiner: str = "",
) -> CollectManifest:
    pack_dir = Path(pack_dir)
    pack_dir.mkdir(parents=True, exist_ok=True)
    started = _utc_now()
    transport = connect(spec)
    probe_out = ""
    steps: list[CollectorStep] = []

    if probe or not dry_run:
        pr = transport.probe(timeout=opts.timeout_probe)
        probe_out = pr.stdout
        if not pr.ok:
            steps.append(CollectorStep(
                "auth",
                "failed",
                (pr.stderr or pr.stdout or "probe failed")[:500],
                detail={"transport": spec.transport, "address": spec.address, "user": spec.auth.user},
            ))
            host = HostResult(
                hostname=_safe_hostname(spec, probe_out),
                address=spec.address,
                os=spec.os,
                transport=spec.transport,
                user=spec.auth.user,
                steps=steps,
            )
            manifest = CollectManifest(
                started=started,
                finished=_utc_now(),
                examiner=examiner,
                pack_dir=str(pack_dir),
                dry_run=dry_run,
                hosts=[host],
                next_hint="Fix authentication (--identity or NEXUS_COLLECT_PASSWORD) and retry.",
            )
            _write_manifest(pack_dir, manifest)
            return manifest
        steps.append(CollectorStep("auth", "ok" if not dry_run else "planned", "probe succeeded"))

    hostname = _safe_hostname(spec, probe_out)
    pack_host = pack_dir / "hosts" / _fs_safe(hostname)
    pack_host.mkdir(parents=True, exist_ok=True)

    if spec.os == "windows":
        steps.extend(_run_windows(spec, transport, pack_host, opts, dry_run=dry_run))
    else:
        steps.extend(run_linux(spec, transport, pack_host, opts, dry_run=dry_run))

    if dry_run:
        steps.append(vr_step(wanted=opts.vr))
    else:
        steps.append(run_vr(
            spec, pack_host,
            wanted=opts.vr, dry_run=False,
            client_id=opts.vr_client_id,
            timeout=opts.timeout_vr,
        ))

    host = HostResult(
        hostname=hostname,
        address=spec.address,
        os=spec.os,
        transport=spec.transport,
        user=spec.auth.user,
        steps=steps,
    )
    hint = (
        f"nexus case init \"IR {hostname}\"   then   "
        f"nexus evidence register \"{pack_dir}\" -d \"Stage 0 pack {hostname}\""
    )
    manifest = CollectManifest(
        started=started,
        finished=_utc_now(),
        examiner=examiner,
        pack_dir=str(pack_dir),
        dry_run=dry_run,
        hosts=[host],
        next_hint=hint,
    )
    _write_manifest(pack_dir, manifest)
    return manifest


def _run_windows(
    spec: HostSpec,
    transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> list[CollectorStep]:
    """Volatility order: live volatile first, disk collectors, memory last."""
    steps: list[CollectorStep] = []
    if opts.kansa:
        steps.append(run_kansa(spec, transport, pack_host, opts, dry_run=dry_run))
    else:
        steps.append(CollectorStep("kansa", "skipped", "disabled"))
    steps.append(run_sysinternals(spec, transport, pack_host, opts, dry_run=dry_run))
    steps.append(run_persistencesniper(spec, transport, pack_host, opts, dry_run=dry_run))
    steps.append(run_wevtutil(spec, transport, pack_host, opts, dry_run=dry_run))
    steps.append(run_hayabusa(spec, transport, pack_host, opts, dry_run=dry_run))
    steps.append(run_suzaku(spec, transport, pack_host, opts, dry_run=dry_run))
    steps.append(run_chainsaw(spec, transport, pack_host, opts, dry_run=dry_run))
    if opts.kape:
        steps.append(run_kape(spec, transport, pack_host, opts, dry_run=dry_run))
    else:
        steps.append(CollectorStep("kape", "skipped", "disabled"))
    steps.append(run_orc(spec, transport, pack_host, opts, dry_run=dry_run))
    steps.append(run_winpmem(spec, transport, pack_host, opts, dry_run=dry_run))
    return steps


def import_dump(
    dump: Path,
    *,
    os_name: str,
    hostname: str,
    pack_dir: Path,
    examiner: str = "",
    copy: bool = False,
) -> CollectManifest:
    """Register an existing KAPE/Kansa/UAC dump as a Stage 0 pack (not a live run)."""
    dump = Path(dump)
    if not dump.exists():
        raise FileNotFoundError(dump)
    pack_dir = Path(pack_dir)
    host_dir = pack_dir / "hosts" / _fs_safe(hostname or dump.name)
    dest = host_dir / "import"
    dest.mkdir(parents=True, exist_ok=True)
    pointer = {
        "source": str(dump.resolve()),
        "copied": copy,
        "os": os_name,
        "note": "Existing IR dump. Stage 0 live collect was not run.",
    }
    if copy:
        if dump.is_file():
            shutil.copy2(dump, dest / dump.name)
        else:
            shutil.copytree(dump, dest / dump.name, dirs_exist_ok=True)
        pointer["pack_rel"] = str((dest / dump.name).relative_to(pack_dir)).replace("\\", "/")
    (dest / "source.json").write_text(json.dumps(pointer, indent=2), encoding="utf-8")
    step = CollectorStep(
        "import",
        "ok",
        "by-reference" if not copy else "copied",
        path=str(dest),
        detail=pointer,
    )
    host = HostResult(
        hostname=hostname or dump.name,
        address="",
        os=os_name,  # type: ignore[arg-type]
        transport="local",
        user="",
        steps=[step, vr_step(wanted=True)],
    )
    manifest = CollectManifest(
        started=_utc_now(),
        finished=_utc_now(),
        examiner=examiner,
        pack_dir=str(pack_dir),
        dry_run=False,
        hosts=[host],
        next_hint=f"nexus evidence register \"{pack_dir}\" -d \"imported dump {hostname}\"",
    )
    _write_manifest(pack_dir, manifest)
    return manifest


def _write_manifest(pack_dir: Path, manifest: CollectManifest) -> None:
    pack_dir.mkdir(parents=True, exist_ok=True)
    path = pack_dir / "manifest.json"
    blob = manifest.to_dict()
    blob["auth"] = "never stored — use --identity or env NEXUS_COLLECT_PASSWORD"
    blob["tools"] = tool_inventory()
    path.write_text(json.dumps(blob, indent=2), encoding="utf-8")


def _fs_safe(name: str) -> str:
    keep = []
    for ch in name.strip() or "host":
        keep.append(ch if ch.isalnum() or ch in "-_." else "-")
    return "".join(keep)[:80] or "host"
