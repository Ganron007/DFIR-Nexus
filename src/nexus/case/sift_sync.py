"""Pull SIFT-host case extractions onto the Windows examiner case.

Mechanism (no shared VM filesystem required):
  scp/rsync over SSH using NEXUS_SIFT_SSH_* settings.

Env::

    NEXUS_SIFT_SYNC       0 disables all SIFT sync (offline examiner host)
    NEXUS_SIFT_SSH_HOST   default 192.168.77.135
    NEXUS_SIFT_SSH_USER   default sansforensics
    NEXUS_SIFT_SSH_KEY    default ~/.ssh/cadre-sift-key
    NEXUS_SIFT_CASES_ROOT default ~/.nexus/cases  (on the remote)
    NEXUS_SIFT_CONNECT_TIMEOUT  default 10 (seconds; fail fast, never hang)
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_SSH_CONNECT_TIMEOUT = "10"


def sync_enabled() -> bool:
    """False when NEXUS_SIFT_SYNC=0 — examiner host runs without the SIFT VM."""
    return os.environ.get("NEXUS_SIFT_SYNC", "").strip().lower() not in (
        "0", "false", "no",
    )


def _ssh_opts() -> dict[str, str]:
    return {
        "host": os.environ.get("NEXUS_SIFT_SSH_HOST", "192.168.77.135").strip(),
        "user": os.environ.get("NEXUS_SIFT_SSH_USER", "sansforensics").strip(),
        "key": os.environ.get(
            "NEXUS_SIFT_SSH_KEY",
            str(Path.home() / ".ssh" / "cadre-sift-key"),
        ).strip(),
        "remote_cases": os.environ.get(
            "NEXUS_SIFT_CASES_ROOT",
            "/home/sansforensics/.nexus/cases",
        ).strip().rstrip("/"),
    }


def _scp_base(key: Path) -> list[str]:
    return [
        "scp",
        "-i", str(key),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_TIMEOUT}",
    ]


def sift_reachable() -> tuple[bool, str]:
    """Fast SSH reachability probe for doctor / preflight checks."""
    if not sync_enabled():
        return False, "SIFT sync disabled (NEXUS_SIFT_SYNC=0)"
    opts = _ssh_opts()
    key = Path(opts["key"])
    if not key.is_file():
        return False, f"SSH key missing: {opts['key']}"
    cmd = [
        "ssh",
        "-i", str(key),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_TIMEOUT}",
        f"{opts['user']}@{opts['host']}",
        "echo SIFT_OK",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"ssh failed: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or "ssh failed").strip()[:200]
    return True, (proc.stdout or "").strip().splitlines()[0] if (proc.stdout or "").strip() else "reachable"


def _scp_base(key: Path) -> list[str]:
    return [
        "scp",
        "-i", str(key),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_TIMEOUT}",
    ]


def pull_sift_extractions(
    case_id: str,
    local_case_dir: Path,
    local_output_dir: Path | None = None,
) -> Path | None:
    """scp remote case extractions into a new local destination."""
    if not sync_enabled():
        log.info("SIFT sync disabled (NEXUS_SIFT_SYNC=0) — skip pull")
        return None
    opts = _ssh_opts()
    key = Path(opts["key"])
    if not key.is_file():
        log.warning("SIFT SSH key missing: %s — skip pull", key)
        return None

    dest = Path(local_output_dir) if local_output_dir else Path(local_case_dir) / "sift" / "extractions"
    # A pull adds what the local copy does not have yet, and never overwrites a local file. An empty folder is
    # no copy: the lane creates one before the pull, and the old guard refused every pull into it, so no SIFT
    # output ever reached the run (CASE-C5B04D31, 2026-10-11).
    staging = dest.parent / "extractions_tmp"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)  # our own staging folder, left by an earlier attempt
    dest.parent.mkdir(parents=True, exist_ok=True)

    remote = (
        f"{opts['user']}@{opts['host']}:"
        f"{opts['remote_cases']}/{case_id}/extractions"
    )
    # scp -r remote/. dest/
    cmd = [
        "scp",
        "-i", str(key),
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", f"ConnectTimeout={_SSH_CONNECT_TIMEOUT}",
        "-r",
        remote,
        str(staging),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("SIFT scp failed: %s", exc)
        shutil.rmtree(staging, ignore_errors=True)
        return None
    if proc.returncode != 0:
        log.warning("SIFT scp rc=%s stderr=%s", proc.returncode, (proc.stderr or "")[:400])
        shutil.rmtree(staging, ignore_errors=True)
        return None

    # scp -r may create staging/extractions or flatten
    pulled = staging / "extractions" if (staging / "extractions").is_dir() else staging
    if pulled.is_dir():
        if not dest.exists() or not any(dest.iterdir()):
            if dest.exists():
                dest.rmdir()  # an empty folder the lane made: the pull takes its place
            pulled.rename(dest)
        else:
            added, present = _merge_new_files(pulled, dest)
            log.info("SIFT pull merged into %s: %d new file(s), %d already present", dest, added, present)
    shutil.rmtree(staging, ignore_errors=True)
    log.info("Pulled SIFT extractions -> %s", dest)
    return dest if dest.is_dir() else None


def _merge_new_files(src: Path, dst: Path) -> tuple[int, int]:
    """Copy each file of ``src`` that ``dst`` does not have yet. Returns (added, already present)."""
    added = present = 0
    for path in sorted(src.rglob("*")):
        if not path.is_file():
            continue
        target = dst / path.relative_to(src)
        if target.exists():
            present += 1
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        added += 1
    return added, present


def push_file(local: Path, remote_path: str) -> bool:
    """scp a single local file to the SIFT host."""
    if not sync_enabled():
        log.info("SIFT sync disabled (NEXUS_SIFT_SYNC=0) — skip push")
        return False
    opts = _ssh_opts()
    key = Path(opts["key"])
    if not key.is_file() or not Path(local).is_file():
        return False
    dest = f"{opts['user']}@{opts['host']}:{remote_path}"
    cmd = _scp_base(key) + [str(local), dest]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("SIFT push failed: %s", exc)
        return False
    if proc.returncode != 0:
        log.warning("SIFT push rc=%s stderr=%s", proc.returncode, (proc.stderr or "")[:400])
        return False
    log.info("Pushed %s -> %s", local, dest)
    return True
