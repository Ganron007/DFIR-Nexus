"""Does the SIFT host run this tree's code? (D108, D148)

The SIFT MCP runs the host's own copy of ``src/nexus``. `nexus sift setup` compares it with this tree and refuses to
start the server on a difference, but the host's systemd unit restarts the server with no check, so after a host
reboot the lane could hand jobs to old code with no sign of it (D148, 2026-10-18). The lane compares the two before
it hands the host any job, with the same manifest the setup uses.
"""
from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

#: The host's listing, in ``sha256sum`` format, of its ``src/nexus`` (the setup reads the same).
HOST_LISTING = ("cd ~/DFIR-Nexus/src && find nexus -type f -not -path '*/__pycache__/*' "
                "| LC_ALL=C sort | xargs sha256sum")


def code_manifest(src_dir: Path) -> dict[str, str]:
    """SHA-256 of every file under ``src_dir/nexus``, keyed by its path relative to ``src_dir``."""
    manifest: dict[str, str] = {}
    for path in sorted((src_dir / "nexus").rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            manifest[path.relative_to(src_dir).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return manifest


def parse_sha256sum(text: str) -> dict[str, str]:
    """{path: sha256} from ``sha256sum`` output: one ``<digest>  <path>`` line per file."""
    manifest: dict[str, str] = {}
    for line in text.splitlines():
        digest, _, path = line.strip().partition("  ")
        if len(digest) == 64 and path:
            manifest[path] = digest
    return manifest


def compare_manifests(local: dict[str, str], host: dict[str, str]) -> dict[str, list[str]]:
    """The paths that differ between this tree and the host: changed, only here, only on the host."""
    return {
        "changed": sorted(p for p in local.keys() & host.keys() if local[p] != host[p]),
        "local_only": sorted(local.keys() - host.keys()),
        "host_only": sorted(host.keys() - local.keys()),
    }


def host_code_drift(src_dir: Path | None = None, *, timeout: int = 60) -> tuple[dict[str, list[str]] | None, str]:
    """(the difference between this tree and the host's code, or None when it could not be read; why not)."""
    from nexus.case.sift_sync import _ssh_opts

    src = src_dir or Path(__file__).resolve().parents[2]
    opts = _ssh_opts()
    if not Path(opts["key"]).is_file():
        return None, f"SSH key missing: {opts['key']}"
    cmd = ["ssh", "-i", opts["key"], "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
           "-o", "ConnectTimeout=10", f"{opts['user']}@{opts['host']}", HOST_LISTING]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, f"could not read the host's code: {exc}"
    host = parse_sha256sum(proc.stdout or "")
    if proc.returncode != 0 or not host:
        return None, f"could not read the host's code: {(proc.stderr or proc.stdout or '').strip()[:160]}"
    return compare_manifests(code_manifest(src), host), ""


def drift_reason(drift: dict[str, list[str]], case_id: str) -> str:
    """The reason a SIFT job waits when the host's code differs from this tree."""
    return (f"the SIFT host runs code that differs from this tree ({len(drift['changed'])} changed, "
            f"{len(drift['local_only'])} only here, {len(drift['host_only'])} only on the host): run "
            f"`nexus sift setup --case {case_id} --sync-code`, then re-run the lane")
