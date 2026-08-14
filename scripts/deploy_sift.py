"""Install DFIR-Nexus on SIFT .135 and serve HTTP :4508. Operator lab only."""
from __future__ import annotations

import secrets
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = Path.home() / ".ssh" / "cadre-sift-key"
HOST = "sansforensics@192.168.77.135"
REMOTE = "~/DFIR-Nexus"
SKIP = {
    ".git", ".venv", "__pycache__", ".pytest_cache", "Evidence-files",
    "Tools", ".env", "node_modules", ".ruff_cache",
}


def ssh(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-i", str(KEY), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST, cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def scp(local: Path, remote: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["scp", "-i", str(KEY), "-o", "BatchMode=yes", str(local), f"{HOST}:{remote}"],
        capture_output=True, text=True, timeout=180,
    )


def main() -> int:
    if not KEY.is_file():
        print("FAIL no sift key", KEY)
        return 1
    probe = ssh("echo KEY_OK && python3 --version")
    print(probe.stdout, probe.stderr)
    if probe.returncode != 0 or "KEY_OK" not in probe.stdout:
        print("FAIL ssh", probe.returncode)
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="nexus-sift-"))
    tarball = tmp / "dfir-nexus-sift.tgz"
    print("packing", tarball, flush=True)
    include_roots = [
        ROOT / "src",
        ROOT / "tests",
        ROOT / "Docs",
        ROOT / "scripts",
        ROOT / "pyproject.toml",
        ROOT / "setup-linux.sh",
        ROOT / "README.md",
        ROOT / ".env.example",
    ]

    def _ok(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = info.name.replace("\\", "/")
        parts = set(Path(name).parts)
        if parts & SKIP or name.endswith((".pyc", ".pyo")):
            return None
        return info

    with tarfile.open(tarball, "w:gz") as tar:
        for item in include_roots:
            if not item.exists():
                continue
            tar.add(item, arcname=item.name if item.is_file() else item.name, filter=_ok)
    print("tarball bytes", tarball.stat().st_size)

    r = ssh(f"mkdir -p {REMOTE} && rm -f /tmp/dfir-nexus-sift.tgz")
    print("mkdir", r.returncode, r.stderr)
    r = scp(tarball, "/tmp/dfir-nexus-sift.tgz")
    print("scp", r.returncode, r.stderr[-300:] if r.stderr else "ok")
    if r.returncode != 0:
        return 1

    r = ssh(
        f"mkdir -p {REMOTE} && tar -xzf /tmp/dfir-nexus-sift.tgz -C {REMOTE} && "
        f"test -f {REMOTE}/pyproject.toml && echo TAR_OK",
        timeout=120,
    )
    print(r.stdout, r.stderr)
    if "TAR_OK" not in r.stdout:
        print("FAIL extract")
        return 1

    # Lean install: HTTP server + Linux catalog. Skip [all] (torch/chroma).
    install = ssh(
        f"cd {REMOTE} && python3 -m venv .venv && "
        f".venv/bin/python -m pip install -U pip && "
        f".venv/bin/pip install -e '.[http]' && "
        f"echo INSTALL_OK",
        timeout=600,
    )
    print(install.stdout[-1500:], install.stderr[-800:])
    if "INSTALL_OK" not in install.stdout:
        print("FAIL pip")
        return 1

    audit = secrets.token_hex(32)
    portal = "lab-sift-portal"
    # persist env for the service (lab-only, on the VM, not in git)
    env_cmd = (
        f"umask 077; cat > {REMOTE}/.env.sift <<'EOF'\n"
        f"NEXUS_AUDIT_SECRET={audit}\n"
        f"NEXUS_PORTAL_PASSWORD={portal}\n"
        f"EOF\n"
        f"echo ENV_OK"
    )
    r = ssh(env_cmd)
    print(r.stdout)

    # stop any previous listener then serve
    ssh("pkill -f 'nexus serve' || true; sleep 1")
    serve = ssh(
        f"cd {REMOTE} && set -a && . .env.sift && set +a && "
        f"nohup .venv/bin/nexus serve --http --host 0.0.0.0 --port 4508 "
        f"> ~/nexus-serve.log 2>&1 & sleep 3 && "
        f"(ss -lntp | grep 4508 || netstat -lntp | grep 4508) && echo SERVE_OK",
        timeout=60,
    )
    print(serve.stdout, serve.stderr)
    log = ssh("tail -n 40 ~/nexus-serve.log")
    print("LOG\n", log.stdout, log.stderr)

    doctor = ssh(f"cd {REMOTE} && .venv/bin/nexus doctor", timeout=90)
    print("DOCTOR\n", doctor.stdout[-1500:], doctor.stderr[-400:])

    count = ssh(
        f"cd {REMOTE} && .venv/bin/python -c "
        f"\"from nexus.app import create_server; s=create_server(); "
        f"print('TOOLS', len(s._tool_manager._tools))\"",
        timeout=60,
    )
    print(count.stdout, count.stderr)

    linux = ssh(
        f"cd {REMOTE} && .venv/bin/python -c "
        f"\"from nexus.app import create_server; s=create_server(); "
        f"t=s._tool_manager._tools; "
        f"print('run_command', 'run_command' in t); "
        f"print('check_tools', 'check_tools' in t)\"",
        timeout=60,
    )
    print(linux.stdout, linux.stderr)

    if "SERVE_OK" in serve.stdout or "4508" in serve.stdout:
        print("SIFT_DEPLOY_OK")
        return 0
    print("SIFT_DEPLOY_PARTIAL")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
