#!/usr/bin/env python3
"""Pack latest src + small Linux evidence, configure SIFT over SSH, run E2E."""
from __future__ import annotations

import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KEY = Path.home() / ".ssh" / "cadre-sift-key"
HOST = "sansforensics@192.168.77.135"
REMOTE = "~/DFIR-Nexus"

EV_REL = [
    "03-linux/audit.log",
    "03-linux/auth.log",
    "03-linux/syslog",
    "03-linux/journal.json",
    "03-linux/bash_history",
    "04-network/monitor-live/conn.log",
    "04-network/monitor-live/eve-tail.json",
    "04-network/monitor-live/kerberos-20260804.log",
    "04-network/monitor-live/dns.log",
    "04-network/monitor-live/http.log",
    "04-network/monitor-live/notice.log",
    "04-network/monitor-live/ssh.log",
    "04-network/monitor-live/weird.log",
    "_fixtures/hayabusa-timeline.csv",
    "_fixtures/volatility-pslist.json",
    "_fixtures/falco-sysdig.json",
    "_fixtures/wmi_subscriptions.csv",
]


def ssh(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-i", str(KEY), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", HOST, cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def scp(local: Path, remote: str, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["scp", "-i", str(KEY), "-o", "BatchMode=yes", str(local), f"{HOST}:{remote}"],
        capture_output=True, text=True, timeout=timeout,
    )


def scp_from(remote: str, local: Path, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["scp", "-i", str(KEY), "-o", "BatchMode=yes", f"{HOST}:{remote}", str(local)],
        capture_output=True, text=True, timeout=timeout,
    )


def pack_src(tmp: Path) -> Path:
    tarball = tmp / "dfir-nexus-sift.tgz"
    include = [
        ROOT / "src",
        ROOT / "scripts" / "sift_e2e.py",
        ROOT / "scripts" / "sift_configure.sh",
        ROOT / "pyproject.toml",
        ROOT / ".env.example",
        ROOT / "README.md",
    ]

    def _ok(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
        name = info.name.replace("\\", "/")
        parts = set(Path(name).parts)
        if parts & {"__pycache__", ".pytest_cache"} or name.endswith((".pyc", ".pyo")):
            return None
        return info

    with tarfile.open(tarball, "w:gz") as tar:
        for item in include:
            if not item.exists():
                continue
            if item.is_file():
                if item.parent.name == "scripts":
                    tar.add(item, arcname=f"scripts/{item.name}", filter=_ok)
                else:
                    tar.add(item, arcname=item.name, filter=_ok)
            else:
                tar.add(item, arcname=item.name, filter=_ok)
    return tarball


def pack_evidence(tmp: Path) -> Path:
    tarball = tmp / "sift-evidence.tgz"
    ev = ROOT / "Evidence-files"
    with tarfile.open(tarball, "w:gz") as tar:
        for rel in EV_REL:
            p = ev / rel
            if p.is_file():
                tar.add(p, arcname=rel)
    return tarball


def ti_env_fragment() -> str:
    """Copy live TI keys from host .env onto the VM. Never print values."""
    env = ROOT / ".env"
    if not env.is_file():
        return ""
    lines = []
    for raw in env.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        key = s.split("=", 1)[0].strip()
        if key.startswith("NEXUS_TI_"):
            lines.append(s)
    return "\n".join(lines)


def main() -> int:
    if not KEY.is_file():
        print("FAIL no sift key", KEY)
        return 1
    probe = ssh("echo KEY_OK && hostname && python3 --version")
    print(probe.stdout)
    if "KEY_OK" not in probe.stdout:
        print("FAIL ssh", probe.returncode, probe.stderr)
        return 1

    tmp = Path(tempfile.mkdtemp(prefix="nexus-sift-"))
    src = pack_src(tmp)
    ev = pack_evidence(tmp)
    print("src_bytes", src.stat().st_size, "ev_bytes", ev.stat().st_size, flush=True)

    r = scp(src, "/tmp/dfir-nexus-sift.tgz")
    print("scp src", r.returncode, (r.stderr or "ok")[-200:])
    if r.returncode != 0:
        return 1
    r = scp(ev, "/tmp/sift-evidence.tgz")
    print("scp ev", r.returncode, (r.stderr or "ok")[-200:])
    if r.returncode != 0:
        return 1

    r = ssh(
        f"mkdir -p {REMOTE} && tar -xzf /tmp/dfir-nexus-sift.tgz -C {REMOTE} && "
        f"mkdir -p {REMOTE}/Evidence-files && "
        f"tar -xzf /tmp/sift-evidence.tgz -C {REMOTE}/Evidence-files && "
        f"chmod +x {REMOTE}/scripts/sift_configure.sh && "
        f"test -f {REMOTE}/src/nexus/app.py && test -f {REMOTE}/Evidence-files/03-linux/auth.log && "
        f"echo EXTRACT_OK",
        timeout=120,
    )
    print(r.stdout, r.stderr)
    if "EXTRACT_OK" not in r.stdout:
        print("FAIL extract")
        return 1

    frag = ti_env_fragment()
    if frag:
        ti_file = tmp / "ti.env"
        ti_file.write_text(frag + "\n", encoding="utf-8")
        scp(ti_file, "/tmp/nexus-ti.env")
        ssh(
            f"umask 077; touch {REMOTE}/.env.sift; "
            f"grep -v '^NEXUS_TI_' {REMOTE}/.env.sift > /tmp/env.sift.keep || true; "
            f"cat /tmp/env.sift.keep /tmp/nexus-ti.env > {REMOTE}/.env.sift; "
            f"rm -f /tmp/nexus-ti.env /tmp/env.sift.keep; echo TI_MERGED"
        )

    print("== configure ==", flush=True)
    cfg = ssh(f"bash {REMOTE}/scripts/sift_configure.sh", timeout=600)
    print(cfg.stdout[-4000:])
    print(cfg.stderr[-1500:] if cfg.stderr else "")
    if "CONFIGURE_DONE" not in cfg.stdout:
        print("FAIL configure rc", cfg.returncode)
        return 1

    health = ssh(
        "curl -sS -m 8 -o /tmp/sift-health.json -w '%{http_code}' "
        "http://127.0.0.1:4508/health || true; echo; cat /tmp/sift-health.json 2>/dev/null || true",
        timeout=20,
    )
    print("HEALTH", health.stdout)

    print("== e2e ==", flush=True)
    e2e = ssh(
        f"cd {REMOTE} && set -a && . .env.sift && set +a && "
        f".venv/bin/python scripts/sift_e2e.py",
        timeout=300,
    )
    print(e2e.stdout[-8000:])
    print(e2e.stderr[-2000:] if e2e.stderr else "")

    dest = ROOT / "Docs" / "internal" / "SIFT-E2E-REPORT.md"
    pulled = scp_from("~/sift-e2e-report.md", dest)
    print("report_pull", pulled.returncode, dest if dest.is_file() else "missing")

    print("E2E_RC", e2e.returncode)
    return 0 if e2e.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
