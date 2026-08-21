"""Linux Stage 0 — UAC when present, else POSIX volatile pack; optional AVML."""

from __future__ import annotations

from pathlib import Path

from nexus.collect.paths import avml_exe, uac_home
from nexus.collect.transport import LocalTransport, Transport, _run_local
from nexus.collect.types import CollectOptions, CollectorStep, HostSpec

BUILTIN_SH = r'''#!/bin/sh
# POSIX volatile IR pack (not a UAC replacement). Missing optional tools are skipped.
OUT="${1:-.}"
mkdir -p "$OUT" || exit 1
hostname > "$OUT/hostname.txt" 2>/dev/null
uname -a > "$OUT/uname.txt" 2>/dev/null
date -u > "$OUT/date_utc.txt" 2>/dev/null
id > "$OUT/id.txt" 2>/dev/null
uptime > "$OUT/uptime.txt" 2>/dev/null
cat /etc/os-release > "$OUT/os-release.txt" 2>/dev/null
ps auxww > "$OUT/ps.txt" 2>/dev/null || ps -ef > "$OUT/ps.txt" 2>/dev/null
(ss -antup || netstat -antup || netstat -an) > "$OUT/netstat.txt" 2>/dev/null
(ss -tulpen || netstat -tulpen) > "$OUT/listeners.txt" 2>/dev/null
(ip addr; ip route; ip neigh) > "$OUT/ip.txt" 2>/dev/null || ifconfig -a > "$OUT/ip.txt" 2>/dev/null
lsof -n > "$OUT/lsof.txt" 2>/dev/null || true
lsmod > "$OUT/lsmod.txt" 2>/dev/null || true
(cat /proc/mounts; mount) > "$OUT/mounts.txt" 2>/dev/null
df -h > "$OUT/df.txt" 2>/dev/null
(iptables-save || nft list ruleset) > "$OUT/firewall.txt" 2>/dev/null || true
last -a > "$OUT/last.txt" 2>/dev/null
lastlog > "$OUT/lastlog.txt" 2>/dev/null
lastb > "$OUT/lastb.txt" 2>/dev/null || true
w > "$OUT/w.txt" 2>/dev/null
who > "$OUT/who.txt" 2>/dev/null
ls -la /tmp /var/tmp /dev/shm > "$OUT/tmp_listing.txt" 2>/dev/null
crontab -l > "$OUT/crontab_current.txt" 2>/dev/null
ls -la /etc/cron.* /var/spool/cron /etc/cron.d 2>/dev/null > "$OUT/cron_dirs.txt"
systemctl list-units --type=service --all > "$OUT/systemd_services.txt" 2>/dev/null
systemctl list-timers --all > "$OUT/systemd_timers.txt" 2>/dev/null
systemctl list-unit-files --type=service > "$OUT/systemd_unit_files.txt" 2>/dev/null
cat /etc/passwd > "$OUT/passwd.txt" 2>/dev/null
cat /etc/group > "$OUT/group.txt" 2>/dev/null
cat /etc/sudoers > "$OUT/sudoers.txt" 2>/dev/null || true
ls -la /etc/sudoers.d > "$OUT/sudoers.d.txt" 2>/dev/null
(dpkg -l || rpm -qa || apk info) > "$OUT/packages.txt" 2>/dev/null || true
(podman ps -a; docker ps -a) > "$OUT/containers.txt" 2>/dev/null || true
env > "$OUT/env.txt" 2>/dev/null
# logs (copy if present; do not fail)
for f in /var/log/auth.log /var/log/secure /var/log/syslog /var/log/messages /var/log/audit/audit.log; do
  if [ -r "$f" ]; then cp "$f" "$OUT/" 2>/dev/null; fi
done
find /home /root -name authorized_keys -o -name '*.pub' -o -name '.bash_history' -o -name '.zsh_history' 2>/dev/null | head -400 > "$OUT/ssh_keys_paths.txt"
# optional extra IR binaries — skip if not installed
command -v osqueryi >/dev/null 2>&1 && osqueryi --json 'SELECT * FROM processes LIMIT 2000' > "$OUT/osquery_processes.json" 2>/dev/null || true
command -v auditctl >/dev/null 2>&1 && auditctl -l > "$OUT/auditctl.txt" 2>/dev/null || true
command -v chkrootkit >/dev/null 2>&1 && chkrootkit > "$OUT/chkrootkit.txt" 2>/dev/null || true
command -v rkhunter >/dev/null 2>&1 && rkhunter --check --sk --nocolors > "$OUT/rkhunter.txt" 2>/dev/null || true
command -v lynis >/dev/null 2>&1 && lynis audit system --quick --no-colors > "$OUT/lynis.txt" 2>/dev/null || true
echo OK > "$OUT/STATUS.txt"
'''


def _write_builtin(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(BUILTIN_SH.lstrip("\n"), encoding="utf-8", newline="\n")
    return dest


def run_linux(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    *,
    dry_run: bool,
) -> list[CollectorStep]:
    steps: list[CollectorStep] = []
    if spec.os != "linux":
        return [CollectorStep("linux", "skipped", "not a linux host")]

    uac = uac_home() if opts.uac else None
    uac_profile = (opts.uac_profile or "full").strip() or "full"
    out_uac = pack_host / "uac"
    out_vol = pack_host / "volatile"
    sudo = "sudo " if spec.sudo else ""

    if dry_run:
        if opts.linux_volatile:
            steps.append(CollectorStep("linux_volatile", "planned", path=str(out_vol), detail={"engine": "builtin"}))
        else:
            steps.append(CollectorStep("linux_volatile", "skipped", "disabled"))
        if not opts.uac:
            steps.append(CollectorStep("uac", "skipped", "disabled"))
        elif uac:
            steps.append(CollectorStep("uac", "planned", path=str(out_uac), detail={"home": str(uac), "profile": uac_profile}))
        else:
            steps.append(CollectorStep("uac", "skipped", "uac tree not found — builtin POSIX used if enabled"))
        if opts.journal:
            steps.append(CollectorStep("journal", "planned", path=str(pack_host / "journal")))
        else:
            steps.append(CollectorStep("journal", "skipped", "disabled"))
        if not opts.memory:
            steps.append(CollectorStep("avml", "skipped", "disabled (profile / --no-memory)"))
        else:
            steps.append(CollectorStep(
                "avml",
                "planned" if avml_exe() else "skipped",
                "" if avml_exe() else "avml binary not found",
            ))
        return steps

    script = _write_builtin(pack_host / "_scripts" / "linux_volatile.sh")

    if opts.linux_volatile:
        steps.append(_run_builtin(spec, transport, script, out_vol, opts, sudo, fallback=False))
    else:
        steps.append(CollectorStep("linux_volatile", "skipped", "disabled"))

    if not opts.uac:
        steps.append(CollectorStep("uac", "skipped", "disabled"))
    elif uac:
        step = _run_uac(spec, transport, uac, out_uac, opts, sudo, profile=uac_profile)
        steps.append(step)
        if step.status == "failed" and not opts.linux_volatile:
            steps.append(_run_builtin(spec, transport, script, out_vol, opts, sudo, fallback=True))
    else:
        steps.append(CollectorStep("uac", "skipped", "uac launcher not found in UAC home"))

    if opts.journal:
        steps.append(_run_journal(spec, transport, pack_host, opts, sudo))
    else:
        steps.append(CollectorStep("journal", "skipped", "disabled"))

    if not opts.memory:
        steps.append(CollectorStep("avml", "skipped", "disabled (profile / --no-memory)"))
    else:
        steps.append(_run_avml(spec, transport, pack_host, opts, sudo, dry_run=False))
    return steps


def _run_builtin(
    spec: HostSpec,
    transport: Transport,
    script: Path,
    out_local: Path,
    opts: CollectOptions,
    sudo: str,
    *,
    fallback: bool,
) -> CollectorStep:
    detail = {"engine": "builtin", "fallback": fallback}
    out_local.mkdir(parents=True, exist_ok=True)
    if isinstance(transport, LocalTransport):
        result = _run_local(["/bin/sh", str(script), str(out_local)], opts.timeout_linux)
        if not result.ok:
            return CollectorStep("linux_volatile", "failed", (result.stderr or result.stdout)[:400], path=str(out_local), detail=detail)
        return CollectorStep("linux_volatile", "ok", path=str(out_local), detail=detail)

    remote = transport.remote_temp().rstrip("/") + "/linux"
    transport.run(f"mkdir -p {remote}/out", timeout=30)
    put = transport.put_file(script, remote + "/linux_volatile.sh")
    if not put.ok:
        return CollectorStep("linux_volatile", "failed", f"stage: {put.stderr[:300]}", detail=detail)
    cmd = f"{sudo}chmod +x {remote}/linux_volatile.sh && {sudo}/bin/sh {remote}/linux_volatile.sh {remote}/out"
    result = transport.run(cmd, timeout=opts.timeout_linux)
    if not result.ok:
        return CollectorStep("linux_volatile", "failed", (result.stderr or result.stdout)[:400], detail=detail)
    pull = transport.get_tree(remote + "/out", out_local, timeout=opts.timeout_linux)
    if not pull.ok:
        return CollectorStep("linux_volatile", "failed", f"pull: {pull.stderr[:300]}", path=str(out_local), detail=detail)
    return CollectorStep("linux_volatile", "ok", path=str(out_local), detail=detail)


def _run_journal(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    sudo: str,
) -> CollectorStep:
    out = pack_host / "journal"
    out.mkdir(parents=True, exist_ok=True)
    if isinstance(transport, LocalTransport):
        dest = str(out)
        sh = (
            f"journalctl --since '30 days ago' --no-pager -o short-iso > {dest}/journal.txt 2> {dest}/journal.err; "
            f"ausearch -ts recent > {dest}/audit.txt 2>/dev/null || true"
        )
        result = _run_local(["/bin/sh", "-c", sh], opts.timeout_linux)
        if not (out / "journal.txt").is_file() and not result.ok:
            return CollectorStep("journal", "failed", (result.stderr or result.stdout)[:400], path=str(out))
        return CollectorStep("journal", "ok", path=str(out))

    remote = transport.remote_temp().rstrip("/") + "/journal"
    transport.run(f"mkdir -p {remote}", timeout=30)
    result = transport.run(
        f"{sudo}journalctl --since '30 days ago' --no-pager -o short-iso > {remote}/journal.txt 2> {remote}/journal.err; "
        f"{sudo}ausearch -ts recent > {remote}/audit.txt 2>/dev/null || true",
        timeout=opts.timeout_linux,
    )
    pull = transport.get_tree(remote, out, timeout=opts.timeout_linux)
    if not pull.ok:
        return CollectorStep("journal", "failed", (pull.stderr or result.stderr)[:400], path=str(out))
    return CollectorStep("journal", "ok", path=str(out))


def _run_uac(
    spec: HostSpec,
    transport: Transport,
    uac: Path,
    out_local: Path,
    opts: CollectOptions,
    sudo: str,
    *,
    profile: str = "full",
) -> CollectorStep:
    if profile not in {"full", "ir_triage", "offline", "offline_ir_triage"}:
        profile = "full"
    detail = {"home": str(uac), "profile": profile}
    out_local.mkdir(parents=True, exist_ok=True)
    uac_bin = uac / "uac"
    if not uac_bin.is_file():
        found = next(uac.glob("uac"), None) or next(uac.rglob("uac"), None)
        if found:
            uac_bin = found
            uac = found.parent
        else:
            return CollectorStep("uac", "skipped", "uac launcher not found in UAC home", detail=detail)

    if isinstance(transport, LocalTransport):
        result = _run_local(
            ["/bin/sh", str(uac_bin), "-p", profile, str(out_local)],
            opts.timeout_linux,
        )
        if not result.ok:
            return CollectorStep("uac", "failed", (result.stderr or result.stdout)[:400], path=str(out_local), detail=detail)
        return CollectorStep("uac", "ok", path=str(out_local), detail=detail)

    remote = transport.remote_temp().rstrip("/") + "/uac"
    put = transport.put_tree(uac, remote, timeout=opts.timeout_linux)
    if not put.ok:
        return CollectorStep("uac", "failed", f"stage uac: {put.stderr[:300]}", detail=detail)
    cmd = f"{sudo}chmod +x {remote}/uac && {sudo}{remote}/uac -p {profile} {remote}/out"
    result = transport.run(f"mkdir -p {remote}/out && {cmd}", timeout=opts.timeout_linux)
    if not result.ok:
        return CollectorStep("uac", "failed", (result.stderr or result.stdout)[:400], detail=detail)
    pull = transport.get_tree(remote + "/out", out_local, timeout=opts.timeout_linux)
    if not pull.ok:
        return CollectorStep("uac", "failed", f"pull: {pull.stderr[:300]}", path=str(out_local), detail=detail)
    return CollectorStep("uac", "ok", path=str(out_local), detail=detail)


def _run_avml(
    spec: HostSpec,
    transport: Transport,
    pack_host: Path,
    opts: CollectOptions,
    sudo: str,
    *,
    dry_run: bool,
) -> CollectorStep:
    exe = avml_exe()
    out = pack_host / "memory"
    if not exe:
        return CollectorStep("avml", "skipped", "avml not found (Tools/linux/avml or NEXUS_AVML)")
    if dry_run:
        return CollectorStep("avml", "planned", path=str(out))
    out.mkdir(parents=True, exist_ok=True)
    dest = out / "memory.lime"
    if isinstance(transport, LocalTransport):
        result = _run_local([str(exe), str(dest)], opts.timeout_memory)
        if not result.ok:
            return CollectorStep("avml", "failed", (result.stderr or result.stdout)[:400], path=str(out))
        return CollectorStep("avml", "ok", path=str(dest))
    remote = transport.remote_temp().rstrip("/") + "/memory"
    transport.run(f"mkdir -p {remote}", timeout=30)
    put = transport.put_file(exe, remote + "/avml")
    if not put.ok:
        return CollectorStep("avml", "failed", f"stage: {put.stderr[:300]}")
    result = transport.run(
        f"{sudo}chmod +x {remote}/avml && {sudo}{remote}/avml {remote}/memory.lime",
        timeout=opts.timeout_memory,
    )
    if not result.ok:
        return CollectorStep("avml", "failed", (result.stderr or result.stdout)[:400])
    pull = transport.get_tree(remote + "/memory.lime", dest, timeout=opts.timeout_memory)
    if not pull.ok:
        return CollectorStep("avml", "failed", f"pull: {pull.stderr[:300]}", path=str(out))
    return CollectorStep("avml", "ok", path=str(dest))
