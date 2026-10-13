"""``nexus sift`` — the SIFT lane: selection, reachability, and Option B ingest.

SIFT is an explicitly selected, always-optional lane. Selecting it marks SIFT
analysis as required (``sift_required``) — the only switch that can refuse
analysis when the host is unreachable. Recovery is exactly three paths: bring
the host up and re-run, clear the selection (``nexus sift disable``), or the
examiner's audited skip. Nothing else is ever skipped.
"""
from __future__ import annotations

from pathlib import Path

import typer

app = typer.Typer(help="SIFT lane: status, selection, and SIFT-output ingest.")


def _resolve_case_dir(case: str) -> Path:
    from pathlib import Path as _P

    if case:
        candidate = _P(case)
        if candidate.is_dir():
            return candidate
        for base in (_P.home() / ".nexus" / "cases", _P("cases")):
            hit = base / case
            if hit.is_dir():
                return hit
        typer.echo(f"case not found: {case}")
        raise typer.Exit(1)
    typer.echo("--case is required: name the case this command acts on.")
    raise typer.Exit(1)


def _context(case_dir: Path) -> dict[str, str]:
    import yaml

    meta_path = case_dir / "CASE.yaml"
    if not meta_path.is_file():
        return {}
    loaded = yaml.safe_load(meta_path.read_text(encoding="utf-8")) or {}
    intake = loaded.get("intake") if isinstance(loaded, dict) else None
    return {str(k): str(v) for k, v in (intake or {}).items() if v is not None}


def _required(ctx: dict[str, str]) -> bool:
    return (ctx.get("sift_required") or "").strip().lower() in ("1", "true", "yes")


@app.command("status")
def status(case: str = typer.Option("", "--case", help="Case id or directory (required).")):
    """Show the SIFT lane selection, evidence paths, and reachability."""
    from nexus.case.sift_sync import sift_reachable

    case_dir = _resolve_case_dir(case)
    ctx = _context(case_dir)
    required = _required(ctx)
    typer.echo(f"case: {case_dir.name}")
    typer.echo(f"SIFT lane selected (sift_required): {'yes' if required else 'no'}")
    for key in ("sift_evidence_root", "sift_memory_file", "sift_disk_image", "sift_os"):
        if ctx.get(key):
            typer.echo(f"  {key}: {ctx[key]}")
    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    typer.echo(f"SIFT reachable: {'yes' if ok else 'NO'} ({msg[:120]})")
    import os

    mcp = os.environ.get("NEXUS_SIFT_MCP_URL", "").strip()
    if mcp:
        typer.echo(f"SIFT MCP URL: {mcp}")
    else:
        typer.echo(
            "SIFT MCP URL: not set in this shell - the serve session needs "
            "NEXUS_SIFT_MCP_URL (`nexus sift setup` prints the block)"
        )
    if required and not ok:
        typer.echo("")
        typer.echo("SIFT is REQUIRED for this case and unreachable - analysis will refuse. "
                   "Recoveries: bring the host up and re-run; `nexus sift disable`; "
                   "or the examiner's audited skip (`nexus lane skip`).")
        raise typer.Exit(1)


@app.command("enable")
def enable(case: str = typer.Option("", "--case", help="Case id or directory (required).")):
    """Mark SIFT analysis as required for this case and run the online check."""
    from nexus.case.sift_sync import sift_reachable
    from nexus.langgraph.case_intake import persist_case_intake

    case_dir = _resolve_case_dir(case)
    persist_case_intake(case_dir, {"sift_required": "true"})
    typer.echo(f"SIFT required: on ({case_dir.name})")
    try:
        ok, msg = sift_reachable()
    except Exception as exc:  # noqa: BLE001
        ok, msg = False, str(exc)
    typer.echo(f"online check: {'reachable' if ok else 'UNREACHABLE'} ({msg[:120]})")
    if not ok:
        typer.echo("Analysis will refuse until the host is up, the selection is "
                   "cleared (`nexus sift disable`), or an audited skip is recorded.")


@app.command("disable")
def disable(case: str = typer.Option("", "--case", help="Case id or directory (required).")):
    """Clear the SIFT selection (a first-class recovery path)."""
    from nexus.langgraph.case_intake import clear_case_intake

    case_dir = _resolve_case_dir(case)
    remaining = clear_case_intake(case_dir, ("sift_required",))
    typer.echo(f"SIFT required: cleared ({case_dir.name})")
    if remaining.get("sift_evidence_root"):
        typer.echo("Note: sift_evidence_root is kept; without the selection its jobs "
                   "SKIP with reasons (never a refusal).")


#: The SIFT MCP runs the host's copy of src/nexus, not this tree. A host that is not synced runs old code
#: without any sign of it (D108), so setup compares the two before it starts or restarts the server.
def code_manifest(src_dir: Path) -> dict[str, str]:
    """SHA-256 of every file under ``src_dir/nexus``, keyed by its path relative to ``src_dir``."""
    import hashlib

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


def push_code(src_dir: Path, ssh_base: list[str]) -> bool:
    """Back up the host's ``src`` and replace its ``src/nexus`` with this tree. The old tree is kept."""
    import datetime
    import io
    import subprocess
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for rel in sorted(code_manifest(src_dir)):
            tar.add(src_dir / rel, arcname=rel, recursive=False)
    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    remote = (f"set -e; cd ~/DFIR-Nexus && cp -a src src.bak-{stamp} && rm -rf src/nexus "
              "&& tar -xzf - -C src && echo SYNC-OK")
    proc = subprocess.run([*ssh_base, remote], input=buf.getvalue(), capture_output=True, timeout=600)
    return proc.returncode == 0 and b"SYNC-OK" in proc.stdout


#: The systemd unit that runs the SIFT MCP at boot (boot persistence, 2026-10-13). setup restarts it through systemd
#: when it is installed and sudo does not prompt on the host.
MCP_UNIT = "dfir-nexus-mcp.service"


def mcp_start_command(unit_managed: bool) -> str:
    """The shell command that (re)starts the SIFT MCP on :4508.

    Whatever holds the port is stopped first: a server an earlier setup started detached, or the unit's own process.
    When the unit is installed the server starts through systemd, so it comes back after a reboot and systemd
    restarts it on failure. Elsewhere it is started detached, as before.
    """
    stop_holder = (
        # Kill ONLY the process listening on 4508. Never `pkill -f 'nexus serve --http'`: the launching shell's
        # command line contains that very string, so pkill kills the script before it can start the server
        # (observed 2026-10-03 - the old server exited and the new one never launched).
        "PID=$(ss -ltnp 2>/dev/null | grep ':4508' | grep -oP 'pid=\\K[0-9]+' | head -1); "
        "[ -n \"$PID\" ] && { kill \"$PID\" 2>/dev/null; sleep 2; }; "
    )
    if unit_managed:
        return (
            "cd ~/DFIR-Nexus && "
            + stop_holder
            + f"sudo -n systemctl restart {MCP_UNIT}; "
            "sleep 12; ss -ltn 2>/dev/null | grep -q ':4508' && echo MCP-UP || echo MCP-FAILED"
        )
    return (
        "cd ~/DFIR-Nexus && "
        "set -a; . ~/.nexus/sift-mcp.env; set +a; "
        + stop_holder
        + "setsid nohup .venv/bin/python -m nexus serve --http --host 0.0.0.0 "
        "--port 4508 < /dev/null > /tmp/nexus-mcp.log 2>&1 & "
        "sleep 12; ss -ltn 2>/dev/null | grep -q ':4508' && echo MCP-UP || echo MCP-FAILED"
    )


@app.command("setup")
def setup(
    case: str = typer.Option("", "--case", help="Case id or directory to lay out on the SIFT host"),
    sync_code: bool = typer.Option(
        False, "--sync-code",
        help="Replace the host's src/nexus with this tree when they differ (the old src is kept as src.bak-<stamp>)",
    ),
):
    """Verify the SIFT host and wire it up (Phase 5 bootstrap).

    Checks SSH reachability, the SIFT default toolset, the Nexus checkout +
    venv and free disk; lays out the per-case folders; starts the SIFT-side
    MCP when it is not already listening; prints the examiner .env block and
    hands off to `nexus doctor --gate` + `nexus sift enable`.
    """
    import os
    import subprocess
    from pathlib import Path as _P

    host = os.environ.get("NEXUS_SIFT_SSH_HOST", "192.168.77.135").strip()
    user = os.environ.get("NEXUS_SIFT_SSH_USER", "sansforensics").strip()
    key = os.environ.get(
        "NEXUS_SIFT_SSH_KEY", str(_P.home() / ".ssh" / "cadre-sift-key")
    ).strip()

    if not _P(key).is_file():
        typer.echo(f"SSH key missing: {key}", err=True)
        raise typer.Exit(1)

    ssh_base = [
        "ssh", "-i", key, "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        f"{user}@{host}",
    ]

    def _ssh(remote: str, timeout: int = 60) -> tuple[int, str]:
        cmd = [*ssh_base, remote]
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return 1, str(exc)
        return p.returncode, (p.stdout or "") + (p.stderr or "")

    typer.echo(f"SIFT setup - {user}@{host}")
    rc, out = _ssh("hostname; uname -r")
    if rc != 0:
        typer.echo(f"  SSH: FAILED — {out.strip()[:200]}", err=True)
        raise typer.Exit(1)
    typer.echo(f"  SSH: OK ({out.strip().splitlines()[0]})")

    # D108: the MCP runs the host's src/nexus. Compare it with this tree before anything is started or restarted.
    src_dir = _P(__file__).resolve().parents[2]
    local_code = code_manifest(src_dir)
    rc, out = _ssh("cd ~/DFIR-Nexus/src && find nexus -type f -not -path '*/__pycache__/*' "
                   "| LC_ALL=C sort | xargs sha256sum")
    host_code = parse_sha256sum(out) if rc == 0 else {}
    if not host_code:
        typer.echo(f"  code: could not read the host's src/nexus ({out.strip()[:160]})", err=True)
        raise typer.Exit(1)
    drift = compare_manifests(local_code, host_code)
    code_synced = False
    if any(drift.values()):
        typer.echo(
            f"  code: host differs from this tree: {len(drift['changed'])} changed, "
            f"{len(drift['local_only'])} only here, {len(drift['host_only'])} only on the host"
        )
        if not sync_code:
            typer.echo(
                "  code: the MCP is not started on stale code. Re-run with --sync-code "
                "(the host's src is kept as src.bak-<stamp>).", err=True)
            raise typer.Exit(1)
        if not push_code(src_dir, ssh_base):
            typer.echo("  code: sync FAILED; the MCP is not started", err=True)
            raise typer.Exit(1)
        code_synced = True
        typer.echo(f"  code: host synced from this tree ({len(local_code)} files)")
    else:
        typer.echo(f"  code: host matches this tree ({len(local_code)} files)")

    rc, out = _ssh(
        "for t in vol log2timeline.py psort.py fls mmls icat mactime bulk_extractor; do "
        "command -v $t >/dev/null 2>&1 && echo OK-$t || echo MISS-$t; done"
    )
    tools = [ln for ln in out.splitlines() if ln.startswith(("OK-", "MISS-"))]
    missing = [t.split("-", 1)[1] for t in tools if t.startswith("MISS-")]
    typer.echo(
        f"  tools: {sum(1 for t in tools if t.startswith('OK-'))}/{len(tools)} present"
        + (f" — MISSING: {', '.join(missing)}" if missing else "")
    )

    rc, out = _ssh(
        "if [ -x ~/DFIR-Nexus/.venv/bin/python ]; then "
        "~/DFIR-Nexus/.venv/bin/python -c 'import nexus; print(nexus.__file__)'; "
        "else echo NO-VENV; fi"
    )
    if "NO-VENV" in out or rc != 0:
        typer.echo("  nexus on SIFT: NOT INSTALLED (expected ~/DFIR-Nexus with .venv)", err=True)
    else:
        typer.echo(f"  nexus on SIFT: OK ({out.strip().splitlines()[-1]})")

    rc, out = _ssh("df -h ~ | tail -1 | awk '{print $4}'")
    typer.echo(f"  disk free: {out.strip() or '?'}")

    if case:
        name = _P(case).name
        rc, out = _ssh(
            f"mkdir -p ~/.nexus/cases/{name}/evidence "
            f"~/.nexus/cases/{name}/extractions ~/.nexus/cases/{name}/analysis "
            "&& echo LAYOUT-OK"
        )
        if "LAYOUT-OK" in out:
            typer.echo(f"  layout: ~/.nexus/cases/{name}/{{evidence,extractions,analysis}} ready")

        # The layout is not a CASE. `run_command` persists tool output into the
        # remote ACTIVE case, and `case_activate` needs a case record
        # (CASE.yaml); with only directories, the active case stays unset and
        # every SIFT job writes nothing and FAILs "produced no output file".
        # Found 2026-10-03 by re-running the staging flow on a fresh case.
        rc, out = _ssh(
            f"if [ -f ~/.nexus/cases/{name}/CASE.yaml ]; then echo CASE-EXISTS; "
            "else cd ~/DFIR-Nexus && .venv/bin/python -m nexus case init "
            f"'SIFT lane {name}' --case-id {name} >/dev/null 2>&1 "
            "&& echo CASE-CREATED || echo CASE-FAILED; fi"
        )
        if "CASE-CREATED" in out:
            typer.echo(
                "  case: created on the host and set ACTIVE "
                "(the lane persists its captures there)"
            )
        elif "CASE-EXISTS" in out:
            typer.echo("  case: already present on the host")
        else:
            typer.echo(
                "  case: could NOT be created on the host — SIFT jobs will FAIL "
                "with 'produced no output file' because there is no active case "
                "to persist into. Run on the host: "
                f"cd ~/DFIR-Nexus && .venv/bin/python -m nexus case init --case-id {name}",
                err=True,
            )

    # The MCP binds 0.0.0.0 and executes host binaries, so it needs a bearer
    # token (D28). ENSURE one first - creating the file, or adding the key to an
    # older file that predates the requirement - and only then decide whether to
    # (re)start: a token added to an already-running server would be ignored
    # until it restarts, which left the first version of this fix provisioning
    # nothing when the server happened to be up.
    ensure = (
        "ENVF=~/.nexus/sift-mcp.env; "
        "if [ ! -f \"$ENVF\" ]; then SEC=$(openssl rand -hex 32); "
        "printf 'NEXUS_AUDIT_SECRET=%s\\nNEXUS_PORTAL_PASSWORD=siftmcp-%s\\n"
        f"NEXUS_MCP_ALLOWED_HOSTS={host}\\nNEXUS_BEARER_TOKEN=%s\\n' "
        "\"$SEC\" \"$SEC\" \"$SEC\" > \"$ENVF\"; chmod 600 \"$ENVF\"; echo TOKEN-ADDED; "
        "elif ! grep -q '^NEXUS_BEARER_TOKEN=' \"$ENVF\"; then "
        "SEC=$(openssl rand -hex 32); printf 'NEXUS_BEARER_TOKEN=%s\\n' \"$SEC\" >> \"$ENVF\"; "
        "echo TOKEN-ADDED; "
        "else echo TOKEN-PRESENT; fi"
    )
    rc, out = _ssh(ensure)
    token_added = "TOKEN-ADDED" in out

    rc, listening = _ssh("ss -ltn 2>/dev/null | grep -q ':4508' && echo MCP-UP || echo MCP-DOWN")
    rc, token = _ssh(
        "grep '^NEXUS_BEARER_TOKEN=' ~/.nexus/sift-mcp.env 2>/dev/null | cut -d= -f2-"
    )
    token = (token or "").strip().splitlines()[0].strip() if (token or "").strip() else ""

    rc, unit = _ssh(
        f"systemctl is-enabled {MCP_UNIT} >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 "
        "&& echo UNIT-MANAGED || echo UNIT-NONE"
    )
    unit_managed = "UNIT-MANAGED" in unit

    # A running server keeps the code and the token it imported at start: new code (code_synced) needs a restart too.
    if "MCP-UP" in listening and not token_added and not code_synced:
        typer.echo("  MCP: listening on :4508 (bearer token already in place)")
    else:
        if "MCP-UP" in listening and (token_added or code_synced):
            typer.echo("  MCP: restarting so the new code and bearer token take effect...")
        else:
            typer.echo("  MCP: not running — starting it...")
        rc, out = _ssh(mcp_start_command(unit_managed), timeout=150)
        failure = (
            f"FAILED — see: journalctl -u {MCP_UNIT}" if unit_managed
            else "FAILED — see /tmp/nexus-mcp.log"
        )
        typer.echo("  MCP: " + ("listening on :4508 (bearer auth on)" if "MCP-UP" in out else failure))

    typer.echo("")
    typer.echo("Examiner .env block (or export for the serve session):")
    typer.echo(f"  NEXUS_SIFT_SSH_HOST={host}")
    typer.echo(f"  NEXUS_SIFT_SSH_USER={user}")
    typer.echo(f"  NEXUS_SIFT_SSH_KEY={key}")
    typer.echo(f"  NEXUS_SIFT_MCP_URL=http://{host}:4508/mcp")
    if token:
        typer.echo(f"  NEXUS_BEARER_TOKEN={token}")
    else:
        typer.echo(
            "  NEXUS_BEARER_TOKEN=<could not read ~/.nexus/sift-mcp.env on the host>"
        )
    typer.echo("  (the MCP requires this token on every /mcp call for a non-loopback "
               "bind — if it does not match, calls return 401)")
    typer.echo("Next: `nexus doctor --gate`, then `nexus sift enable --case <case>` "
               "(evidence itself is copied by the examiner into "
               "~/.nexus/cases/<case>/evidence/ on the host).")


@app.command("ingest")
def ingest(
    path: str = typer.Argument(..., help="SIFT outputs: a file, a directory, or a .zip"),
    case: str = typer.Option("", "--case", help="Case id or directory (required)."),
    family: str = typer.Option(
        "", "--as", help="Destination family name (plaso / vol / fls / bulk_extractor) for mapping"
    ),
):
    """Option B - stage SIFT-produced outputs for indexing (no SIFT host needed)."""
    from nexus.case.sift_ingest import stage_sift_outputs

    case_dir = _resolve_case_dir(case)
    src = Path(path)
    staged = stage_sift_outputs(case_dir, [src], family=family)
    for dest in staged:
        n = sum(1 for _ in dest.rglob("*") if _.is_file())
        typer.echo(f"staged: {dest.relative_to(case_dir)}  ({n} file(s))")
    typer.echo("Next: run the indexer (`nexus index rebuild` or the pipeline) so the rows "
               "land in the case index with the mapped fields.")
