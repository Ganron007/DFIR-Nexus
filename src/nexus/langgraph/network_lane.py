"""EH-14b network lane — Zeek / Suricata / nfdump jobs + local session guarantee.

Product rule: every PCAP must yield *something* iterable. The lane:
1. runs the app-layer parsers when the host has them (``zeek``, ``suricata``),
2. always projects L3/L4 **flows** with tshark as the session guarantee
   (works on any host with Wireshark — including Windows examiners),
3. schedules the same jobs on the SIFT host when the capture lives under the
   configured SIFT evidence root and remote ``run_command`` is connected.

Planning is pure (testable); execution happens through the existing tool lane
(``run_tool_lane``) and the importer lane (``execute_tool_lane``).
"""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

PCAP_SUFFIXES = (".pcap", ".pcapng", ".cap")
NFDUMP_SUFFIXES = (".nfcapd", ".nfdump", ".nf")

_FLOW_FIELDS = (
    "frame.time_epoch", "ip.src", "tcp.srcport", "udp.srcport",
    "ip.dst", "tcp.dstport", "udp.dstport", "_ws.col.Protocol", "frame.len",
)


def discover_network_inputs(paths: list[str]) -> dict[str, list[str]]:
    """Split registered paths into {'pcap': [...], 'nfcapd': [...]} (pure)."""
    out: dict[str, list[str]] = {"pcap": [], "nfcapd": []}
    for raw in paths:
        p = Path(str(raw))
        if not p.is_file():
            continue
        name = p.name.lower()
        if p.suffix.lower() in PCAP_SUFFIXES:
            out["pcap"].append(str(p))
        elif p.suffix.lower() in NFDUMP_SUFFIXES or name.startswith("nfcapd"):
            out["nfcapd"].append(str(p))
    return out


def plan_network_triage(
    pcap_paths: list[str],
    nfcapd_paths: list[str],
    remote_root: str,
    *,
    has_sift_mcp: bool,
) -> list:
    """SIFT-host jobs for captures visible under ``remote_root`` (EH-14b).

    Order is app-layer first (Zeek → Suricata) then flows (nfdump); every
    capture under the root gets a job or an honest SKIP row — never silence.
    """
    from nexus.langgraph.tool_lane import ToolJob

    jobs: list = []
    root = (remote_root or "").strip().rstrip("/")
    if not has_sift_mcp:
        return jobs

    def _remote(p: str) -> str | None:
        if not root:
            return None
        s = str(p).replace("\\", "/")
        root_s = root.replace("\\", "/")
        if s.lower().startswith(root_s.lower() + "/"):
            return s
        return None

    for p in pcap_paths:
        rp = _remote(p)
        stem = Path(p).stem
        out_dir = f"{root or '/tmp'}/nexus-network/{stem}"
        if rp is None:
            jobs.append(ToolJob(
                host="sift", tool="(network)", argv=[],
                purpose="Network parser visibility", status="SKIP",
                reason=(
                    f"{Path(p).name} is not under the SIFT evidence root "
                    "(set case_context.sift_evidence_root / NEXUS_SIFT_EVIDENCE_ROOT "
                    "with the remote path) — local flow projection still runs"
                ),
            ))
            continue
        jobs.append(ToolJob(
            host="sift", tool="zeek",
            argv=["zeek", "-Cr", rp, "local",
                  f"Log::default_logdir={out_dir}/zeek"],
            purpose=f"Zeek conn/dns/http/ssl/files logs ({Path(p).name})",
            timeout=1800,
        ))
        jobs.append(ToolJob(
            host="sift", tool="suricata",
            argv=["suricata", "-r", rp, "-l", f"{out_dir}/suricata",
                  "--set", "outputs.1.eve-log.enabled=yes"],
            purpose=f"Suricata eve.json alerts/flows ({Path(p).name})",
            timeout=1800,
        ))
    for p in nfcapd_paths:
        rp = _remote(p)
        if rp is None:
            jobs.append(ToolJob(
                host="sift", tool="(network)", argv=[],
                purpose="Netflow visibility", status="SKIP",
                reason=(
                    f"{Path(p).name} is not under the SIFT evidence root — "
                    "the nfdump importer can still parse it locally/registered"
                ),
            ))
            continue
        stem = Path(p).stem
        jobs.append(ToolJob(
            host="sift", tool="nfdump",
            argv=["nfdump", "-r", rp, "-o", "csv"],
            purpose=f"nfdump every flow row ({Path(p).name})",
            timeout=1800,
        ))
    return jobs


def resolve_local_tool(name: str) -> str | None:
    """Locate a network binary on this host (PATH or NEXUS_TOOL_PATHS)."""
    from nexus.collect.paths import network_tool

    hit = network_tool(name)
    return str(hit) if hit else None


def project_flows(
    pcap: Path,
    out_csv: Path,
    *,
    timeout: int | None = None,
) -> dict:
    """tshark L3/L4 flow projection — the session guarantee (EH-14b).

    Runs ``tshark -T fields`` (header + comma separator) and writes a small
    normalized CSV: ``ts,src_ip,src_port,dst_ip,dst_port,protocol,bytes``.
    Returns ``{rows, path, error}``; a missing tshark is a truthful error, not
    an empty success.
    """
    from nexus.config import settings

    tshark = resolve_local_tool("tshark")
    if not tshark:
        return {"rows": 0, "path": "", "error": "tshark not found on PATH"}
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        tshark, "-r", str(pcap), "-T", "fields", "-E", "separator=,",
        "-E", "header=y",
    ]
    for field in _FLOW_FIELDS:
        cmd += ["-e", field]
    limit = timeout or settings.command_timeout
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=limit, text=True)
    except subprocess.TimeoutExpired:
        return {"rows": 0, "path": "", "error": f"tshark timed out after {limit}s"}
    except OSError as exc:
        return {"rows": 0, "path": "", "error": f"tshark execution failed: {exc}"}
    if proc.returncode != 0:
        return {
            "rows": 0, "path": "",
            "error": f"tshark failed: {(proc.stderr or '')[:300]}",
        }
    rows = 0
    with out_csv.open("w", encoding="utf-8", newline="") as fh:
        fh.write("ts,src_ip,src_port,dst_ip,dst_port,protocol,bytes\n")
        import csv

        writer = csv.writer(fh)
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split(",")
            if len(parts) < len(_FLOW_FIELDS):
                continue
            ts, src_ip, t_sport, u_sport, dst_ip, t_dport, u_dport, proto, length = (
                parts[:9]
            )
            writer.writerow([
                ts, src_ip, t_sport or u_sport, dst_ip, t_dport or u_dport,
                proto, length,
            ])
            rows += 1
    return {"rows": rows, "path": str(out_csv), "error": ""}


def enrich_local_network(pcap: str | Path, case_dir: str | Path) -> dict:
    """Local app-layer + flow enrichment for one capture (sync; thread me).

    - Zeek/Suricata run when their binaries resolve locally (Nexus-on-SIFT).
    - Flow projection always runs when tshark exists.
    Outputs land under ``case/ingest/network/`` (scan-indexed) or
    ``case/extractions/network/`` (pulled/uncapped scan for app logs).
    """
    pcap = Path(pcap)
    case_dir = Path(case_dir)
    result: dict = {"pcap": str(pcap), "steps": [], "errors": []}
    app_root = case_dir / "extractions" / "network" / pcap.stem
    zeek = resolve_local_tool("zeek")
    if zeek:
        out = app_root / "zeek"
        out.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                [zeek, "-Cr", str(pcap), "local",
                 f"Log::default_logdir={out}"],
                capture_output=True, timeout=3600, text=True,
            )
            if proc.returncode == 0:
                result["steps"].append(f"network: zeek logs -> {out}")
            else:
                result["errors"].append(f"zeek rc={proc.returncode}: {(proc.stderr or '')[:200]}")
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["errors"].append(f"zeek failed: {exc}")
    suricata = resolve_local_tool("suricata")
    if suricata:
        out = app_root / "suricata"
        out.mkdir(parents=True, exist_ok=True)
        try:
            proc = subprocess.run(
                [suricata, "-r", str(pcap), "-l", str(out),
                 "--set", "outputs.1.eve-log.enabled=yes"],
                capture_output=True, timeout=3600, text=True,
            )
            if proc.returncode == 0:
                result["steps"].append(f"network: suricata eve.json -> {out}")
            else:
                result["errors"].append(
                    f"suricata rc={proc.returncode}: {(proc.stderr or '')[:200]}"
                )
        except (OSError, subprocess.TimeoutExpired) as exc:
            result["errors"].append(f"suricata failed: {exc}")
    flows = project_flows(pcap, case_dir / "ingest" / "network" / f"{pcap.stem}-flows.csv")
    if flows.get("error"):
        result["errors"].append(f"flow projection: {flows['error']}")
    else:
        result["flows_csv"] = flows["path"]
        result["flows_rows"] = flows["rows"]
        result["steps"].append(
            f"network: flow projection {flows['rows']} row(s) -> {flows['path']}"
        )
    return result
