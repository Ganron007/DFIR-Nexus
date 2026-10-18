"""EH-14b network lane — SIFT defaults / nfdump jobs + local session guarantee.

Product rule: every PCAP must yield *something* iterable. The lane:
1. runs app-layer parsers **only when the host actually has them** — on SIFT that
   means the default toolset (``nfdump``; Zeek/Suricata are opt-in and never
   assumed, since nothing is installed or copied onto the SIFT workstation),
2. always projects L3/L4 **flows** with tshark as the session guarantee
   (works on any host with Wireshark — including Windows examiners),
3. schedules the same jobs on the SIFT host when the capture lives under the
   configured SIFT evidence root and remote ``run_command`` is connected.

Planning is pure (testable); execution happens through the existing tool lane
(``run_tool_lane``) and the importer lane (``execute_tool_lane``).
"""
from __future__ import annotations

import logging
import os
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
    """Split registered paths into {'pcap': [...], 'nfcapd': [...]}; a registered folder is walked.

    Only files were looked at, so a capture registered inside a folder (samples S03 and S04) was never a network
    input and no SIFT job could be planned for it (2026-10-18).
    """
    out: dict[str, list[str]] = {"pcap": [], "nfcapd": []}
    for raw in paths:
        p = Path(str(raw))
        if p.is_dir():
            try:
                files = sorted(f for f in p.rglob("*") if f.is_file())
            except OSError:
                files = []
        elif p.is_file():
            files = [p]
        else:
            continue
        for f in files:
            name = f.name.lower()
            if f.suffix.lower() in PCAP_SUFFIXES:
                out["pcap"].append(str(f))
            elif f.suffix.lower() in NFDUMP_SUFFIXES or name.startswith("nfcapd"):
                out["nfcapd"].append(str(f))
    return out


def plan_network_triage(
    pcap_paths: list[str],
    nfcapd_paths: list[str],
    remote_root: str,
    *,
    has_sift_mcp: bool,
    remote_extractions: str = "",
) -> list:
    """SIFT-host jobs for captures on the SIFT host (EH-14b).

    Zeek and Suricata are installed on the SIFT host (2026-10-13) and run only when opted in
    (``NEXUS_SIFT_ZEEK=1`` / ``NEXUS_SIFT_SURICATA=1``); otherwise they produce one honest SKIP row
    (never a guaranteed FAIL). ``nfdump`` ships with SIFT and runs for NetFlow.

    A capture is read on SIFT from under ``remote_root``: its own path when it is there, else its staged copy,
    which the staging step (``scripts/stage-sift-evidence.ps1``) puts in that folder by its file name. A capture
    registered on this host used to be planned only if its local path began with the remote root, which a
    Windows path never does. The outputs go to ``remote_extractions`` (the remote case's extractions, which the
    lane pulls); they used to go under the evidence root, which no pull reads. Never silence.
    """
    from nexus.langgraph.tool_lane import ToolJob

    jobs: list = []
    root = (remote_root or "").strip().rstrip("/")
    if not has_sift_mcp:
        return jobs

    zeek_on = os.environ.get("NEXUS_SIFT_ZEEK", "").strip().lower() in ("1", "true", "yes")
    suricata_on = os.environ.get("NEXUS_SIFT_SURICATA", "").strip().lower() in ("1", "true", "yes")

    names: dict[str, int] = {}
    for p in [*pcap_paths, *nfcapd_paths]:
        names[Path(p).name.lower()] = names.get(Path(p).name.lower(), 0) + 1

    def _remote(p: str) -> str | None:
        if not root:
            return None
        s = str(p).replace("\\", "/")
        root_s = root.replace("\\", "/")
        if s.lower().startswith(root_s.lower() + "/"):
            return s
        if names.get(Path(p).name.lower()) == 1:
            return f"{root_s}/{Path(p).name}"
        return None

    def _not_on_sift(p: str) -> str:
        if not root:
            return (f"{Path(p).name}: no SIFT evidence root (set case_context.sift_evidence_root / "
                    "NEXUS_SIFT_EVIDENCE_ROOT) — local flow projection still runs")
        return (f"{Path(p).name}: another registered file has the same name, so its staged copy on SIFT is "
                "ambiguous — stage them under distinct names; local flow projection still runs")

    out_base = (remote_extractions or "").strip().rstrip("/")
    pcap_under_root = False
    for p in pcap_paths:
        rp = _remote(p)
        stem = Path(p).stem
        out_dir = f"{out_base}/network/{stem}" if out_base else f"{root or '/tmp'}/nexus-network/{stem}"
        if rp is None:
            jobs.append(ToolJob(
                host="sift", tool="(network)", argv=[],
                purpose="Network parser visibility", status="SKIP",
                reason=_not_on_sift(p),
            ))
            continue
        pcap_under_root = True
        if zeek_on:
            jobs.append(ToolJob(
                host="sift", tool="zeek",
                argv=["zeek", "-Cr", rp, "local",
                      f"Log::default_logdir={out_dir}/zeek"],
                purpose=f"Zeek conn/dns/http/ssl/files logs ({Path(p).name})",
                timeout=1800,
                prep_dirs=[f"{out_dir}/zeek"],
            ))
        if suricata_on:
            jobs.append(ToolJob(
                host="sift", tool="suricata",
                argv=["suricata", "-r", rp, "-l", f"{out_dir}/suricata",
                      "--set", "outputs.1.eve-log.enabled=yes"],
                purpose=f"Suricata eve.json alerts/flows ({Path(p).name})",
                timeout=1800,
                prep_dirs=[f"{out_dir}/suricata"],
            ))
    if pcap_under_root and not zeek_on:
        jobs.append(ToolJob(
            host="sift", tool="zeek", argv=[],
            purpose="Zeek app-layer logs",
            status="SKIP",
            reason=(
                "installed on SIFT; runs only when NEXUS_SIFT_ZEEK=1 is set (opt-in)"
            ),
        ))
    if pcap_under_root and not suricata_on:
        jobs.append(ToolJob(
            host="sift", tool="suricata", argv=[],
            purpose="Suricata eve.json alerts/flows",
            status="SKIP",
            reason=(
                "installed on SIFT; runs only when NEXUS_SIFT_SURICATA=1 is set (opt-in)"
            ),
        ))
    for p in nfcapd_paths:
        rp = _remote(p)
        if rp is None:
            jobs.append(ToolJob(
                host="sift", tool="(network)", argv=[],
                purpose="Netflow visibility", status="SKIP",
                reason=_not_on_sift(p).replace("local flow projection still runs",
                                               "the nfdump importer can still parse it locally"),
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


def enrich_local_network(pcap: str | Path, case_dir: str | Path, extractions: str | Path | None = None) -> dict:
    """Local app-layer + flow enrichment for one capture (sync; thread me).

    - Zeek/Suricata run when their binaries resolve locally (Nexus-on-SIFT).
    - Flow projection always runs when tshark exists.
    The flows land under ``case/ingest/network/``; the app logs under ``<extractions>/network/<capture>``, the run's own
    extractions, which the index reads (D272). They went to the case's own ``extractions`` folder, which the index does
    not read once a run holds data of its own: sample S03's local Suricata alerts were written and never indexed.
    """
    pcap = Path(pcap)
    case_dir = Path(case_dir)
    result: dict = {"pcap": str(pcap), "steps": [], "errors": []}
    app_root = Path(extractions or case_dir / "extractions") / "network" / pcap.stem
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
