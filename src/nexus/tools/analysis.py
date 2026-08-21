"""Advanced analysis tools — beacon detection, gap analysis, deobfuscation, KEV, adversary emulation.

MCP tools that wrap the new analysis modules from REVAMP-V2.
"""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def ingest_auto(path: str, source: str = "") -> dict:
        """Auto-detect file format and ingest forensic artifacts.

        Sniffs the file content to determine the correct importer
        (33 formats supported). One entry point for any file type.
        Pass source to skip sniffing (same values as CLI --source).

        Args:
            path: Path to the forensic artifact file.
            source: Optional ArtifactSource override (e.g. zeek, evtx).
        """
        from nexus.ingest.detect import ingest_auto as _ingest
        result = _ingest(Path(path), source=source or None)
        aid = audit.log(
            "ingest_auto",
            params={"path": path, "source": source},
            result_summary=result,
            input_files=[path],
        )
        result["audit_id"] = aid
        return result

    @server.tool()
    def convert_pcap(
        pcap_path: str,
        display_filter: str = "",
        max_packets: int = 0,
    ) -> dict:
        """Convert a raw PCAP/PCAPNG capture to tshark JSON for ingestion.

        Raw packet captures are not parsed natively. This tool runs tshark
        (Wireshark CLI) to produce a JSON export, which ingest_auto() then
        parses via the Wireshark importer.

        Args:
            pcap_path: Path to the .pcap/.pcapng file.
            display_filter: Optional tshark display filter (e.g. "dns",
                "http.request"). Recommended for large captures.
            max_packets: Optional packet limit (0 = all).
        """
        import re
        import shutil
        import subprocess

        from nexus.config import settings

        src = Path(pcap_path)
        if not src.is_file():
            return {"success": False, "error": f"File not found: {pcap_path}"}

        tshark = shutil.which("tshark") or shutil.which("tshark.exe")
        if not tshark:
            return {
                "success": False,
                "error": "tshark not found on PATH. Install Wireshark "
                         "(e.g. choco install wireshark) first.",
            }

        out_dir = src.parent
        try:
            from nexus.case_manager import CaseManager
            out_dir = CaseManager().require_active_case() / "extractions"
        except Exception:  # noqa: BLE001
            pass
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            return {"success": False, "error": f"Cannot create output dir: {e}"}

        safe_stem = re.sub(r"[^a-zA-Z0-9._-]", "_", src.stem)
        out_path = out_dir / f"{safe_stem}.tshark.json"

        cmd = [tshark, "-r", str(src), "-T", "json"]
        if display_filter:
            cmd += ["-Y", display_filter]
        if max_packets and max_packets > 0:
            cmd += ["-c", str(int(max_packets))]

        result: dict = {"pcap": str(src), "output_path": str(out_path)}
        if src.stat().st_size > 100 * 1024 * 1024 and not display_filter and not max_packets:
            result["warning"] = (
                "Large capture without a filter — JSON output can be several "
                "times the pcap size. Consider display_filter or max_packets."
            )

        try:
            with open(out_path, "wb") as out_f:
                proc = subprocess.run(
                    cmd,
                    stdout=out_f,
                    stderr=subprocess.PIPE,
                    timeout=settings.command_timeout,
                )
        except subprocess.TimeoutExpired:
            result.update({"success": False,
                           "error": f"tshark timed out after {settings.command_timeout}s"})
            result["audit_id"] = audit.log(
                tool="convert_pcap", params={"pcap_path": str(src)},
                result_summary={"success": False, "error": "timeout"})
            return result
        except OSError as e:
            return {"success": False, "error": f"tshark execution failed: {e}"}

        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", errors="replace")[:500]
            result.update({"success": False, "error": stderr})
            result["audit_id"] = audit.log(
                tool="convert_pcap", params={"pcap_path": str(src)},
                result_summary={"success": False, "error": stderr[:200]})
            return result

        result.update({
            "success": True,
            "size_bytes": out_path.stat().st_size,
            "next_step": f'ingest_auto("{out_path}")',
        })
        result["audit_id"] = audit.log(
            tool="convert_pcap",
            params={"pcap_path": str(src), "display_filter": display_filter,
                    "max_packets": max_packets},
            result_summary={"success": True, "output_path": str(out_path),
                            "size_bytes": result["size_bytes"]})
        return result

    @server.tool()
    def analyze_gaps(min_gap_seconds: int = 300) -> dict:
        """Detect suspicious gaps in the forensic timeline.

        Identifies periods where logs go silent (potential log tampering).
        Two types: COMPLETE (all sources dark) and PARTIAL (selective).

        Args:
            min_gap_seconds: Minimum gap duration to flag (default 300).
        """
        from nexus.case_manager import CaseManager
        from nexus.ingest.gap_analysis import analyze_gaps as _analyze
        mgr = CaseManager()
        timeline = mgr.get_timeline()
        artifacts = []
        for entry in timeline:
            from datetime import datetime

            from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
            ts = entry.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                dt = datetime.now(UTC)
            artifacts.append(Artifact(
                id=entry.get("id", Artifact.new_id()),
                artifact_type=ArtifactType.UNKNOWN,
                source=ArtifactSource.UNKNOWN,
                timestamp=dt,
                severity=Severity.INFORMATIONAL,
                description=entry.get("description", ""),
                host=entry.get("host"),
            ))
        result = _analyze(artifacts, min_gap_seconds=min_gap_seconds)
        return result.to_dict()

    @server.tool()
    def deobfuscate_command(command_line: str) -> dict:
        """Decode obfuscated command lines (base64 PowerShell, hex strings).

        Detects -EncodedCommand, [Convert]::FromBase64String, hex-encoded strings.

        Args:
            command_line: The command line to analyze.
        """
        from nexus.ingest.deobfuscate import deobfuscate_command as _deob
        results = _deob(command_line)
        return {
            "payloads_found": len(results),
            "results": [r.to_dict() for r in results],
        }

    @server.tool()
    def check_kev(cve_id: str) -> dict:
        """Check if a CVE is in CISA's Known Exploited Vulnerabilities catalog.

        Cross-references against the local KEV cache.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228).
        """
        from nexus.ingest.kev import check_kev as _check
        result = _check(cve_id)
        if result:
            return {"is_kev": True, "entry": result}
        return {"is_kev": False, "cve_id": cve_id}

    @server.tool()
    def predict_techniques(observed_techniques: list[str], top_n: int = 10) -> dict:
        """Predict likely next techniques based on observed TTPs.

        Uses TF-IDF scoring against known threat actor group profiles.
        Helps anticipate attacker next steps.

        Args:
            observed_techniques: List of observed MITRE technique IDs.
            top_n: Number of predictions to return (default 10).
        """
        from nexus.mitre.adversary import match_observed_to_groups as _match
        from nexus.mitre.adversary import predict_next_techniques as _predict
        predictions = _predict(observed_techniques, top_n=top_n)
        groups = _match(observed_techniques, min_overlap=2)
        return {
            "predictions": [p.to_dict() for p in predictions],
            "matched_groups": groups,
        }

    @server.tool()
    def create_playbook(playbook_type: str = "ir") -> dict:
        """Create an incident response playbook.

        Pre-built templates: 'ir' (standard IR), 'ransomware' (ransomware-specific).

        Args:
            playbook_type: Type of playbook ('ir' or 'ransomware').
        """
        from nexus.case.playbook import create_ir_playbook, create_ransomware_playbook
        pb = create_ransomware_playbook() if playbook_type == "ransomware" else create_ir_playbook()
        return pb.to_dict()

    @server.tool()
    def build_asset_graph() -> dict:
        """Build asset ↔ IOC bipartite graph from artifacts.

        Auto-extracts hosts, accounts (DOMAIN\\user, UPN/email),
        and links them to observed IOCs.
        """
        from nexus.case_manager import CaseManager
        from nexus.ingest.asset_graph import build_asset_graph as _build
        mgr = CaseManager()
        timeline = mgr.get_timeline()
        from datetime import datetime

        from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
        artifacts = []
        for entry in timeline:
            try:
                dt = datetime.fromisoformat(entry.get("timestamp", ""))
            except (ValueError, TypeError):
                dt = datetime.now(UTC)
            artifacts.append(Artifact(
                id=entry.get("id", ""), artifact_type=ArtifactType.UNKNOWN,
                source=ArtifactSource.UNKNOWN, timestamp=dt,
                severity=Severity.INFORMATIONAL,
                description=entry.get("description", ""), host=entry.get("host"),
            ))
        graph = _build(artifacts)
        return graph.to_dict()

    @server.tool()
    def anonymize_text(text: str) -> dict:
        """Tokenize sensitive values (IPs, hosts, users, domains) in text.

        Reversible — returns tokenized text + token dictionary.
        Use deanonymize_text() to reverse.
        """
        from nexus.ingest.anonymize import Anonymizer
        anonymizer = Anonymizer()
        tokenized, tokens = anonymizer.anonymize(text)
        return {"tokenized": tokenized, "token_count": len(tokens), "tokens": tokens}

    @server.tool()
    def deanonymize_text(tokenized_text: str, tokens: dict) -> str:
        """Reverse anonymization using the token dictionary."""
        from nexus.ingest.anonymize import deanonymize
        return deanonymize(tokenized_text, tokens)

    @server.tool()
    def export_stix_bundle() -> dict:
        """Export case findings and IOCs as a STIX 2.1 bundle."""
        from nexus.case_manager import CaseManager
        from nexus.integration.stix_export import export_stix
        mgr = CaseManager()
        findings = [f for f in mgr.get_findings() if f.get("status") == "APPROVED"]
        iocs = []
        for f in findings:
            for ioc in f.get("iocs", []):
                iocs.append(ioc)
        return export_stix(findings, iocs)

    @server.tool()
    def export_navigator_layer(technique_ids: list[str] | None = None) -> dict:
        """Export ATT&CK Navigator layer from findings or explicit technique list."""
        from nexus.case_manager import CaseManager
        from nexus.integration.navigator_export import export_navigator_layer as _export
        if not technique_ids:
            mgr = CaseManager()
            findings = mgr.get_findings()
            technique_ids = []
            for f in findings:
                technique_ids.extend(f.get("technique_ids", []))
        technique_map = {t: "high" for t in set(technique_ids)}
        return _export(technique_map)

    @server.tool()
    def export_blocklist(format: str = "txt") -> dict:
        """Export IOCs as a blocklist for firewall/EDR (txt, csv, or stix)."""
        from nexus.case_manager import CaseManager
        from nexus.integration.ioc_blocklist import export_blocklist as _export
        mgr = CaseManager()
        findings = mgr.get_findings()
        iocs = []
        for f in findings:
            for ioc in f.get("iocs", []):
                iocs.append(ioc)
        content = _export(iocs, format=format)
        return {"format": format, "content": content, "ioc_count": len(iocs)}

    @server.tool()
    def translate_query(description: str, target_format: str = "spl") -> dict:
        """Translate a natural-language description into a query.

        Supported formats: spl (Splunk), kql (Kusto), sigma, yara, eql.

        Args:
            description: Plain English description of what to search for.
            target_format: Target query language.
        """
        from nexus.tools.nl_query import translate_query as _translate
        result = _translate(description, target_format)  # type: ignore[arg-type]
        return {"query": result, "format": target_format, "description": description}

    @server.tool()
    def suggest_fleet_hunts() -> dict:
        """Suggest Velociraptor VQL hunts based on evidence graph analysis.

        Analyzes observed lateral movement, file lineage, and persistence
        to propose proactive fleet-wide hunts.
        """
        from nexus.case_manager import CaseManager
        from nexus.ingest.evidence_graph import build_evidence_graph
        from nexus.tools.fleet_hunts import suggest_hunts
        mgr = CaseManager()
        timeline = mgr.get_timeline()
        from datetime import datetime

        from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity
        artifacts = []
        for entry in timeline:
            try:
                dt = datetime.fromisoformat(entry.get("timestamp", ""))
            except (ValueError, TypeError):
                dt = datetime.now(UTC)
            artifacts.append(Artifact(
                id=entry.get("id", ""), artifact_type=ArtifactType.UNKNOWN,
                source=ArtifactSource.UNKNOWN, timestamp=dt,
                severity=Severity.INFORMATIONAL,
                description=entry.get("description", ""), host=entry.get("host"),
            ))
        graph = build_evidence_graph(artifacts)
        hunts = suggest_hunts(graph.to_dict())
        return {"hunts": hunts, "count": len(hunts)}

    @server.tool()
    def check_nsrl(hash_value: str) -> dict:
        """Check a file hash against the NSRL known-good database."""
        from nexus.ingest.nsrl import check_nsrl
        verdict = check_nsrl(hash_value)
        return {"hash": hash_value, "verdict": verdict}

    @server.tool()
    def get_knowledge_graph_stats() -> dict:
        """Get statistics about the knowledge graph (entity/relation counts)."""
        from nexus.config import settings
        from nexus.knowledge.graph import KnowledgeGraph
        db_path = settings.data_root / "knowledge_graph.db"
        if not db_path.exists():
            return {"status": "empty", "entities": 0, "relations": 0}
        kg = KnowledgeGraph(db_path)
        entities = kg.list_entities()
        relations = kg.list_relations()
        return {"status": "ok", "entities": len(entities), "relations": len(relations)}

    @server.tool()
    def get_dynamic_tables() -> dict:
        """List all LLM-created dynamic tables."""
        from nexus.config import settings
        from nexus.knowledge.dynamic_tables import DynamicTableManager
        db_path = settings.data_root / "dynamic_tables.db"
        if not db_path.exists():
            return {"status": "empty", "tables": []}
        dtm = DynamicTableManager(db_path)
        return {"tables": dtm.list_tables()}

    @server.tool()
    def list_query_templates() -> dict:
        """List saved query templates."""
        from nexus.config import settings
        from nexus.knowledge.query_templates import QueryTemplateManager
        db_path = settings.data_root / "query_templates.db"
        if not db_path.exists():
            return {"status": "empty", "templates": []}
        qtm = QueryTemplateManager(db_path)
        return {"templates": qtm.list_templates()}

    @server.tool()
    def generate_sigma_rule(technique_id: str, title: str = "", log_source: str = "windows") -> dict:
        """Generate a Sigma detection rule from a technique ID.

        Uses technique-specific templates for common ATT&CK techniques.

        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1059.001).
            title: Optional rule title.
            log_source: Sigma log source (windows, linux, etc.).
        """
        from nexus.detection.generator import generate_sigma_rule as _gen
        from nexus.ingest.cti_ingestion import CTIItem, CTIItemType, CTISource
        item = CTIItem(
            id="auto",
            title=title or f"Detection for {technique_id}",
            description=f"Auto-generated detection for {technique_id}",
            item_type=CTIItemType.TECHNIQUE,
            source=CTISource.MITRE_ATTACK,
            technique_ids=[technique_id],
        )
        sigma_yaml = _gen(item)
        return {"sigma_yaml": sigma_yaml, "technique_id": technique_id}
