"""AI-suggested fleet hunts from evidence graphs.

Given an evidence graph (nodes and edges representing artifacts, hosts,
and relationships), suggests proactive Velociraptor VQL hunts based on
observed lateral movement patterns and file lineage.
Pure function — no side effects, no I/O.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class HuntSuggestion:
    """A suggested Velociraptor hunt with rationale."""

    name: str
    description: str
    vql: str
    priority: Literal["critical", "high", "medium", "low"]
    rationale: str
    technique_ids: list[str] = field(default_factory=list)
    source_artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "vql": self.vql,
            "priority": self.priority,
            "rationale": self.rationale,
            "technique_ids": self.technique_ids,
            "source_artifacts": self.source_artifacts,
        }


@dataclass
class EvidenceNode:
    """A node in the evidence graph."""

    id: str
    node_type: Literal["host", "process", "file", "network", "registry", "user", "ioc"]
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceNode:
        return cls(
            id=data.get("id", ""),
            node_type=data.get("node_type", "ioc"),
            properties=data.get("properties", {}),
        )


@dataclass
class EvidenceEdge:
    """An edge in the evidence graph."""

    source: str
    target: str
    edge_type: str
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceEdge:
        return cls(
            source=data.get("source", ""),
            target=data.get("target", ""),
            edge_type=data.get("edge_type", ""),
            properties=data.get("properties", {}),
        )


@dataclass
class EvidenceGraph:
    """An evidence graph containing nodes and edges."""

    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceGraph:
        return cls(
            nodes=[EvidenceNode.from_dict(n) for n in data.get("nodes", [])],
            edges=[EvidenceEdge.from_dict(e) for e in data.get("edges", [])],
        )

    def get_node(self, node_id: str) -> EvidenceNode | None:
        for n in self.nodes:
            if n.id == node_id:
                return n
        return None

    def nodes_of_type(self, node_type: str) -> list[EvidenceNode]:
        return [n for n in self.nodes if n.node_type == node_type]

    def edges_of_type(self, edge_type: str) -> list[EvidenceEdge]:
        return [e for e in self.edges if e.edge_type == edge_type]

    def outgoing(self, node_id: str) -> list[EvidenceEdge]:
        return [e for e in self.edges if e.source == node_id]

    def incoming(self, node_id: str) -> list[EvidenceEdge]:
        return [e for e in self.edges if e.target == node_id]


def _suggest_lateral_movement_hunts(graph: EvidenceGraph) -> list[HuntSuggestion]:
    """Suggest hunts based on observed lateral movement patterns."""
    suggestions: list[HuntSuggestion] = []

    network_edges = graph.edges_of_type("connected_to")
    hosts = {n.id: n for n in graph.nodes_of_type("host")}

    if len(hosts) >= 2:
        internal_ips = set()
        for node in graph.nodes_of_type("network"):
            ip = node.properties.get("ip", node.properties.get("dest_ip", ""))
            if ip:
                internal_ips.add(ip)

        if internal_ips:
            ip_list = ", ".join(f"'{ip}'" for ip in sorted(internal_ips)[:20])
            vql = (
                "SELECT \n"
                "  ClientId,\n"
                "  Hostname,\n"
                "  RemoteAddress,\n"
                "  RemotePort,\n"
                "  Pid,\n"
                "  ProcessName\n"
                "FROM netstat()\n"
                f"WHERE RemoteAddress IN ({ip_list})"
            )
            suggestions.append(HuntSuggestion(
                name="Lateral Movement — Internal Network Connections",
                description="Scan all endpoints for connections to observed internal IPs.",
                vql=vql,
                priority="high",
                rationale=f"Observed {len(hosts)} hosts in evidence graph with internal network activity.",
                technique_ids=["T1021", "T1570"],
                source_artifacts=[n.id for n in hosts.values()],
            ))

    process_nodes = graph.nodes_of_type("process")
    lateral_tools = {"psexec", "wmic", "winrm", "wmi", "ssh", "mstsc", "rdp"}
    for proc in process_nodes:
        name = proc.properties.get("name", proc.properties.get("process_name", "")).lower()
        cmd = proc.properties.get("command_line", "").lower()
        if any(tool in name or tool in cmd for tool in lateral_tools):
            tool_name = next((t for t in lateral_tools if t in name or t in cmd), "unknown")
            vql = (
                "SELECT \n"
                "  Pid,\n"
                "  ProcessName,\n"
                "  CommandLine,\n"
                "  ParentProcessName,\n"
                "  Username\n"
                "FROM process_creation()\n"
                f"WHERE ProcessName =~ '(?i){tool_name}'"
            )
            suggestions.append(HuntSuggestion(
                name=f"Lateral Movement — {tool_name.upper()} Usage",
                description=f"Hunt for {tool_name} process execution fleet-wide.",
                vql=vql,
                priority="critical",
                rationale=f"Process '{name}' observed in evidence graph indicates lateral movement tool usage.",
                technique_ids=["T1021.002", "T1047"],
                source_artifacts=[proc.id],
            ))

    return suggestions


def _suggest_file_lineage_hunts(graph: EvidenceGraph) -> list[HuntSuggestion]:
    """Suggest hunts based on observed file lineage and drops."""
    suggestions: list[HuntSuggestion] = []

    file_nodes = graph.nodes_of_type("file")
    suspicious_extensions = {
        ".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js",
        ".hta", ".wsf", ".scr", ".pif", ".msi", ".cab",
    }

    suspicious_files: list[EvidenceNode] = []
    for fnode in file_nodes:
        path = fnode.properties.get("path", fnode.properties.get("file_path", ""))
        ext = fnode.properties.get("extension", "")
        if not ext and path:
            ext = path[path.rfind("."):].lower() if "." in path else ""
        if ext in suspicious_extensions:
            suspicious_files.append(fnode)

    if suspicious_files:
        hash_set: set[str] = set()
        for sf in suspicious_files:
            for hash_key in ("sha256", "sha1", "md5", "file_hash_sha256", "file_hash_sha1", "file_hash_md5"):
                h = sf.properties.get(hash_key, "")
                if h:
                    hash_set.add(h.lower())

        if hash_set:
            hash_list = ", ".join(f"'{h}'" for h in sorted(hash_set)[:10])
            vql = (
                "SELECT \n"
                "  FullPath,\n"
                "  Size,\n"
                "  Mtime,\n"
                "  hash(path=FullPath) AS Hash\n"
                "FROM glob(globs='C:/**/*')\n"
                "WHERE hash(path=FullPath).SHA256 IN (" + hash_list + ")"
            )
            suggestions.append(HuntSuggestion(
                name="File Lineage — Known Malicious Hash Hunt",
                description="Fleet-wide search for files matching observed malicious hashes.",
                vql=vql,
                priority="critical",
                rationale=f"Observed {len(hash_set)} suspicious file hashes in evidence graph.",
                technique_ids=["T1105"],
                source_artifacts=[sf.id for sf in suspicious_files],
            ))

        write_edges = graph.edges_of_type("wrote")
        drop_paths: set[str] = set()
        for edge in write_edges:
            target_node = graph.get_node(edge.target)
            if target_node and target_node.node_type == "file":
                path = target_node.properties.get("path", target_node.properties.get("file_path", ""))
                if path:
                    drop_paths.add(path)

        if drop_paths:
            parent_dirs = set()
            for p in drop_paths:
                parts = p.replace("\\", "/").rsplit("/", 1)
                if len(parts) > 1:
                    parent_dirs.add(parts[0])

            if parent_dirs:
                dir_list = ", ".join(f"'{d}/**'" for d in sorted(parent_dirs)[:5])
                vql = (
                    "SELECT \n"
                    "  FullPath,\n"
                    "  Size,\n"
                    "  Mtime,\n"
                    "  hash(path=FullPath) AS Hash\n"
                    "FROM glob(globs=[\n"
                    f"  {dir_list}\n"
                    "])\n"
                    "WHERE Mtime > timestamp(epoch=now() - 86400)"
                )
                suggestions.append(HuntSuggestion(
                    name="File Lineage — Recently Dropped Files",
                    description="Hunt for recently created files in directories where malicious files were dropped.",
                    vql=vql,
                    priority="high",
                    rationale=f"Observed {len(drop_paths)} file drop events in evidence graph.",
                    technique_ids=["T1105", "T1059"],
                    source_artifacts=[e.source for e in write_edges],
                ))

    return suggestions


def _suggest_persistence_hunts(graph: EvidenceGraph) -> list[HuntSuggestion]:
    """Suggest hunts based on observed persistence mechanisms."""
    suggestions: list[HuntSuggestion] = []

    registry_nodes = graph.nodes_of_type("registry")
    persistence_keys = {
        "run", "runonce", "runservices", "startup",
        "currentversion\\run", "currentversion\\runonce",
        "winlogon\\shell", "winlogon\\userinit",
        "currentversion\\explorer\\shellserviceobjects",
    }

    for reg_node in registry_nodes:
        key = reg_node.properties.get("key", reg_node.properties.get("registry_key", "")).lower()
        if any(pk in key for pk in persistence_keys):
            vql = (
                "SELECT \n"
                "  Type,\n"
                "  KeyPath,\n"
                "  ValueName,\n"
                "  ValueData\n"
                "FROM glob(globs=['HKEY_USERS/*/Software/Microsoft/Windows/CurrentVersion/Run/*',\n"
                "                   'HKEY_LOCAL_MACHINE/Software/Microsoft/Windows/CurrentVersion/Run/*'])\n"
            )
            suggestions.append(HuntSuggestion(
                name="Persistence — Registry Run Keys",
                description="Fleet-wide hunt for persistence via registry Run keys.",
                vql=vql,
                priority="high",
                rationale="Observed registry persistence mechanism in evidence graph.",
                technique_ids=["T1547.001"],
                source_artifacts=[reg_node.id],
            ))
            break

    file_nodes = graph.nodes_of_type("file")
    startup_indicators = {"startup", "shell:startup", "programdata\\microsoft\\windows\\start menu"}
    for fnode in file_nodes:
        path = fnode.properties.get("path", fnode.properties.get("file_path", "")).lower()
        if any(si in path for si in startup_indicators):
            vql = (
                "SELECT \n"
                "  FullPath,\n"
                "  Size,\n"
                "  Mtime,\n"
                "  hash(path=FullPath) AS Hash\n"
                "FROM glob(globs=['C:/*Users/*/AppData/Roaming/Microsoft/Windows/Start Menu/**/*',\n"
                "                   'C:/*ProgramData/Microsoft/Windows/Start Menu/**/*'])\n"
            )
            suggestions.append(HuntSuggestion(
                name="Persistence — Startup Folder Items",
                description="Fleet-wide hunt for files in startup folders.",
                vql=vql,
                priority="high",
                rationale="Observed file creation in startup folder path.",
                technique_ids=["T1547.001"],
                source_artifacts=[fnode.id],
            ))
            break

    return suggestions


def _suggest_credential_hunts(graph: EvidenceGraph) -> list[HuntSuggestion]:
    """Suggest hunts based on observed credential access patterns."""
    suggestions: list[HuntSuggestion] = []

    process_nodes = graph.nodes_of_type("process")
    cred_tools = {
        "mimikatz", "sekurlsa", "procdump", "nanodump", "comsvcs",
        "lsassy", "pypykatz", "cachedump", "gsecdump",
    }

    for proc in process_nodes:
        name = proc.properties.get("name", proc.properties.get("process_name", "")).lower()
        cmd = proc.properties.get("command_line", "").lower()
        if any(ct in name or ct in cmd for ct in cred_tools):
            vql = (
                "SELECT \n"
                "  Pid,\n"
                "  ProcessName,\n"
                "  CommandLine,\n"
                "  ParentProcessName,\n"
                "  Username\n"
                "FROM process_creation()\n"
                "WHERE ProcessName =~ '(?i)mimikatz|procdump|nanodump|comsvcs|lsassy'"
            )
            suggestions.append(HuntSuggestion(
                name="Credential Access — Dump Tool Detection",
                description="Fleet-wide hunt for known credential dumping tools.",
                vql=vql,
                priority="critical",
                rationale="Credential dumping tool observed in evidence graph.",
                technique_ids=["T1003.001", "T1003.002"],
                source_artifacts=[proc.id],
            ))
            break

    auth_edges = graph.edges_of_type("authenticated_to")
    if len(auth_edges) > 5:
        vql = (
            "SELECT \n"
            "  EventID,\n"
            "  Username,\n"
            "  SourceIP,\n"
            "  LogonType,\n"
            "  Timestamp\n"
            "FROM parse_evtx(filename='Security.evtx')\n"
            "WHERE EventID = 4624 AND LogonType = 3\n"
            "GROUP BY Username, SourceIP\n"
            "HAVING count() > 5"
        )
        suggestions.append(HuntSuggestion(
            name="Credential Access — Excessive Network Logons",
            description="Fleet-wide hunt for accounts with excessive network logon activity.",
            vql=vql,
            priority="high",
            rationale=f"Observed {len(auth_edges)} authentication events in evidence graph.",
            technique_ids=["T1078", "T1021"],
            source_artifacts=[e.source for e in auth_edges[:5]],
        ))

    return suggestions


def _suggest_defense_evasion_hunts(graph: EvidenceGraph) -> list[HuntSuggestion]:
    """Suggest hunts based on observed defense evasion patterns."""
    suggestions: list[HuntSuggestion] = []

    process_nodes = graph.nodes_of_type("process")
    evasion_indicators = {
        "powershell", "cmd", "certutil", "bitsadmin", "mshta",
        "regsvr32", "rundll32", "wscript", "cscript",
    }

    encoded_cmd_pattern = re.compile(
        r"-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/]{20,}", re.I
    )

    for proc in process_nodes:
        cmd = proc.properties.get("command_line", "")
        if encoded_cmd_pattern.search(cmd):
            vql = (
                "SELECT \n"
                "  Pid,\n"
                "  ProcessName,\n"
                "  CommandLine,\n"
                "  ParentProcessName\n"
                "FROM process_creation()\n"
                "WHERE CommandLine =~ '(?i)-e(nc|ncodedcommand)?\\s+[A-Za-z0-9+/]{20,}'"
            )
            suggestions.append(HuntSuggestion(
                name="Defense Evasion — Encoded PowerShell Commands",
                description="Fleet-wide hunt for encoded PowerShell command execution.",
                vql=vql,
                priority="high",
                rationale="Encoded PowerShell command observed in evidence graph.",
                technique_ids=["T1059.001", "T1027"],
                source_artifacts=[proc.id],
            ))
            break

    for proc in process_nodes:
        name = proc.properties.get("name", proc.properties.get("process_name", "")).lower()
        cmd = proc.properties.get("command_line", "").lower()
        if "certutil" in name and ("decode" in cmd or "urlcache" in cmd):
            vql = (
                "SELECT \n"
                "  Pid,\n"
                "  ProcessName,\n"
                "  CommandLine,\n"
                "  ParentProcessName\n"
                "FROM process_creation()\n"
                "WHERE ProcessName =~ '(?i)certutil' AND CommandLine =~ '(?i)(decode|urlcache)'"
            )
            suggestions.append(HuntSuggestion(
                name="Defense Evasion — CertUtil Abuse",
                description="Fleet-wide hunt for certutil abuse (download/decode).",
                vql=vql,
                priority="high",
                rationale="CertUtil abuse observed in evidence graph.",
                technique_ids=["T1140"],
                source_artifacts=[proc.id],
            ))
            break

    return suggestions


def _deduplicate_suggestions(suggestions: list[HuntSuggestion]) -> list[HuntSuggestion]:
    """Remove duplicate hunt suggestions by name."""
    seen: set[str] = set()
    result: list[HuntSuggestion] = []
    for s in suggestions:
        if s.name not in seen:
            seen.add(s.name)
            result.append(s)
    return result


def suggest_hunts(graph: dict[str, Any]) -> list[dict[str, Any]]:
    """Suggest proactive Velociraptor VQL hunts from an evidence graph.

    Analyzes the evidence graph for patterns indicating lateral movement,
    file lineage, persistence mechanisms, credential access, and defense
    evasion. Returns prioritized hunt suggestions with executable VQL.

    Args:
        graph: Evidence graph dict with keys ``"nodes"`` and ``"edges"``.
            Each node has ``id``, ``node_type``, and ``properties``.
            Each edge has ``source``, ``target``, ``edge_type``, and
            ``properties``.

    Returns:
        List of hunt suggestion dicts, sorted by priority
        (critical → high → medium → low). Each contains:
        ``name``, ``description``, ``vql``, ``priority``,
        ``rationale``, ``technique_ids``, ``source_artifacts``.
    """
    evidence_graph = EvidenceGraph.from_dict(graph)

    all_suggestions: list[HuntSuggestion] = []
    all_suggestions.extend(_suggest_lateral_movement_hunts(evidence_graph))
    all_suggestions.extend(_suggest_file_lineage_hunts(evidence_graph))
    all_suggestions.extend(_suggest_persistence_hunts(evidence_graph))
    all_suggestions.extend(_suggest_credential_hunts(evidence_graph))
    all_suggestions.extend(_suggest_defense_evasion_hunts(evidence_graph))

    all_suggestions = _deduplicate_suggestions(all_suggestions)

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_suggestions.sort(key=lambda s: priority_order.get(s.priority, 99))

    return [s.to_dict() for s in all_suggestions]
