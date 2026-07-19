"""Asset ↔ IOC graph — maps hosts and accounts to indicators of compromise.

Builds a bipartite graph where AssetNode vertices (hosts, accounts) are
connected to IOCNode vertices (IPs, hashes, domains, etc.) by edges that
record "this IOC was seen on this asset".

Accounts are auto-extracted from event text via DOMAIN\\user and UPN/email
regex patterns.  Hosts come directly from Artifact.host.

Pure/deterministic — no AI, no network calls.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from nexus.ingest.schemas import Artifact


class AssetType(StrEnum):
    """Kind of asset node."""
    HOST = "host"
    ACCOUNT = "account"


class IOCType(StrEnum):
    """Kind of indicator of compromise."""
    IP = "ip"
    HASH = "hash"
    DOMAIN = "domain"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    EMAIL = "email"


# ---------------------------------------------------------------------------
# Regex patterns for account extraction
# ---------------------------------------------------------------------------

# DOMAIN\user (e.g. CORP\jsmith, NT AUTHORITY\SYSTEM)
_DOMAIN_USER_RE = re.compile(
    r"(?<![\\/\w])(?P<domain>[A-Za-z0-9_.-]+)\\(?P<user>[A-Za-z0-9_.$-]+)"
)

# UPN / email-style accounts embedded in event text
_UPN_RE = re.compile(
    r"(?P<user>[A-Za-z0-9_.+-]+)@(?P<domain>[A-Za-z0-9-]+\.[A-Za-z0-9.-]+)"
)

# IP addresses (v4 only — keeps false-positive rate low)
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# SHA-256 / SHA-1 / MD5 hashes in hex
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")

# File paths (Windows and Unix)
_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\(?:[^\\\s:*?\"<>|\r\n]+\\)*[^\\\s:*?\"<>|\r\n]+")
_UNIX_PATH_RE = re.compile(r"(?:/[^/\s:*?\"<>|\r\n]+){2,}")

# Registry keys
_REG_RE = re.compile(
    r"(?:HKLM|HKCU|HKU|HKCR|HKCC|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER"
    r"|HKEY_USERS|HKEY_CLASSES_ROOT|HKEY_CURRENT_CONFIG)"
    r"\\[^\s:*?\"<>|\r\n]+",
    re.IGNORECASE,
)


def _normalise_account(domain: str, user: str) -> str:
    """Canonical form for an account identifier."""
    d = domain.upper().strip(".")
    u = user.upper()
    # Skip well-known built-in principals that add noise
    if d in {"NT AUTHORITY", "BUILTIN", "WINDOW MANAGER", "LOCAL SERVICE",
             "NETWORK SERVICE", "DWM"}:
        return ""
    if u in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "DWM"}:
        return ""
    return f"{d}\\{u}"


@dataclass
class AssetNode:
    """An asset (host or account) in the graph."""
    id: str
    asset_type: AssetType
    label: str
    artifact_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "asset_type": self.asset_type.value,
            "label": self.label,
            "artifact_ids": self.artifact_ids,
        }


@dataclass
class IOCNode:
    """An indicator of compromise in the graph."""
    id: str
    ioc_type: IOCType
    value: str
    artifact_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "artifact_ids": self.artifact_ids,
        }


@dataclass
class AssetIOCEdge:
    """Edge connecting an asset to an IOC (\"seen on\" relationship)."""
    asset_id: str
    ioc_id: str
    artifact_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ioc_id": self.ioc_id,
            "artifact_ids": self.artifact_ids,
        }


@dataclass
class AssetGraph:
    """The complete Asset ↔ IOC bipartite graph."""
    assets: dict[str, AssetNode] = field(default_factory=dict)
    iocs: dict[str, IOCNode] = field(default_factory=dict)
    edges: list[AssetIOCEdge] = field(default_factory=list)

    @property
    def asset_count(self) -> int:
        return len(self.assets)

    @property
    def ioc_count(self) -> int:
        return len(self.iocs)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def add_asset(self, node: AssetNode) -> None:
        if node.id in self.assets:
            existing = self.assets[node.id]
            for aid in node.artifact_ids:
                if aid not in existing.artifact_ids:
                    existing.artifact_ids.append(aid)
        else:
            self.assets[node.id] = node

    def add_ioc(self, node: IOCNode) -> None:
        if node.id in self.iocs:
            existing = self.iocs[node.id]
            for aid in node.artifact_ids:
                if aid not in existing.artifact_ids:
                    existing.artifact_ids.append(aid)
        else:
            self.iocs[node.id] = node

    def add_edge(self, edge: AssetIOCEdge) -> None:
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_count": self.asset_count,
            "ioc_count": self.ioc_count,
            "edge_count": self.edge_count,
            "assets": [a.to_dict() for a in self.assets.values()],
            "iocs": [i.to_dict() for i in self.iocs.values()],
            "edges": [e.to_dict() for e in self.edges],
        }


def build_asset_graph(artifacts: list[Artifact]) -> AssetGraph:
    """Build a deterministic Asset ↔ IOC graph from a list of artifacts.

    Pure function — no side effects, no I/O, no AI.
    """
    graph = AssetGraph()

    # Temporary lookup: (asset_id, ioc_id) -> list[artifact_id]
    edge_index: dict[tuple[str, str], list[str]] = defaultdict(list)

    def _link(asset_id: str, ioc_id: str, artifact_id: str) -> None:
        edge_index[(asset_id, ioc_id)].append(artifact_id)

    for art in artifacts:
        # ---- Host asset ----
        if art.host:
            host_id = f"host:{art.host.lower()}"
            graph.add_asset(AssetNode(
                id=host_id,
                asset_type=AssetType.HOST,
                label=art.host,
                artifact_ids=[art.id],
            ))

            # Link host ↔ every IOC on this artifact
            for ip in (art.source_ip, art.dest_ip):
                if ip:
                    ioc_id = f"ioc:ip:{ip}"
                    graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.IP, value=ip, artifact_ids=[art.id]))
                    _link(host_id, ioc_id, art.id)
            for h in (art.file_hash_md5, art.file_hash_sha1, art.file_hash_sha256):
                if h:
                    h_lower = h.lower()
                    ioc_id = f"ioc:hash:{h_lower}"
                    graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.HASH, value=h_lower, artifact_ids=[art.id]))
                    _link(host_id, ioc_id, art.id)
            if art.file_path:
                ioc_id = f"ioc:path:{art.file_path.lower()}"
                graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.FILE_PATH, value=art.file_path, artifact_ids=[art.id]))
                _link(host_id, ioc_id, art.id)
            if art.registry_key:
                ioc_id = f"ioc:reg:{art.registry_key.lower()}"
                graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.REGISTRY_KEY, value=art.registry_key, artifact_ids=[art.id]))
                _link(host_id, ioc_id, art.id)

        # ---- Account assets from structured fields ----
        if art.user and art.host:
            acct = _normalise_account("", art.user)
            if acct:
                acct_id = f"acct:{acct}"
                graph.add_asset(AssetNode(id=acct_id, asset_type=AssetType.ACCOUNT, label=acct, artifact_ids=[art.id]))
                host_id = f"host:{art.host.lower()}"
                for ip in (art.source_ip, art.dest_ip):
                    if ip:
                        ioc_id = f"ioc:ip:{ip}"
                        graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.IP, value=ip, artifact_ids=[art.id]))
                        _link(acct_id, ioc_id, art.id)

        # ---- Account extraction from free-form text (description, raw) ----
        text_pool = art.description or ""
        raw_text = " ".join(str(v) for v in art.raw.values()) if art.raw else ""
        combined = f"{text_pool} {raw_text}"

        if combined.strip():
            for m in _DOMAIN_USER_RE.finditer(combined):
                acct = _normalise_account(m.group("domain"), m.group("user"))
                if acct:
                    acct_id = f"acct:{acct}"
                    graph.add_asset(AssetNode(id=acct_id, asset_type=AssetType.ACCOUNT, label=acct, artifact_ids=[art.id]))
                    host_id = f"host:{art.host.lower()}" if art.host else None
                    if host_id:
                        _link(host_id, acct_id, art.id)

            for m in _UPN_RE.finditer(combined):
                acct = _normalise_account(m.group("domain"), m.group("user"))
                if acct:
                    acct_id = f"acct:{acct}"
                    graph.add_asset(AssetNode(id=acct_id, asset_type=AssetType.ACCOUNT, label=acct, artifact_ids=[art.id]))

        # ---- IOC extraction from free-form text ----
        if combined.strip():
            host_id = f"host:{art.host.lower()}" if art.host else None

            for m in _IPV4_RE.finditer(combined):
                ip = m.group(0)
                # Skip obvious non-routable noise (0.0.0.0, 255.255.255.255)
                if ip in ("0.0.0.0", "255.255.255.255"):
                    continue
                ioc_id = f"ioc:ip:{ip}"
                graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.IP, value=ip, artifact_ids=[art.id]))
                if host_id:
                    _link(host_id, ioc_id, art.id)

            for m in _HASH_RE.finditer(combined):
                h = m.group(0).lower()
                ioc_id = f"ioc:hash:{h}"
                graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.HASH, value=h, artifact_ids=[art.id]))
                if host_id:
                    _link(host_id, ioc_id, art.id)

            for m in _REG_RE.finditer(combined):
                reg = m.group(0)
                ioc_id = f"ioc:reg:{reg.lower()}"
                graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.REGISTRY_KEY, value=reg, artifact_ids=[art.id]))
                if host_id:
                    _link(host_id, ioc_id, art.id)

            for pattern in (_WIN_PATH_RE, _UNIX_PATH_RE):
                for m in pattern.finditer(combined):
                    p = m.group(0)
                    ioc_id = f"ioc:path:{p.lower()}"
                    graph.add_ioc(IOCNode(id=ioc_id, ioc_type=IOCType.FILE_PATH, value=p, artifact_ids=[art.id]))
                    if host_id:
                        _link(host_id, ioc_id, art.id)

    # Deduplicate edges
    for (asset_id, ioc_id), artifact_ids in edge_index.items():
        # Ensure both endpoints exist (account linking to host edge case)
        if asset_id in graph.assets and ioc_id in graph.iocs:
            graph.add_edge(AssetIOCEdge(
                asset_id=asset_id,
                ioc_id=ioc_id,
                artifact_ids=list(set(artifact_ids)),
            ))

    return graph
