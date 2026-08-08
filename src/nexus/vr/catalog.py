"""Velociraptor artifact + hunt catalog."""

from __future__ import annotations

import re

from nexus.vr.schemas import VRCatalogEntry

_PARAM_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

VR_HUNTS: list[VRCatalogEntry] = [
    VRCatalogEntry(
        id="nexus-process-tree",
        artifact_name="Nexus.Hunts.ProcessTree",
        title="Process Tree",
        description="Pslist, scheduled tasks, and services — process-based attacks.",
        platforms=["windows"],
        technique_ids=["T1059", "T1053", "T1543", "T1547"],
    ),
    VRCatalogEntry(
        id="nexus-credential-access",
        artifact_name="Nexus.Hunts.CredentialAccess",
        title="Credential Access",
        description="AMCache, NTUser registry, and prefetch — credential dumping.",
        platforms=["windows"],
        technique_ids=["T1003", "T1003.001", "T1003.002", "T1555"],
    ),
    VRCatalogEntry(
        id="nexus-network-state",
        artifact_name="Nexus.Hunts.NetworkState",
        title="Network State",
        description="Netstat, DNS cache, and ARP — lateral movement and C2.",
        platforms=["windows"],
        technique_ids=["T1071", "T1021", "T1041"],
    ),
    VRCatalogEntry(
        id="nexus-fs-timeline",
        artifact_name="Nexus.Hunts.FilesystemTimeline",
        title="Filesystem Timeline",
        description="MFT and USN journal — file drops and persistence.",
        platforms=["windows"],
        technique_ids=["T1486", "T1070", "T1547"],
    ),
    VRCatalogEntry(
        id="nexus-registry-snapshot",
        artifact_name="Nexus.Hunts.RegistrySnapshot",
        title="Registry Snapshot",
        description="SAM, SECURITY, and SYSTEM hives — privilege escalation.",
        platforms=["windows"],
        technique_ids=["T1068", "T1547", "T1098"],
    ),
    VRCatalogEntry(
        id="nexus-event-logs",
        artifact_name="Nexus.Hunts.EventLogs",
        title="Event Logs",
        description="Export all EVTX for Hayabusa / Chainsaw analysis.",
        platforms=["windows"],
        technique_ids=["T1070", "T1059"],
    ),
    VRCatalogEntry(
        id="nexus-adcs-snapshot",
        artifact_name="Nexus.Hunts.ADCSSnapshot",
        title="ADCS Snapshot",
        description="CA database and template config — ADCS attacks (ESC).",
        platforms=["windows"],
        technique_ids=["T1649", "T1553"],
    ),
    VRCatalogEntry(
        id="nexus-sccm-snapshot",
        artifact_name="Nexus.Hunts.SCCMSnapshot",
        title="SCCM Snapshot",
        description="SCCM WMI classes and NAA policy — SCCM branch attacks.",
        platforms=["windows"],
        technique_ids=["T1210", "T1078"],
    ),
    VRCatalogEntry(
        id="nexus-linux-triage",
        artifact_name="Nexus.Hunts.LinuxTriage",
        title="Linux Triage",
        description="Audit logs, bash history, netstat, keytabs, podman, SSSD.",
        platforms=["linux"],
        technique_ids=["T1550", "T1078", "T1611"],
    ),
    VRCatalogEntry(
        id="nexus-full-breach",
        artifact_name="Nexus.Hunts.FullBreach",
        title="Full Breach",
        description="Union of all hunt artifacts — comprehensive collection.",
        platforms=["windows", "linux"],
        technique_ids=[],
    ),
]

VR_CUSTOM_ARTIFACTS: list[VRCatalogEntry] = [
    VRCatalogEntry(
        id="nexus-linux-keytab-fingerprints",
        artifact_name="Nexus.Linux.KeytabFingerprints",
        title="Linux Keytab Fingerprints",
        description="klist -ke inventory for krb5/mssql keytabs on linux01.",
        platforms=["linux"],
        technique_ids=["T1550", "T1558"],
        kind="custom_artifact",
    ),
    VRCatalogEntry(
        id="nexus-linux-podman-inventory",
        artifact_name="Nexus.Linux.PodmanInventory",
        title="Linux Podman Inventory",
        description="Container images, mounts, and privileged namespace inventory.",
        platforms=["linux"],
        technique_ids=["T1611"],
        kind="custom_artifact",
    ),
    VRCatalogEntry(
        id="nexus-linux-sssd-cache",
        artifact_name="Nexus.Linux.SSSDCache",
        title="Linux SSSD Cache",
        description="SSSD cache.db metadata extraction.",
        platforms=["linux"],
        technique_ids=["T1078"],
        kind="custom_artifact",
    ),
    VRCatalogEntry(
        id="nexus-windows-adcs-templates",
        artifact_name="Nexus.Windows.AdcsTemplates",
        title="Windows ADCS Templates",
        description="ADCS template ACL and flag inventory.",
        platforms=["windows"],
        technique_ids=["T1649"],
        kind="custom_artifact",
    ),
    VRCatalogEntry(
        id="nexus-windows-sccm-policy",
        artifact_name="Nexus.Windows.SccmPolicy",
        title="Windows SCCM Policy",
        description="NAA policy and client-push configuration.",
        platforms=["windows"],
        technique_ids=["T1210"],
        kind="custom_artifact",
    ),
]

VR_MOCK_CLIENTS: list[dict[str, str]] = [
    {"client_id": "C.dc01", "hostname": "dc01.lab.example", "platform": "windows", "ip": "192.0.2.10"},
    {"client_id": "C.dc02", "hostname": "dc02.child.lab.example", "platform": "windows", "ip": "192.0.2.11"},
    {"client_id": "C.dc03", "hostname": "dc03.range.local", "platform": "windows", "ip": "192.0.2.12"},
    {"client_id": "C.mbr01", "hostname": "mbr01.lab.example", "platform": "windows", "ip": "192.0.2.20"},
    {"client_id": "C.mbr02", "hostname": "mbr02.lab.example", "platform": "windows", "ip": "192.0.2.21"},
    {"client_id": "C.linux01", "hostname": "linux01.lab.example", "platform": "linux", "ip": "192.0.2.40"},
    {"client_id": "C.vr", "hostname": "vr.lab.example", "platform": "linux", "ip": "192.0.2.51"},
]

_HUNT_BY_ID = {h.id: h for h in VR_HUNTS}
_ARTIFACT_BY_ID = {a.id: a for a in VR_CUSTOM_ARTIFACTS}
_ALL_BY_ARTIFACT = {h.artifact_name: h for h in VR_HUNTS + VR_CUSTOM_ARTIFACTS}


def list_hunts(*, technique_id: str | None = None) -> list[VRCatalogEntry]:
    if not technique_id:
        return list(VR_HUNTS)
    tid = technique_id.upper()
    return [
        h
        for h in VR_HUNTS
        if not h.technique_ids
        or tid in h.technique_ids
        or any(tid.startswith(t) or t.startswith(tid) for t in h.technique_ids)
    ]


def list_custom_artifacts() -> list[VRCatalogEntry]:
    return list(VR_CUSTOM_ARTIFACTS)


def get_hunt(hunt_id: str) -> VRCatalogEntry | None:
    return _HUNT_BY_ID.get(hunt_id)


def get_catalog_entry(entry_id: str) -> VRCatalogEntry | None:
    return _HUNT_BY_ID.get(entry_id) or _ARTIFACT_BY_ID.get(entry_id)


def suggest_hunt_ids(technique_ids: list[str], *, limit: int = 3) -> list[str]:
    if not technique_ids:
        return ["nexus-process-tree"]
    scores: dict[str, int] = {}
    for tid in technique_ids:
        for hunt in list_hunts(technique_id=tid):
            scores[hunt.id] = scores.get(hunt.id, 0) + 1
    if not scores:
        return ["nexus-process-tree"]
    ranked = sorted(scores.items(), key=lambda x: (-x[1], x[0]))
    return [hunt_id for hunt_id, _ in ranked[:limit]]


def validate_artifact_name(artifact_name: str) -> None:
    if artifact_name not in _ALL_BY_ARTIFACT:
        raise ValueError(f"Unknown Velociraptor artifact: {artifact_name}")


def _vql_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def artifact_vql(artifact_name: str, parameters: dict[str, str] | None = None) -> str:
    validate_artifact_name(artifact_name)
    params = parameters or {}
    for key in params:
        if not _PARAM_NAME_RE.match(key):
            raise ValueError(f"Invalid VQL parameter name: {key}")
    if params:
        param_vql = ", ".join(
            f'{k}="{_vql_escape(str(v))}"' for k, v in params.items()
        )
        return f"SELECT * FROM Artifact.{artifact_name}({param_vql})"
    return f"SELECT * FROM Artifact.{artifact_name}()"
