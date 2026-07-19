"""VQL hunt generator.

Given MITRE techniques (or a single technique), generates Velociraptor
VQL queries that hunt for evidence of those techniques on a target host.

Velociraptor artifacts are referenced by their canonical name
(e.g., `Windows.System.Pslist`, `Windows.EventLogs.Evtx`).
"""

from __future__ import annotations

import logging
from typing import Any, ClassVar

from nexus.analysis.schemas import (
    AnalysisResult,
    HuntQuery,
)
from nexus.ingest.schemas import Artifact

log = logging.getLogger(__name__)


class VQLHuntGenerator:
    """Generate Velociraptor VQL hunt queries for MITRE techniques.

    Usage:
        gen = VQLHuntGenerator()
        queries = gen.for_techniques(["T1003.001", "T1059.001"])
    """

    # Mapping of MITRE techniques to Velociraptor artifacts + VQL templates.
    # When multiple techniques apply, the more specific one wins.
    TECHNIQUE_QUERIES: ClassVar[dict[str, dict[str, Any]]] = {
        # Credential Access
        "T1003": {
            "name": "OS Credential Dumping",
            "artifacts": ["Windows.System.Drivers", "Windows.EventLogs.Evtx"],
            "vql": """
LET credential_dumping = SELECT * FROM foreach(
    row={
        SELECT Fqdn, OSPath, Mtime, Size
        FROM glob(globs=[
            "C:/Windows/System32/*.dll",
            "C:/Windows/System32/drivers/*.sys"
        ])
        WHERE Size < 1000000 AND Mtime > now() - 86400
    },
    query={
        SELECT * FROM info()
    }
)
SELECT * FROM credential_dumping
""",
            "rationale": "Detect suspicious small DLL/sys files created in last 24h — possible mimikatz/seatbelt/etc.",
        },
        "T1003.001": {
            "name": "LSASS Memory Dump",
            "artifacts": ["Windows.System.Pslist", "Windows.EventLogs.Evtx"],
            "vql": """
LET lsass_access = SELECT Timestamp, EventID, Source, Provider
FROM source(event="SELECT Timestamp, EventID, EventData, Source, Provider FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4661
SELECT * FROM lsass_access
""",
            "rationale": "Look for Event ID 4661 — handle access to LSASS process (mimikatz, ProcDump, comsvcs.dll).",
        },
        "T1003.002": {
            "name": "Security Account Manager (SAM) Dump",
            "artifacts": ["Windows.System.Drivers", "Windows.Registry.NTUser"],
            "vql": """
SELECT Fqdn, OSPath, Mtime, Size
FROM glob(globs=["C:/Windows/System32/config/SAM*", "C:/Windows/System32/config/SYSTEM*", "C:/Windows/repair/SAM"])
WHERE Mtime > now() - 86400
""",
            "rationale": "Look for access/modification of SAM/SYSTEM hive files in last 24h.",
        },
        "T1003.003": {
            "name": "NTDS.dit Dump",
            "artifacts": ["Windows.System.Drivers"],
            "vql": """
SELECT Fqdn, OSPath, Mtime, Size
FROM glob(globs=["C:/Windows/NTDS/ntds.dit", "C:/Windows/NTDS/ntds*.dit", "C:/temp/ntds.dit", "C:/ntds.dit"])
WHERE Size > 10000000
""",
            "rationale": "Look for NTDS.dit copies outside their normal location — domain controller credential extraction.",
        },
        # Execution
        "T1059.001": {
            "name": "PowerShell Execution",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.Powershell.Scriptblock"],
            "vql": """
LET ps_logs = SELECT * FROM source(
    event="SELECT EventID, TimeCreated, Computer, Payload FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell/Operational.evtx')"
)
WHERE EventID = 4104
SELECT * FROM ps_logs
""",
            "rationale": "PowerShell script block logging (Event 4104) — capture all PS activity for review.",
        },
        "T1059.003": {
            "name": "Windows Command Shell",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4688 AND EventData.CommandLine =~ "(?i)(whoami|net user|net group|net localgroup|nltest|ipconfig|systeminfo)"
""",
            "rationale": "Look for common recon commands run via cmd.exe (4688 with suspicious command lines).",
        },
        # Persistence
        "T1547.001": {
            "name": "Registry Run Keys / Startup Folder",
            "artifacts": ["Windows.Registry.NTUser", "Windows.Registry.User"],
            "vql": """
SELECT Fqdn, Key, Name, Value, Mtime
FROM glob(globs=[
    "HKEY_USERS/\\*/Software/Microsoft/Windows/CurrentVersion/Run",
    "HKEY_USERS/\\*/Software/Microsoft/Windows/CurrentVersion/RunOnce",
    "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/Run",
    "HKEY_LOCAL_MACHINE/SOFTWARE/Microsoft/Windows/CurrentVersion/RunOnce"
])
WHERE Value =~ "(?i)(powershell|cmd|rundll|regsvr|mshta|certutil|bitsadmin)"
""",
            "rationale": "Look for Run/RunOnce keys with suspicious values (LOLBAS commands).",
        },
        "T1543.003": {
            "name": "Windows Service Persistence",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.System.Services"],
            "vql": """
SELECT Name, DisplayName, Status, StartType, BinaryPathName, ServiceType
FROM source(artifact="Windows.System.Services")
WHERE BinaryPathName =~ "(?i)(powershell|cmd|regsvr|mshta|certutil|bitsadmin|\\.bat$|\\.ps1$)"
""",
            "rationale": "Look for services with suspicious binary paths (LOLBAS / scripts).",
        },
        # Lateral Movement
        "T1021.002": {
            "name": "SMB/Windows Admin Shares",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.Network.NetstatEnriched"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 5145 AND EventData.ShareName =~ "(?i)(ADMIN\\$|C\\$|IPC\\$)"
""",
            "rationale": "Event 5145 — network share access to ADMIN$/C$/IPC$ (lateral movement).",
        },
        "T1021.001": {
            "name": "Remote Desktop Protocol",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID IN (4624, 4625, 4648, 4778) AND EventData.LogonType = "10"
""",
            "rationale": "Event 4624/4625 with LogonType=10 (RemoteInteractive) — RDP logon detection.",
        },
        # Defense Evasion
        "T1070.001": {
            "name": "Clear Windows Event Logs",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 1102
""",
            "rationale": "Event 1102 — audit log was cleared (potential anti-forensics).",
        },
        "T1562.001": {
            "name": "Disable or Modify Tools",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.System.Services"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')")
WHERE EventID IN (7034, 7035, 7036) AND EventData.ServiceName =~ "(?i)(defender|antivirus|protection)"
""",
            "rationale": "Look for service state changes to Defender / AV products.",
        },
        # Discovery
        "T1087.002": {
            "name": "Domain Account Discovery",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4662 AND EventData.ObjectName =~ "(?i)(domain users|domain admins|enterprise admins|adminSDHolder)"
""",
            "rationale": "Event 4662 on privileged AD objects — domain enumeration.",
        },
        # Initial Access
        "T1110": {
            "name": "Brute Force",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4625
LIMIT 1000
""",
            "rationale": "Look for repeated 4625 events (failed logon) — possible brute force.",
        },
        "T1110.001": {
            "name": "Password Guessing",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4625 AND EventData.LogonType IN ("2", "3", "10")
""",
            "rationale": "LogonType 2 (interactive), 3 (network), 10 (RDP) — typical brute force targets.",
        },
        "T1078": {
            "name": "Valid Accounts",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4624 AND EventData.LogonType IN ("10", "9", "3")
""",
            "rationale": "Look for logons via existing accounts (4624) over RDP, NewCredentials, or network — possible valid account abuse.",
        },
        "T1078.002": {
            "name": "Domain Accounts",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4624 AND EventData.TargetUserName =~ "(?i)(admin|administrator|svc|service)"
""",
            "rationale": "Logon by privileged domain account names — verify each one is legitimate.",
        },
        # Execution - additional interpreters
        "T1059.005": {
            "name": "VBScript Execution",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.Sys.Drivers"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4688 AND EventData.CommandLine =~ "(?i)(wscript|cscript|\\.vbs)"
""",
            "rationale": "VBScript via wscript/cscript — possible scripting-based execution.",
        },
        "T1059.007": {
            "name": "JavaScript Execution",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 4688 AND EventData.CommandLine =~ "(?i)(mshta|\\.js|\\.jse)"
""",
            "rationale": "JavaScript/JScript execution via mshta or .js file association.",
        },
        "T1053.005": {
            "name": "Scheduled Task/Job - Scheduled Task",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.Sys.Drivers"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID IN (4698, 4702) AND EventData.TaskName =~ "(?i)(powershell|cmd|regsvr|mshta|certutil|bitsadmin|\\.ps1|\\.bat)"
""",
            "rationale": "Scheduled task creation (4698) / update (4702) with suspicious task names or binaries.",
        },
        # Account manipulation
        "T1136": {
            "name": "Create Account",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, Computer, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID IN (4720, 4732, 4756)
""",
            "rationale": "Event 4720 (user account created), 4732 (member added to local group), 4756 (member added to universal group).",
        },
        "T1098": {
            "name": "Account Manipulation",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID IN (4722, 4723, 4724, 4725, 4726, 4738, 4781)
""",
            "rationale": "Account enabled (4722), password set (4723/4724), disabled (4725), deleted (4726/4738), renamed (4781).",
        },
        # Command and Control
        "T1071.001": {
            "name": "Application Layer Protocol - Web",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.Network.NetstatEnriched"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Security.evtx')")
WHERE EventID = 5156 AND EventData.Direction =~ "(?i)(outbound)" AND EventData.Protocol = "6"
""",
            "rationale": "Outbound network connection attempts via Windows Filtering Platform logs.",
        },
        "T1071.004": {
            "name": "Application Layer Protocol - DNS",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/Microsoft-Windows-DNSServer/Analytical.evtx')")
WHERE EventID = 257
""",
            "rationale": "DNS Analytical event 257 — query logging for C2 over DNS detection.",
        },
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "artifacts": ["Windows.Network.NetstatEnriched", "Windows.EventLogs.Evtx"],
            "vql": """
SELECT Pid, Name, CommandLine, CreateTime
FROM source(artifact="Windows.System.Pslist")
WHERE CommandLine =~ "(?i)(curl|wget|Invoke-WebRequest|Invoke-RestMethod|bitsadmin|\\.zip|\\.rar|7z|compress)"
""",
            "rationale": "Look for processes with arguments that suggest data exfiltration over web/protocol channels.",
        },
        # Impact
        "T1486": {
            "name": "Data Encrypted for Impact (Ransomware)",
            "artifacts": ["Windows.EventLogs.Evtx", "Windows.NTFS.MFT"],
            "vql": """
SELECT Fqdn, OSPath, Mtime
FROM glob(globs=["C:/Users/*/Desktop/*", "C:/Users/*/Documents/*", "C:/Users/*/Pictures/*"])
WHERE OSPath =~ "(?i)\\.(encrypted|locked|crypt|enc)$"
LIMIT 1000
""",
            "rationale": "Look for files with ransomware-style extensions (.encrypted, .locked, .crypt).",
        },
        "T1490": {
            "name": "Inhibit System Recovery",
            "artifacts": ["Windows.EventLogs.Evtx"],
            "vql": """
SELECT EventID, TimeCreated, EventData
FROM source(event="SELECT * FROM watch_evtx(filename='C:/Windows/System32/winevt/Logs/System.evtx')")
WHERE EventID IN (8198, 8210) OR (EventID = 4688 AND EventData.CommandLine =~ "(?i)(vssadmin|bcdedit|wbadmin|reagentc).*(delete|disable)")
""",
            "rationale": "Volume Shadow Copy deletion (8198), shadow copy events (8210), or vssadmin/bcdedit/wbadmin delete commands.",
        },
        # Generic fallback
        "_default": {
            "name": "Generic Process Hunt",
            "artifacts": ["Windows.System.Pslist", "Windows.EventLogs.Evtx"],
            "vql": """
SELECT Fqdn, Name, CommandLine, Pid, Username, CreateTime
FROM source(artifact="Windows.System.Pslist")
WHERE Name =~ "(?i)(powershell|cmd|wscript|cscript|mshta|regsvr|rundll|certutil|bitsadmin|wmic|nltest)"
""",
            "rationale": "Generic hunt for processes named after common LOLBAS tools.",
        },
    }

    def for_techniques(self, technique_ids: list[str]) -> list[HuntQuery]:
        """Generate hunt queries for a list of MITRE techniques."""
        out: list[HuntQuery] = []
        seen: set[str] = set()
        for tid in technique_ids:
            tid_upper = tid.upper()
            if tid_upper in seen:
                continue
            seen.add(tid_upper)
            if tid_upper in self.TECHNIQUE_QUERIES:
                spec = self.TECHNIQUE_QUERIES[tid_upper]
            else:
                # Try parent technique
                parent = tid_upper.rsplit(".", 1)[0] if "." in tid_upper else "_default"
                spec = self.TECHNIQUE_QUERIES.get(parent, self.TECHNIQUE_QUERIES["_default"])
            out.append(HuntQuery(
                name=f"Hunt for {spec['name']} ({tid_upper})",
                description=spec["name"],
                technique_id=tid_upper,
                vql=spec["vql"].strip(),
                parameters={
                    "artifacts": spec["artifacts"],
                    "rationale": spec["rationale"],
                },
                notes="Run with `velociraptor --config server.config.yaml query --query '<vql>'`",
            ))
        return out

    def for_artifact(self, artifact: Artifact) -> list[HuntQuery]:
        """Generate hunt queries for an artifact's techniques."""
        return self.for_techniques(list(artifact.technique_ids))

    def for_artifacts(self, artifacts: list[Artifact]) -> list[HuntQuery]:
        """Generate unique hunt queries for the techniques in many artifacts."""
        techs: set[str] = set()
        for a in artifacts:
            for t in a.technique_ids:
                techs.add(t.upper())
        return self.for_techniques(sorted(techs))

    def list_supported_techniques(self) -> list[dict[str, str]]:
        """Return the list of techniques with custom templates."""
        out = []
        for tid, spec in self.TECHNIQUE_QUERIES.items():
            if tid == "_default":
                continue
            out.append({
                "technique_id": tid,
                "name": spec["name"],
                "artifacts": ", ".join(spec["artifacts"]),
            })
        return sorted(out, key=lambda x: x["technique_id"])

    def analyze(self, artifacts: list[Artifact]) -> AnalysisResult:
        """Generate hunt queries and return a partial AnalysisResult."""
        queries = self.for_artifacts(artifacts)
        return AnalysisResult(
            artifact_count=len(artifacts),
            hunt_queries=queries,
        )
