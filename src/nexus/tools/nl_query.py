"""Natural-language query translator.

Translates plain English descriptions into structured query languages:
VQL (Velociraptor), KQL (Microsoft Sentinel/Defender), SPL (Splunk),
Sigma (YAML), and YARA rules.
Uses pattern matching and templates — no LLM dependency.
Pure function — no side effects, no I/O.
"""

from __future__ import annotations

import re
from typing import Literal

TargetFormat = Literal["vql", "kql", "spl", "sigma", "yara"]

_QUERY_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"process.*(?:create|start|spawn)", re.I), "process_creation"),
    (re.compile(r"(?:file|document).*(?:create|write|drop|modify)", re.I), "file_creation"),
    (re.compile(r"(?:file|document).*(?:delet|remov)", re.I), "file_deletion"),
    (re.compile(r"(?:network|connect).*(?:outbound|external|c2|command)", re.I), "network_connection"),
    (re.compile(r"(?:dns|domain).*(?:queri|resolv|lookup)", re.I), "dns_query"),
    (re.compile(r"(?:login|logon|auth).*(?:fail|attempt|brute)", re.I), "auth_failure"),
    (re.compile(r"(?:login|logon|auth).*(?:success)", re.I), "auth_success"),
    (re.compile(r"(?:powershell|ps).*(?:execut|run|command|invoke)", re.I), "powershell_exec"),
    (re.compile(r"(?:registry|reg).*(?:modif|creat|add|set|write)", re.I), "registry_modification"),
    (re.compile(r"(?:schedul|cron|task).*(?:creat|add|regist)", re.I), "scheduled_task"),
    (re.compile(r"(?:service|svc).*(?:creat|install|modif)", re.I), "service_install"),
    (re.compile(r"(?:dll|library).*(?:inject|load)", re.I), "dll_injection"),
    (re.compile(r"(?:credential|password|hash).*(?:dump|extract|steal)", re.I), "credential_dump"),
    (re.compile(r"(?:lateral|mov|pivot|pass.the.hash|ptt)", re.I), "lateral_movement"),
    (re.compile(r"(?:persist|autorun|startup|run.key)", re.I), "persistence"),
    (re.compile(r"(?:exfil|data.steal|data.transfer)", re.I), "exfiltration"),
    (re.compile(r"(?:process).*(?:terminat|kill|end)", re.I), "process_termination"),
    (re.compile(r"(?:user|account).*(?:creat|add|new)", re.I), "user_creation"),
    (re.compile(r"(?:privilege|escalat|elevat|admin)", re.I), "privilege_escalation"),
    (re.compile(r"(?:defender|av|antivirus).*(?:disabl|stop|bypass)", re.I), "defense_evasion"),
]

_TEMPLATES: dict[str, dict[str, str]] = {
    "process_creation": {
        "vql": (
            "SELECT ProcessName, CommandLine, Pid, ParentPid, StartTime\n"
            "FROM process_creation()\n"
            "WHERE StartTime > timestamp(epoch={start_time})"
        ),
        "kql": (
            "DeviceProcessEvents\n"
            "| where Timestamp > datetime({start_time})\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName"
        ),
        "spl": (
            'index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1\n'
            "| table _time, Computer, Image, CommandLine, ParentImage, User"
        ),
        "sigma": (
            "title: Process Creation Detection\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 1\n"
            "  condition: selection"
        ),
        "yara": (
            "rule process_creation_indicator {\n"
            "  meta:\n"
            '    description = "Process creation artifact"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $cmd1 = "cmd.exe" ascii nocase\n'
            '    $cmd2 = "powershell" ascii nocase\n'
            "  condition:\n"
            "    any of them"
        ),
    },
    "file_creation": {
        "vql": (
            "SELECT FullPath, Size, Timestamp, Mtime\n"
            "FROM glob(globs='C:/**/*')\n"
            "WHERE Mtime > timestamp(epoch={start_time})"
        ),
        "kql": (
            "DeviceFileEvents\n"
            "| where ActionType == 'FileCreated'\n"
            "| where Timestamp > datetime({start_time})\n"
            "| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName"
        ),
        "spl": (
            'index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11\n'
            "| table _time, Computer, TargetFilename, Image"
        ),
        "sigma": (
            "title: File Creation Detection\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: file_event\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 11\n"
            "  condition: selection"
        ),
        "yara": (
            "rule file_creation_indicator {\n"
            "  meta:\n"
            '    description = "Suspicious file creation"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $ext1 = ".exe" ascii\n'
            '    $ext2 = ".dll" ascii\n'
            '    $ext3 = ".ps1" ascii\n'
            "  condition:\n"
            "    any of them"
        ),
    },
    "network_connection": {
        "vql": (
            "SELECT Pid, ProcessName, DestIP, DestPort, SrcIP, Timestamp\n"
            "FROM netstat()\n"
            "WHERE DestPort != 0"
        ),
        "kql": (
            "DeviceNetworkEvents\n"
            "| where ActionType == 'ConnectionSuccess'\n"
            "| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName"
        ),
        "spl": (
            'index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3\n'
            "| table _time, Computer, DestinationIp, DestinationPort, Image, User"
        ),
        "sigma": (
            "title: Network Connection Detection\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: network_connection\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 3\n"
            "  condition: selection"
        ),
        "yara": (
            "rule network_c2_indicator {\n"
            "  meta:\n"
            '    description = "C2 network communication pattern"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            "    $ip = /\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/ ascii\n"
            "  condition:\n"
            "    $ip"
        ),
    },
    "dns_query": {
        "vql": (
            "SELECT Name, Type, Answers, Timestamp\n"
            "FROM dns()\n"
            "WHERE Name != ''"
        ),
        "kql": (
            "DeviceNetworkEvents\n"
            "| where ActionType == 'DnsQueryResponse'\n"
            "| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName"
        ),
        "spl": (
            'index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22\n'
            "| table _time, Computer, QueryName, QueryResults"
        ),
        "sigma": (
            "title: DNS Query Detection\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: dns\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 22\n"
            "  condition: selection"
        ),
        "yara": (
            "rule dns_c2_indicator {\n"
            "  meta:\n"
            '    description = "DNS-based C2 communication"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $dns1 = "dns" ascii nocase\n'
            "    $domain = /[a-z0-9]{20,}\\.[a-z]{2,}/ ascii\n"
            "  condition:\n"
            "    $dns1 and $domain"
        ),
    },
    "auth_failure": {
        "vql": (
            "SELECT EventID, Username, SourceIP, LogonType, Timestamp\n"
            "FROM parse_evtx(filename='{evtx_path}')\n"
            "WHERE EventID IN (4625, 4771, 4776)"
        ),
        "kql": (
            "SecurityEvent\n"
            "| where EventID in (4625, 4771)\n"
            "| project TimeGenerated, Account, IpAddress, LogonType, Computer"
        ),
        "spl": (
            'index=main EventCode=4625\n'
            "| table _time, Computer, Account_Name, IpAddress, Logon_Type"
        ),
        "sigma": (
            "title: Authentication Failure Detection\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: authentication\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    EventID:\n"
            "      - 4625\n"
            "      - 4771\n"
            "  condition: selection"
        ),
        "yara": (
            "rule auth_failure_brute_force {\n"
            "  meta:\n"
            '    description = "Brute force authentication pattern"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $evt = "4625" ascii\n'
            "  condition:\n"
            "    $evt"
        ),
    },
    "powershell_exec": {
        "vql": (
            "SELECT ProcessName, CommandLine, Pid, ParentPid, StartTime\n"
            "FROM process_creation()\n"
            "WHERE ProcessName =~ 'powershell'"
        ),
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName =~ 'powershell.exe'\n"
            "| project Timestamp, DeviceName, ProcessCommandLine, AccountName"
        ),
        "spl": (
            'index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell*"\n'
            "| table _time, Computer, CommandLine, ParentImage, User"
        ),
        "sigma": (
            "title: PowerShell Execution\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\powershell.exe'\n"
            "  condition: selection"
        ),
        "yara": (
            "rule powershell_execution {\n"
            "  meta:\n"
            '    description = "PowerShell script execution"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $ps1 = "powershell" ascii nocase\n'
            '    $ps2 = "-encodedcommand" ascii nocase\n'
            '    $ps3 = "invoke-expression" ascii nocase\n'
            "  condition:\n"
            "    any of them"
        ),
    },
    "registry_modification": {
        "vql": (
            "SELECT Path, Name, Data, Timestamp\n"
            "FROM glob(globs='HKEY_*/**/*')\n"
            "WHERE Timestamp > timestamp(epoch={start_time})"
        ),
        "kql": (
            "DeviceRegistryEvents\n"
            "| where ActionType in ('RegistryValueSet', 'RegistryKeyCreated')\n"
            "| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData"
        ),
        "spl": (
            'index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (12, 13, 14)\n'
            "| table _time, Computer, EventType, TargetObject, Details"
        ),
        "sigma": (
            "title: Registry Modification\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: registry_event\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    EventID:\n"
            "      - 12\n"
            "      - 13\n"
            "      - 14\n"
            "  condition: selection"
        ),
        "yara": (
            "rule registry_persistence {\n"
            "  meta:\n"
            '    description = "Registry-based persistence"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $run = "CurrentVersion\\\\Run" ascii nocase\n'
            '    $svc = "CurrentVersion\\\\Services" ascii nocase\n'
            "  condition:\n"
            "    any of them"
        ),
    },
    "persistence": {
        "vql": (
            "SELECT Path, Name, Data, Timestamp\n"
            "FROM glob(globs='HKEY_*/**/Run*/*')\n"
            "UNION ALL\n"
            "SELECT Name, Command, Enabled FROM scheduled_tasks()"
        ),
        "kql": (
            "DeviceRegistryEvents\n"
            "| where RegistryKey contains 'CurrentVersion\\\\Run'\n"
            "| union DeviceProcessEvents\n"
            "| where FileName in ('schtasks.exe', 'at.exe')\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine"
        ),
        "spl": (
            'index=main (EventCode=12 OR EventCode=13) TargetObject="*\\\\Run\\\\*"\n'
            "| table _time, Computer, TargetObject, Details"
        ),
        "sigma": (
            "title: Persistence Mechanism\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: registry_event\n"
            "  product: windows\n"
            "detection:\n"
            "  selection_run:\n"
            "    TargetObject|contains: 'CurrentVersion\\Run'\n"
            "  selection_task:\n"
            "    Image|endswith: '\\schtasks.exe'\n"
            "  condition: selection_run or selection_task"
        ),
        "yara": (
            "rule persistence_indicator {\n"
            "  meta:\n"
            '    description = "Persistence mechanism indicators"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $run = "Run" ascii\n'
            '    $task = "schtasks" ascii nocase\n'
            '    $startup = "Startup" ascii nocase\n'
            "  condition:\n"
            "    any of them"
        ),
    },
    "credential_dump": {
        "vql": (
            "SELECT ProcessName, CommandLine, Pid, ParentPid\n"
            "FROM process_creation()\n"
            "WHERE ProcessName IN ('mimikatz', 'procdump', 'lsass')"
        ),
        "kql": (
            "DeviceProcessEvents\n"
            "| where ProcessCommandLine contains 'sekurlsa' or ProcessCommandLine contains 'lsass'\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName"
        ),
        "spl": (
            'index=main (Image="*mimikatz*" OR CommandLine="*sekurlsa*" OR CommandLine="*lsass*")\n'
            "| table _time, Computer, Image, CommandLine, User"
        ),
        "sigma": (
            "title: Credential Dumping\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    CommandLine|contains:\n"
            "      - 'sekurlsa'\n"
            "      - 'lsadump'\n"
            "      - 'lsass'\n"
            "  condition: selection"
        ),
        "yara": (
            "rule credential_dumping {\n"
            "  meta:\n"
            '    description = "Credential dumping tool indicators"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $mimi = "mimikatz" ascii nocase\n'
            '    $sek = "sekurlsa" ascii nocase\n'
            '    $lsass = "lsass" ascii nocase\n'
            "  condition:\n"
            "    any of them"
        ),
    },
    "lateral_movement": {
        "vql": (
            "SELECT ProcessName, CommandLine, DestIP, DestPort\n"
            "FROM process_creation()\n"
            "WHERE ProcessName IN ('psexec', 'wmic', 'winrm', 'ssh')"
        ),
        "kql": (
            "DeviceProcessEvents\n"
            "| where FileName in ('psexec.exe', 'wmic.exe', 'winrs.exe')\n"
            "| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName"
        ),
        "spl": (
            'index=main (Image="*psexec*" OR Image="*wmic*" OR CommandLine="*/node:*")\n'
            "| table _time, Computer, Image, CommandLine, User"
        ),
        "sigma": (
            "title: Lateral Movement\n"
            "status: experimental\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith:\n"
            "      - '\\psexec.exe'\n"
            "      - '\\wmic.exe'\n"
            "  condition: selection"
        ),
        "yara": (
            "rule lateral_movement {\n"
            "  meta:\n"
            '    description = "Lateral movement tool indicators"\n'
            "    author = \"DFIR-Nexus\"\n"
            "  strings:\n"
            '    $psexec = "psexec" ascii nocase\n'
            '    $wmic = "wmic" ascii nocase\n'
            '    $winrm = "winrm" ascii nocase\n'
            "  condition:\n"
            "    any of them"
        ),
    },
}

_FALLBACK_TEMPLATES: dict[str, str] = {
    "vql": (
        "SELECT *\n"
        "FROM {table}\n"
        "WHERE Timestamp > timestamp(epoch={start_time})"
    ),
    "kql": (
        "{table}\n"
        "| where Timestamp > datetime({start_time})\n"
        "| take 100"
    ),
    "spl": (
        'index=main sourcetype="{source}"\n'
        "| head 100"
    ),
    "sigma": (
        "title: Custom Detection\n"
        "status: experimental\n"
        "logsource:\n"
        "  category: generic\n"
        "detection:\n"
        "  selection:\n"
        "    EventID: 1\n"
        "  condition: selection"
    ),
    "yara": (
        "rule custom_indicator {\n"
        "  meta:\n"
        '    description = "Custom detection rule"\n'
        "    author = \"DFIR-Nexus\"\n"
        "  strings:\n"
        '    $s1 = "{pattern}" ascii nocase\n'
        "  condition:\n"
        "    any of them"
        ),
}


def _detect_intent(description: str) -> str:
    """Detect the query intent from a natural language description."""
    for pattern, intent in _QUERY_PATTERNS:
        if pattern.search(description):
            return intent
    return "generic"


def _extract_keywords(description: str) -> list[str]:
    """Extract potentially meaningful keywords from description."""
    stopwords = {
        "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
        "have", "has", "had", "do", "does", "did", "will", "would", "could",
        "should", "may", "might", "shall", "can", "need", "dare", "to", "of",
        "in", "for", "on", "with", "at", "by", "from", "as", "into", "about",
        "all", "and", "or", "but", "not", "if", "then", "that", "this",
        "these", "those", "it", "its", "i", "me", "my", "we", "our", "you",
        "your", "he", "him", "his", "she", "her", "they", "them", "their",
        "find", "show", "look", "search", "detect", "get", "list", "any",
        "some", "events", "activity", "logs",
    }
    words = re.findall(r"[a-zA-Z0-9_.-]+", description.lower())
    return [w for w in words if w not in stopwords and len(w) > 2]


def translate_query(description: str, target_format: TargetFormat) -> str:
    """Translate a natural language description into a structured query.

    Args:
        description: Plain English description of what to search for
            (e.g., "find all process creation events from the last hour",
            "show DNS queries to suspicious domains").
        target_format: Target query language — ``"vql"``, ``"kql"``,
            ``"spl"``, ``"sigma"``, or ``"yara"``.

    Returns:
        A query string in the target format.

    Raises:
        ValueError: If ``target_format`` is not a supported language.
    """
    fmt = target_format.lower().strip()
    if fmt not in ("vql", "kql", "spl", "sigma", "yara"):
        raise ValueError(
            f"Unsupported format: {target_format!r}. "
            f"Supported: vql, kql, spl, sigma, yara"
        )

    intent = _detect_intent(description)

    if intent in _TEMPLATES and fmt in _TEMPLATES[intent]:
        return _TEMPLATES[intent][fmt]

    keywords = _extract_keywords(description)
    fallback = _FALLBACK_TEMPLATES[fmt]

    table_map = {
        "vql": "process_creation()",
        "kql": "DeviceProcessEvents",
        "spl": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "sigma": "process_creation",
        "yara": "",
    }

    pattern = keywords[0] if keywords else "unknown"
    table = table_map.get(fmt, "generic")
    start_time = "now() - 3600"

    return fallback.format(
        table=table,
        source=table,
        start_time=start_time,
        pattern=pattern,
    )
