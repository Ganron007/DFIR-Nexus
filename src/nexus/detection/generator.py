"""Detection rule generator — template-based Sigma rule synthesis from CTI.

Converts a CTIItem (techniques, IOCs, CVEs, products) into a valid Sigma
rule YAML string using deterministic templates. No LLM involved.

All functions are pure: CTIItem in → Sigma YAML string out.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime

from nexus.ingest.cti_ingestion import CTIItem, CTIItemType


def generate_sigma_rule(cti_item: CTIItem) -> str:
    """Generate a Sigma rule YAML string from a CTIItem.

    Dispatches to the appropriate template based on ``cti_item.item_type``.
    The generated rule includes:
    - A unique Sigma rule ID (UUID v4)
    - Title, description from the CTI item
    - MITRE ATT&CK tags derived from technique/tactic IDs
    - Detection logic appropriate to the item type
    - Severity mapped from CTI severity

    Args:
        cti_item: Normalized threat intelligence item.

    Returns:
        A complete Sigma rule YAML string.
    """
    rule_id = str(uuid.uuid4())
    title = _sanitize_title(cti_item.title)
    description = _sanitize_description(cti_item.description)
    level = _map_severity(cti_item.severity)
    tags = _build_tags(cti_item)
    author = "DFIR-Nexus CTI Pipeline"
    date = datetime.now(UTC).strftime("%Y/%m/%d")

    if cti_item.item_type == CTIItemType.VULNERABILITY:
        detection = _detection_for_vulnerability(cti_item)
        logsource = _logsource_vulnerability()
    elif cti_item.item_type == CTIItemType.TECHNIQUE:
        detection = _detection_for_technique(cti_item)
        logsource = _logsource_technique(cti_item)
    elif cti_item.item_type == CTIItemType.INDICATOR:
        detection = _detection_for_indicator(cti_item)
        logsource = _logsource_generic()
    else:
        detection = _detection_generic(cti_item)
        logsource = _logsource_generic()

    tags_line = "\n".join(f"    - {t}" for t in tags) if tags else "    - attack.initial_access"

    yaml_str = f"""title: {title}
id: {rule_id}
status: experimental
description: >
  {description}
author: {author}
date: {date}
modified: {date}
tags:
{tags_line}
logsource:
{logsource}
detection:
{detection}
falsepositives:
    - Unknown
level: {level}"""

    return yaml_str


# ---------------------------------------------------------------------------
# Detection templates
# ---------------------------------------------------------------------------


def _detection_for_vulnerability(item: CTIItem) -> str:
    """Build detection block for a vulnerability (CVE) item.

    Targets web/proxy/firewall logs where exploitation attempts may appear.
    """
    conditions: list[str] = []

    # Match on CVE ID in log messages
    for cve in item.cve_ids:
        conditions.append(f'    Keywords|contains: "{cve}"')

    # Match on product names
    for product in item.affected_products:
        product_clean = _sanitize_field_value(product)
        conditions.append(f'    Product|contains: "{product_clean}"')

    # IOC-based conditions
    for ioc in item.iocs[:10]:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
            conditions.append(f"    SourceIP: '{ioc}'")
            conditions.append(f"    DestinationIP: '{ioc}'")

    if not conditions:
        conditions.append('    Keywords|contains: "exploit"')

    selection_block = "\n".join(conditions)
    return f"""    selection:
{selection_block}
    condition: selection"""


def _detection_for_technique(item: CTIItem) -> str:
    """Build detection block for a MITRE ATT&CK technique.

    Uses technique-specific heuristics for logsource and field matching.
    """
    technique_id = item.technique_ids[0] if item.technique_ids else ""

    # Technique-specific templates
    templates = {
        "T1190": _detection_t1190,
        "T1566": _detection_t1566,
        "T1059": _detection_t1059,
        "T1053": _detection_t1053,
        "T1003": _detection_t1003,
        "T1071": _detection_t1071,
    }

    # Try exact match first, then prefix
    builder = templates.get(technique_id)
    if builder is None:
        for prefix, fn in templates.items():
            if technique_id.startswith(prefix):
                builder = fn
                break

    if builder is None:
        return _detection_generic(item)

    return builder(item)


def _detection_t1190(item: CTIItem) -> str:
    """T1190 — Exploit Public-Facing Application."""
    conditions = ['    selection:', '        c-uri|contains:']

    for cve in item.cve_ids:
        conditions.append(f'            - "{cve}"')

    # Add IOC paths if present
    for ioc in item.iocs[:5]:
        if "/" in ioc or "." in ioc:
            conditions.append(f'            - "{ioc}"')

    if len(conditions) == 2:
        conditions.append('            - "exploit"')

    conditions.append("    condition: selection")
    return "\n".join(conditions)


def _detection_t1566(item: CTIItem) -> str:
    """T1566 — Phishing."""
    return """    selection_1:
        EventID: 1
        ParentImage|endswith:
            - '\\OUTLOOK.EXE'
            - '\\WINWORD.EXE'
            - '\\EXCEL.EXE'
    selection_2:
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
    condition: selection_1 and selection_2"""


def _detection_t1059(item: CTIItem) -> str:
    """T1059 — Command and Scripting Interpreter."""
    return """    selection:
        EventID: 1
        Image|endswith:
            - '\\cmd.exe'
            - '\\powershell.exe'
            - '\\pwsh.exe'
            - '\\wscript.exe'
            - '\\cscript.exe'
            - '\\mshta.exe'
    filter:
        ParentImage|endswith:
            - '\\explorer.exe'
            - '\\svchost.exe'
    condition: selection and not filter"""


def _detection_t1053(item: CTIItem) -> str:
    """T1053 — Scheduled Task/Job."""
    return """    selection:
        EventID:
            - 4698
            - 1
        Image|endswith:
            - '\\schtasks.exe'
            - '\\at.exe'
    condition: selection"""


def _detection_t1003(item: CTIItem) -> str:
    """T1003 — OS Credential Dumping."""
    return """    selection:
        EventID:
            - 1
            - 10
        Image|endswith:
            - '\\mimikatz.exe'
            - '\\procdump.exe'
            - '\\nanodump.exe'
        CommandLine|contains:
            - 'sekurlsa'
            - 'lsadump'
            - 'token::elevate'
            - 'lsass'
    condition: selection"""


def _detection_t1071(item: CTIItem) -> str:
    """T1071 — Application Layer Protocol (C2)."""
    return """    selection:
        EventID: 3
        DestinationPort:
            - 80
            - 443
            - 8080
    filter:
        Image|endswith:
            - '\\chrome.exe'
            - '\\firefox.exe'
            - '\\msedge.exe'
            - '\\iexplore.exe'
    condition: selection and not filter"""


def _detection_for_indicator(item: CTIItem) -> str:
    """Build detection block for IOC-based items (hashes, IPs, domains)."""
    selection_parts: list[str] = []

    for ioc in item.iocs[:20]:
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc) or re.match(r"^[a-fA-F0-9]{32,64}$", ioc):
            selection_parts.append(f"        - '{ioc}'")
        else:
            selection_parts.append(f'        - "{ioc}"')

    if not selection_parts:
        return _detection_generic(item)

    hash_lines = [x for x in selection_parts if re.search(r"[a-fA-F0-9]{32,64}", x)]
    ip_lines = [x for x in selection_parts if re.search(r"\d{1,3}\.\d{1,3}", x)]
    other_lines = [x for x in selection_parts if x not in hash_lines and x not in ip_lines]

    blocks: list[str] = []
    if hash_lines:
        blocks.append("    selection_hash:\n        Hashes|contains:\n" + "\n".join(hash_lines))
    if ip_lines:
        blocks.append("    selection_ip:\n        DestinationIP:\n" + "\n".join(ip_lines))
    if other_lines:
        blocks.append("    selection_domain:\n        QueryName|contains:\n" + "\n".join(other_lines))

    if not blocks:
        blocks.append("    selection:\n" + "\n".join(selection_parts))

    detection_text = "\n".join(blocks)

    selection_names = [
        n.split("_")[1]
        for n in re.findall(r"selection_\w+", detection_text)
    ]
    if len(selection_names) > 1:
        condition = " or ".join(f"selection_{n}" for n in selection_names)
    elif selection_names:
        condition = f"selection_{selection_names[0]}"
    else:
        condition = "selection"

    return f"{detection_text}\n    condition: {condition}"


def _detection_generic(item: CTIItem) -> str:
    """Fallback generic detection block."""
    keyword = _sanitize_field_value(item.title.split(":")[0].strip()[:40])
    return f"""    selection:
        CommandLine|contains: "{keyword}"
    condition: selection"""


# ---------------------------------------------------------------------------
# Logsource templates
# ---------------------------------------------------------------------------


def _logsource_vulnerability() -> str:
    return """    category: webserver
    product: ""


"""


def _logsource_technique(item: CTIItem) -> str:
    technique_id = item.technique_ids[0] if item.technique_ids else ""
    if technique_id.startswith("T1190"):
        return """    category: webserver
    product: ""


"""
    if technique_id.startswith("T1566"):
        return """    category: process_creation
    product: windows"""
    if technique_id.startswith("T1059"):
        return """    category: process_creation
    product: windows"""
    if technique_id.startswith("T1053"):
        return """    category: process_creation
    product: windows"""
    if technique_id.startswith("T1003"):
        return """    category: process_creation
    product: windows"""
    if technique_id.startswith("T1071"):
        return """    category: network_connection
    product: windows"""
    return _logsource_generic()


def _logsource_generic() -> str:
    return """    category: process_creation
    product: windows"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _map_severity(severity: str) -> str:
    """Map CTI severity string to Sigma level."""
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "informational": "informational",
    }
    return mapping.get(severity.lower().strip(), "medium")


def _build_tags(item: CTIItem) -> list[str]:
    """Build Sigma MITRE ATT&CK tags from a CTIItem."""
    tags: list[str] = []
    for tid in item.technique_ids:
        tags.append(f"attack.{tid.lower()}")
    for tactic in item.tactic_ids:
        tags.append(f"attack.{_tactic_id_to_name(tactic)}")
    if not tags:
        tags.append("attack.initial_access")
    return sorted(set(tags))


def _tactic_id_to_name(tactic_id: str) -> str:
    """Convert a tactic ID (TA0001) to Sigma tag name (initial_access)."""
    mapping = {
        "TA0001": "initial_access",
        "TA0002": "execution",
        "TA0003": "persistence",
        "TA0004": "privilege_escalation",
        "TA0005": "defense_evasion",
        "TA0006": "credential_access",
        "TA0007": "discovery",
        "TA0008": "lateral_movement",
        "TA0009": "collection",
        "TA0010": "exfiltration",
        "TA0011": "command_and_control",
        "TA0040": "impact",
        "TA0042": "resource_development",
        "TA0043": "reconnaissance",
    }
    return mapping.get(tactic_id, "initial_access")


def _sanitize_title(title: str) -> str:
    """Remove characters that break YAML."""
    return title.replace("\n", " ").replace('"', "'").strip()[:200]


def _sanitize_description(description: str) -> str:
    """Collapse whitespace for inline YAML."""
    return re.sub(r"\s+", " ", description).strip()[:500]


def _sanitize_field_value(value: str) -> str:
    """Escape a value for safe inclusion in YAML strings."""
    return value.replace('"', '\\"').replace("\n", " ").strip()
