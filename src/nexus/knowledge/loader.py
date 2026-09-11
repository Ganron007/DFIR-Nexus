"""YAML-driven forensic knowledge base loader.

Provides lazy-loaded access to artifact definitions, tool knowledge,
discipline rules, playbooks, and investigation frameworks stored as
YAML files in the data/knowledge/ directory.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_cache: dict[str, Any] = {}
_data_dir: Path | None = None


def _find_data_dir() -> Path:
    global _data_dir
    if _data_dir is not None:
        return _data_dir

    env_dir = os.environ.get("NEXUS_FK_DATA_DIR")
    if env_dir:
        _data_dir = Path(env_dir)
        if _data_dir.is_dir():
            return _data_dir

    relative = Path(__file__).resolve().parent.parent / "data" / "knowledge"
    if relative.is_dir():
        _data_dir = relative
        return _data_dir

    relative2 = Path(__file__).resolve().parent.parent.parent / "data" / "knowledge"
    if relative2.is_dir():
        _data_dir = relative2
        return _data_dir

    raise FileNotFoundError(
        "Forensic knowledge data directory not found. "
        "Set NEXUS_FK_DATA_DIR or ensure data/knowledge/ is present."
    )


def _load_yaml(rel_path: str) -> Any:
    data_dir = _find_data_dir()
    cache_key = rel_path
    if cache_key in _cache:
        return _cache[cache_key]
    path = data_dir / rel_path
    if not path.exists():
        _cache[cache_key] = None
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        _cache[cache_key] = data
        return data
    except Exception as e:
        logger.warning("Failed to load %s: %s", rel_path, e)
        _cache[cache_key] = None
        return None


def _load_all_in_dir(rel_dir: str) -> list[dict]:
    data_dir = _find_data_dir()
    cache_key = f"__dir__/{rel_dir}"
    if cache_key in _cache:
        return _cache[cache_key]
    dir_path = data_dir / rel_dir
    if not dir_path.is_dir():
        _cache[cache_key] = []
        return []
    results: list[dict] = []
    for yaml_file in sorted(dir_path.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                results.append(data)
            elif isinstance(data, list):
                results.extend(data)
        except Exception as e:
            logger.warning("Failed to load %s: %s", yaml_file, e)
    _cache[cache_key] = results
    return results


# ── Artifacts ───────────────────────────────────────────────────────────

def get_artifact(name: str, platform: str = "windows") -> dict | None:
    """Get artifact definition by name (case-insensitive)."""
    name_lower = name.lower().replace(" ", "_")
    candidates = [
        f"artifacts/{platform}/{name_lower}.yaml",
        f"artifacts/windows/{name_lower}.yaml",
    ]
    for path in candidates:
        data = _load_yaml(path)
        if data and isinstance(data, dict):
            return data
    return None


def list_artifacts(platform: str | None = None) -> list[dict]:
    """List all artifact definitions, optionally filtered by platform."""
    results = []
    platforms = [platform] if platform else ["windows", "linux"]
    for p in platforms:
        results.extend(_load_all_in_dir(f"artifacts/{p}"))
    return results


def get_artifacts_for_tool(tool_name: str) -> list[dict]:
    """Find artifacts that list this tool as related_tools."""
    tool_lower = tool_name.lower()
    artifacts = list_artifacts()
    related = []
    for art in artifacts:
        related_tools = art.get("related_tools", [])
        if any(t.lower() == tool_lower for t in related_tools):
            related.append(art)
    return related


# ── Tools ───────────────────────────────────────────────────────────────

def _scan_all_tools() -> list[dict]:
    """Scan all tool category subdirectories."""
    data_dir = _find_data_dir()
    tools_dir = data_dir / "tools"
    if not tools_dir.is_dir():
        return []
    cache_key = "__dir__/tools/all"
    if cache_key in _cache:
        return _cache[cache_key]
    results = []
    for cat_dir in sorted(tools_dir.iterdir()):
        if cat_dir.is_dir():
            for yaml_file in sorted(cat_dir.glob("*.yaml")):
                try:
                    with open(yaml_file, encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        data.setdefault("category", cat_dir.name)
                        results.append(data)
                except Exception as e:
                    logger.warning("Failed to load tool %s: %s", yaml_file, e)
    _cache[cache_key] = results
    return results


def get_tool(name: str) -> dict | None:
    """Get tool definition by name (case-insensitive)."""
    name_lower = name.lower()
    for tool in _scan_all_tools():
        if tool.get("name", "").lower() == name_lower:
            return tool
    return None


def list_tools(category: str | None = None, platform: str | None = None) -> list[dict]:
    """List all tool definitions, optionally filtered."""
    tools = _scan_all_tools()
    if category:
        tools = [t for t in tools if t.get("category", "").lower() == category.lower()]
    if platform:
        tools = [t for t in tools if platform in t.get("platform", [])]
    return tools


# ── Discipline ──────────────────────────────────────────────────────────

def get_rules() -> list[dict]:
    data = _load_yaml("discipline/rules.yaml")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("rules", [])
    return []


def get_playbook(name: str) -> dict | None:
    name_lower = name.strip().lower().replace(" ", "_")
    return _load_yaml(f"discipline/playbooks/{name_lower}.yaml")


def get_attack_needles() -> list[dict]:
    """MITRE ATT&CK needle packs (data-driven search vocabulary).

    File: ``needles/attack_needles.yaml`` — technique id -> needles + caveats.
    """
    data = _load_yaml("needles/attack_needles.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_sigma_needles() -> list[dict]:
    """SigmaHQ-derived needle packs.

    File: ``needles/sigma_needles.yaml`` — family -> detection-field needles
    mined from well-known Sigma rules, with FD-004 caveats.
    """
    data = _load_yaml("needles/sigma_needles.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_lolbas_needles() -> list[dict]:
    """LOLBAS (Living Off The Land Binaries) needle packs.

    File: ``needles/lolbas.yaml`` — binary name -> abuse patterns,
    expected parents, network indicators, and FD-004 caveats.
    """
    data = _load_yaml("needles/lolbas.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_atomic_red_team() -> list[dict]:
    """Atomic Red Team test procedures per ATT&CK technique.

    File: ``needles/atomic_red_team.yaml`` — technique ID -> test
    procedures (command, expected artifacts, cleanup).
    """
    data = _load_yaml("needles/atomic_red_team.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_car_analytics() -> list[dict]:
    """MITRE CAR analytics — detection logic, data model fields,
    pseudocode, and ATT&CK mapping for each technique.

    File: ``needles/car_analytics.yaml`` — analytic ID -> data model
    fields, pseudocode, ATT&CK mapping.
    """
    data = _load_yaml("needles/car_analytics.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_ossem_events() -> list[dict]:
    """OSSEM event data models — field names, data types, common values,
    and detection guidance per event type.

    File: ``needles/ossem_events.yaml`` — event type -> field names,
    data types, common values, detection guidance.
    """
    data = _load_yaml("needles/ossem_events.yaml")
    if isinstance(data, dict):
        events = data.get("events")
        if isinstance(events, dict):
            return [{"name": k, **v} for k, v in events.items() if isinstance(v, dict)]
    return []


def get_evtx_attack_samples() -> list[dict]:
    """EVTX-ATTACK-SAMPLES — real event log entries per ATT&CK technique.

    File: ``needles/evtx_attack_samples.yaml`` — technique ID -> event
    IDs, fields, values, detection guidance.
    """
    data = _load_yaml("needles/evtx_attack_samples.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_incident_reports() -> list[dict]:
    """Real-world incident reports — IOCs and TTPs from Mandiant,
    CrowdStrike, Unit42, TheDFIRReport, and other IR sources.

    File: ``needles/incident_reports.yaml`` — group/tool -> IOCs,
    TTPs, ATT&CK mapping.
    """
    data = _load_yaml("needles/incident_reports.yaml")
    if isinstance(data, dict):
        packs = data.get("packs")
        if isinstance(packs, list):
            return [p for p in packs if isinstance(p, dict)]
    return []


def get_threat_feeds() -> list[dict]:
    """Threat intel feeds — known-bad IOCs from MalwareBazaar, URLhaus,
    AbuseIPDB, ThreatFox, and other feeds.

    File: ``needles/threat_feeds.yaml`` — feed name -> IOC types,
    update frequency, needles.
    """
    data = _load_yaml("needles/threat_feeds.yaml")
    if isinstance(data, dict):
        feeds = data.get("feeds")
        if isinstance(feeds, list):
            return [f for f in feeds if isinstance(f, dict)]
    return []


def get_vendor_guides() -> list[dict]:
    """Vendor detection guides — detection logic and field names from
    Microsoft, CrowdStrike, SentinelOne, Palo Alto, FireEye, Elastic,
    Splunk.

    File: ``needles/vendor_guides.yaml`` — vendor -> detection logic,
    field names, needles.
    """
    data = _load_yaml("needles/vendor_guides.yaml")
    if isinstance(data, dict):
        vendors = data.get("vendors")
        if isinstance(vendors, list):
            return [v for v in vendors if isinstance(v, dict)]
    return []


def get_sysmon_configs() -> list[dict]:
    """Sysmon configurations — recommended event coverage and field names
    from SwiftOnSecurity, Olaf Hartong, and other community configs.

    File: ``needles/sysmon_configs.yaml`` — config name -> event IDs,
    field names, detection hints.
    """
    data = _load_yaml("needles/sysmon_configs.yaml")
    if isinstance(data, dict):
        configs = data.get("configs")
        if isinstance(configs, list):
            return [c for c in configs if isinstance(c, dict)]
    return []


def get_yara_rules() -> list[dict]:
    """YARA rules — rule names, strings, and conditions for malware
    family detection.

    File: ``needles/yara_rules.yaml`` — family -> rules with strings,
    conditions, descriptions.
    """
    data = _load_yaml("needles/yara_rules.yaml")
    if isinstance(data, dict):
        rules = data.get("rules")
        if isinstance(rules, list):
            return [r for r in rules if isinstance(r, dict)]
    return []


def get_cisa_kev() -> list[dict]:
    """CISA KEV — actively exploited CVEs with exploit detection needles
    and ATT&CK mapping.

    File: ``needles/cisa_kev.yaml`` — CVE -> exploit detection needles,
    ATT&CK mapping, caveats.
    """
    data = _load_yaml("needles/cisa_kev.yaml")
    if isinstance(data, dict):
        cves = data.get("cves")
        if isinstance(cves, list):
            return [c for c in cves if isinstance(c, dict)]
    return []


def get_misp_opencti() -> list[dict]:
    """MISP / OpenCTI structured threat intel — IOCs, TTPs, campaigns,
    and threat actors from curated feeds.

    File: ``needles/misp_opencti.yaml`` — platform -> feed types,
    needles, IOC types.
    """
    data = _load_yaml("needles/misp_opencti.yaml")
    if isinstance(data, dict):
        platforms = data.get("platforms")
        if isinstance(platforms, list):
            return [p for p in platforms if isinstance(p, dict)]
    return []


def list_playbooks() -> list[dict]:
    return _load_all_in_dir("discipline/playbooks")


def list_playbook_slugs() -> list[str]:
    data_dir = _find_data_dir()
    pb_dir = data_dir / "discipline" / "playbooks"
    if not pb_dir.is_dir():
        return []
    return sorted(p.stem for p in pb_dir.glob("*.yaml"))


def get_confidence_definitions() -> dict:
    data = _load_yaml("discipline/confidence.yaml")
    if isinstance(data, dict):
        levels = data.get("levels") or data.get("confidence", data)
        if isinstance(levels, dict):
            return levels
    return {}


def get_anti_patterns() -> list[dict]:
    data = _load_yaml("discipline/anti_patterns.yaml")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("anti_patterns", [])
    return []


def get_evidence_standards() -> dict:
    data = _load_yaml("discipline/evidence_standards.yaml")
    if isinstance(data, dict):
        return data.get("standards") or data.get("evidence_standards", data)
    return {}


def get_evidence_template() -> dict | None:
    data = _load_yaml("discipline/evidence_template.yaml")
    if isinstance(data, dict):
        return data.get("template", data)
    return None


def get_checkpoint(action_type: str) -> dict | None:
    data = _load_yaml("discipline/checkpoints.yaml")
    if isinstance(data, dict):
        checkpoints = data.get("checkpoints", [])
        for cp in checkpoints:
            if cp.get("action_type", "").lower() == action_type.lower():
                return cp
    return None


def list_checkpoints() -> list[dict]:
    data = _load_yaml("discipline/checkpoints.yaml")
    if isinstance(data, dict):
        return data.get("checkpoints", [])
    return []


def get_corroboration(finding_type: str) -> list[dict] | None:
    data = _load_yaml("discipline/guidance/corroboration.yaml")
    if isinstance(data, dict):
        wrapper = data.get("corroboration", data)
        if isinstance(wrapper, dict):
            return wrapper.get(finding_type)
    return None


def get_false_positive_context(tool: str, finding_type: str) -> dict | None:
    data = _load_yaml("discipline/guidance/false_positives.yaml")
    if isinstance(data, dict):
        fp = data.get("false_positives", data)
        if isinstance(fp, dict):
            tool_data = fp.get(tool)
            if isinstance(tool_data, dict):
                return tool_data.get(finding_type)
    return None


def get_tool_interpretation(tool_name: str) -> dict | None:
    data = _load_yaml("discipline/guidance/tool_interpretation.yaml")
    if isinstance(data, dict):
        tools = data.get("tools", data)
        if isinstance(tools, dict):
            return tools.get(tool_name)
    return None


def get_collection_checklist(artifact_type: str) -> dict | None:
    name_lower = artifact_type.lower().replace(" ", "_")
    return _load_yaml(f"discipline/checklists/{name_lower}.yaml")


def list_collection_checklists() -> list[str]:
    data_dir = _find_data_dir()
    cl_dir = data_dir / "discipline" / "checklists"
    if not cl_dir.is_dir():
        return []
    return sorted(p.stem for p in cl_dir.glob("*.yaml"))


def get_investigation_framework() -> dict | None:
    return _load_yaml("discipline/framework/investigation_framework.yaml")


def clear_cache() -> None:
    _cache.clear()
    global _data_dir
    _data_dir = None
