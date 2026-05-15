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
    name_lower = name.lower().replace(" ", "_")
    return _load_yaml(f"discipline/playbooks/{name_lower}.yaml")


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
