"""ATT&CK's method, for the seats: what a technique looks like in evidence, and what a detected tool does (IC-5).

The registry (``attack/attack_registry.yaml``, ATT&CK v20.0 from MITRE's pinned STIX) holds, per technique, the
detection strategies ATT&CK publishes - each analytic's description, the log sources and event codes it reads,
the data components they observe, and the elements a defender tunes - and, per software, the techniques ATT&CK
records it using. The seats used to receive a 220-character fragment of an analytic in 9 of 1,032 calls.

Two blocks are rendered from it, and nothing in them is written here:

* ``method_block(techniques)``: for each technique a lead names, its analytics for the case's platform;
* ``software_block(software)``: for a detected tool (a YARA ``Threat_name``, a Defender threat), the techniques
  ATT&CK records it using: the hunt list a detection opens.

A threat name maps to software by its family token in the two naming formats detections use - Elastic's
``Platform.Type.Family`` (MemProcFS YARA) and Microsoft's ``Type:Platform/Family.Variant`` (Defender) - matched
against ATT&CK's own names and aliases. A family ATT&CK does not record (Kekeo) maps to nothing.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

#: Microsoft's malware naming: ``Type:Platform/Family.Variant!Suffix`` (Defender, the Security Center).
_MICROSOFT_THREAT = re.compile(r"\b[A-Z][A-Za-z]*:[A-Za-z0-9]+/([A-Za-z][A-Za-z0-9_-]*)")


def _norm(text: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(text or "").lower())


@lru_cache(maxsize=1)
def _registry() -> dict[str, Any]:
    from nexus.knowledge.loader import get_attack_registry

    return get_attack_registry() or {}


@lru_cache(maxsize=1)
def _techniques() -> dict[str, dict[str, Any]]:
    return {str(t["id"]).upper(): t for t in _registry().get("techniques") or [] if t.get("id")}


@lru_cache(maxsize=1)
def _software_by_name() -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for software in _registry().get("software") or []:
        for name in [software.get("name"), *(software.get("aliases") or [])]:
            key = _norm(name)
            if key and key not in out:
                out[key] = software
    return out


def technique_name(tid: str) -> str:
    """``Parent: Sub`` for a sub-technique, the name otherwise; '' for an id ATT&CK does not hold."""
    tech = _techniques().get(str(tid).upper())
    if not tech:
        return ""
    parent = _techniques().get(str(tech.get("parent") or "").upper())
    return f"{parent['name']}: {tech['name']}" if parent and tech.get("sub") else str(tech.get("name") or "")


def current_technique(tid: str) -> str:
    """The id ATT&CK v20 uses for this technique: a revoked id follows its ``revoked_by``.

    v20 revoked several ids that rule engines still tag (Hayabusa tags "Security log cleared" T1070.001,
    now T1685.005); a revoked entry carries no analytics, so reading it as written gave such a lead no method.
    """
    seen: set[str] = set()
    current = str(tid or "").upper()
    while current and current not in seen:
        seen.add(current)
        tech = _techniques().get(current)
        nxt = str((tech or {}).get("revoked_by") or "").upper() if (tech or {}).get("revoked") else ""
        if not nxt:
            return current
        current = nxt
    return current


def technique_by_name(name: str, *, parent: str = "", platform: str = "Windows") -> str:
    """The id of the active technique with this name (and parent's name), on this platform; '' when none."""
    for tid, tech in sorted(_techniques().items()):
        if tech.get("revoked") or tech.get("deprecated") or _norm(tech.get("name")) != _norm(name):
            continue
        if platform and platform not in (tech.get("platforms") or []):
            continue
        if parent and _norm((_techniques().get(str(tech.get("parent") or "").upper()) or {}).get("name")) != _norm(
                parent):
            continue
        return tid
    return ""


def family_of(threat: str) -> str:
    """The family token of a threat name: Microsoft's ``Type:Platform/Family.Variant`` or a dotted name's last part."""
    text = str(threat or "").strip()
    match = _MICROSOFT_THREAT.search(text)
    if match:
        return match.group(1)
    return text.split(".")[-1] if "." in text else text


def software_for(threat: str) -> dict[str, Any] | None:
    """ATT&CK's software entry for a threat name's family, or None."""
    return _software_by_name().get(_norm(family_of(threat))) if threat else None


def threats_in(text: str) -> list[str]:
    """The Microsoft-format threat names a text carries (a Defender detection rendered by an engine)."""
    return list(dict.fromkeys(m.group(0) for m in _MICROSOFT_THREAT.finditer(str(text or ""))))


def case_platforms(case_dir: Path | str | None) -> list[str]:
    """ATT&CK platform names for the case: the intake's declared OS, else Windows when the index holds Windows
    event logs (ECS ``winlog``); [] when neither says, so nothing is filtered on a guess."""
    if case_dir is None:
        return []
    case_dir = Path(case_dir)
    try:
        import yaml

        meta = yaml.safe_load((case_dir / "CASE.yaml").read_text(encoding="utf-8")) or {}
        intake = meta.get("intake") if isinstance(meta, dict) else None
        declared = str((intake or {}).get("sift_os") or "").strip().lower() if isinstance(intake, dict) else ""
    except Exception:  # noqa: BLE001 - an unreadable intake declares nothing
        declared = ""
    for prefix, platform in (("win", "Windows"), ("linux", "Linux"), ("mac", "macOS")):
        if declared.startswith(prefix):
            return [platform]
    try:
        from nexus.langgraph.es_native import es_search

        result = es_search(case_dir.name, {"exists": {"field": "ecs.winlog.channel"}}, size=1)
        if int(result.get("total") or 0) > 0:
            return ["Windows"]
    except Exception:  # noqa: BLE001 - no index: no platform to state
        pass
    return []


@lru_cache(maxsize=32)
def case_platforms_cached(case_dir: str) -> tuple[str, ...]:
    """``case_platforms`` once per case and process: every order and seat of a run asks it."""
    return tuple(case_platforms(case_dir))


def method_block(techniques: list[str], *, platforms: list[str] | None = None, max_techniques: int = 8,
                 max_analytics: int = 2) -> str:
    """ATT&CK's analytics for each technique, on the case's platforms."""
    lines: list[str] = []
    shown_ids: set[str] = set()
    for named in list(dict.fromkeys(str(t).upper() for t in techniques if t))[:max_techniques]:
        tid = current_technique(named)
        tech = _techniques().get(tid)
        if not tech or tid in shown_ids:
            continue
        shown_ids.add(tid)
        was = f" (tagged {named}, revoked in ATT&CK v20)" if tid != named else ""
        lines.append(f"- {tid} {technique_name(tid)}{was} ({', '.join(tech.get('tactics') or [])})")
        shown = 0
        for strategy in tech.get("detection") or []:
            for analytic in strategy.get("analytics") or []:
                if platforms and not set(platforms) & set(analytic.get("platforms") or []):
                    continue
                if shown >= max_analytics:
                    break
                shown += 1
                where = "; ".join(
                    f"{ref.get('name')} {ref.get('channel')}".strip()
                    + (f" ({ref.get('data_component')})" if ref.get("data_component") else "")
                    for ref in analytic.get("log_source_refs") or [])
                tune = "; ".join(f"{t.get('field')}: {t.get('description')}" for t in analytic.get("tunables") or [])
                lines.append(f"    {strategy.get('id')} {analytic.get('name')}: {analytic.get('description')}")
                if where:
                    lines.append(f"      where: {where}")
                if tune:
                    lines.append(f"      what makes an instance suspicious: {tune}")
        if not shown:
            lines.append("    (no ATT&CK analytic for this platform)")
    if not lines:
        return ""
    return ("ATT&CK v20 METHOD for the techniques these leads name (what ATT&CK says to look for and where; "
            "the case's rows decide):\n" + "\n".join(lines) + "\n")


def software_block(software_ids: list[str]) -> str:
    """The techniques ATT&CK records each detected tool using: the hunt list a detection opens."""
    by_id = {str(s.get("id")): s for s in _registry().get("software") or []}
    lines = []
    for sid in dict.fromkeys(str(s) for s in software_ids if s):
        software = by_id.get(sid)
        if not software:
            continue
        named = [f"{t} {technique_name(t)}" for t in software.get("techniques") or [] if technique_name(t)]
        lines.append(f"- {sid} {software.get('name')} ({software.get('type')}), {len(named)} technique(s): "
                     + "; ".join(named))
    if not lines:
        return ""
    return ("ATT&CK SOFTWARE detected in this case: the techniques ATT&CK records it using. Each is a hypothesis "
            "to test in the evidence (persistence, credential access, lateral movement, C2), not a finding:\n"
            + "\n".join(lines) + "\n")
