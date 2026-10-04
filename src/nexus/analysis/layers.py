"""WO-K8 — per-layer toggles, and what a run says about its own layers.

    NEXUS_LEADS_DISABLE=needles,rules,baselines,anomaly,analytics
    NEXUS_KNOWLEDGE_DISABLE=skills,playbooks,kb,rag,registries

They exist for **ablation**: `eval_run.py --ablate` runs the K1 set once per
toggle and writes the deltas, so the operator can decide whether a layer earns
its place. A toggle that only changed a flag and did not actually remove the
layer would make every ablation number a lie, so `layer_status()` is reported
into the run record and each layer's own call site checks its switch.

A disabled layer is **not** the same as a layer that found nothing, and an absent
layer is not the same as an absent behaviour - both are what WO-K7 is for.
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger(__name__)

ENV_LEADS_DISABLE = "NEXUS_LEADS_DISABLE"
ENV_KNOWLEDGE_DISABLE = "NEXUS_KNOWLEDGE_DISABLE"

#: The lead sources the work order names. Each must be genuinely removable.
LEAD_SOURCES: tuple[str, ...] = ("needles", "rules", "baselines", "anomaly", "analytics")

#: The knowledge layers the work order names.
KNOWLEDGE_LAYERS: tuple[str, ...] = ("skills", "playbooks", "kb", "rag", "registries")

#: Aliases accepted on the switch, so an operator's wording does not silently
#: disable nothing (which would look like a layer that earned its place).
_ALIASES: dict[str, str] = {
    "rule": "rules", "rule_engine": "rules", "rule-engines": "rules",
    "rule_engines": "rules", "hayabusa": "rules", "chainsaw": "rules",
    "needle": "needles", "baseline": "baselines", "triage": "baselines",
    "anomaly_leads": "anomaly", "leads": "anomaly",
    "analytic": "analytics", "analytic_pack": "analytics",
    "behavioural_analytics": "analytics", "behavioral_analytics": "analytics",
    "skill": "skills", "playbook": "playbooks", "knowledgebase": "kb",
    "knowledge_base": "kb", "retrieval": "rag", "registry": "registries",
    "field_registry": "registries",
}


def _parse(raw: str) -> set[str]:
    out: set[str] = set()
    for token in str(raw or "").replace(";", ",").split(","):
        name = token.strip().lower()
        if not name:
            continue
        out.add(_ALIASES.get(name, name))
    return out


def disabled_lead_sources() -> set[str]:
    """Lead sources switched off by `NEXUS_LEADS_DISABLE`."""
    return _parse(os.environ.get(ENV_LEADS_DISABLE, ""))


def disabled_knowledge_layers() -> set[str]:
    """Knowledge layers switched off by `NEXUS_KNOWLEDGE_DISABLE`."""
    return _parse(os.environ.get(ENV_KNOWLEDGE_DISABLE, ""))


def leads_enabled(source: str) -> bool:
    """Whether a lead source may run. An unrecognised name is always enabled.

    Refusing an unknown name would turn a typo into a silently disabled layer;
    `layer_status()` reports the unknown names instead.
    """
    return str(source or "").strip().lower() not in disabled_lead_sources()


def knowledge_enabled(layer: str) -> bool:
    """Whether a knowledge layer may run."""
    return str(layer or "").strip().lower() not in disabled_knowledge_layers()


def unknown_toggles() -> dict[str, list[str]]:
    """Toggle names that match no layer - a typo would disable nothing silently."""
    return {
        "leads": sorted(disabled_lead_sources() - set(LEAD_SOURCES)),
        "knowledge": sorted(disabled_knowledge_layers() - set(KNOWLEDGE_LAYERS)),
    }


def layer_status() -> dict[str, Any]:
    """Per-layer enabled/disabled state, for the run record (WO-K7/K8).

    Reported whether the layer ran or was switched off, so an ablation number can
    be read against what was actually active.
    """
    lead_off = disabled_lead_sources()
    know_off = disabled_knowledge_layers()
    return {
        "leads": {
            name: {
                "enabled": name not in lead_off,
                "reason": "" if name not in lead_off else f"{ENV_LEADS_DISABLE} listed it",
            }
            for name in LEAD_SOURCES
        },
        "knowledge": {
            name: {
                "enabled": name not in know_off,
                "reason": "" if name not in know_off else f"{ENV_KNOWLEDGE_DISABLE} listed it",
            }
            for name in KNOWLEDGE_LAYERS
        },
        "unknown_toggles": unknown_toggles(),
        "env": {ENV_LEADS_DISABLE: os.environ.get(ENV_LEADS_DISABLE, ""),
                ENV_KNOWLEDGE_DISABLE: os.environ.get(ENV_KNOWLEDGE_DISABLE, "")},
    }


def disabled_names() -> list[str]:
    """Every disabled layer name, both groups, for a one-line summary."""
    return sorted(disabled_lead_sources() | disabled_knowledge_layers())
