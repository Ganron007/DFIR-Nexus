"""MITRE ATT&CK Navigator v4.5 layer builder (D.0.3)."""

from __future__ import annotations

from typing import Any

LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "4.9.1"
ATTACK_VERSION = "15"


def _normalize_tid(tid: str) -> str:
    return tid.strip().upper()


def build_observed_layer(
    technique_ids: list[str],
    *,
    name: str = "DFIR-Nexus Observed",
    description: str = "Techniques observed in investigation",
    metadata: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Basic observed-technique layer (B.0 compatible, v4.5 metadata)."""
    techniques = []
    for tid in technique_ids:
        tid = _normalize_tid(tid)
        if not tid.startswith("T"):
            continue
        techniques.append(
            {
                "techniqueID": tid,
                "color": "#ff6666",
                "comment": "Observed in investigation",
                "enabled": True,
                "score": 1,
                "metadata": [{"name": "source", "value": "observed"}],
            }
        )
    return _layer_shell(name, description, techniques, metadata=metadata)


def build_coverage_layer(
    technique_scores: dict[str, int],
    *,
    name: str = "DFIR-Nexus Detection Coverage",
    description: str = "Rule count per technique (heatmap)",
    metadata: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Coverage heatmap — score = detection rule count per technique."""
    if not technique_scores:
        return _layer_shell(name, description, [], metadata=metadata)

    max_score = max(technique_scores.values()) or 1
    techniques = []
    for tid, count in sorted(technique_scores.items()):
        tid = _normalize_tid(tid)
        if not tid.startswith("T"):
            continue
        techniques.append(
            {
                "techniqueID": tid,
                "score": count,
                "enabled": True,
                "comment": f"{count} detection rule(s)",
                "metadata": [
                    {"name": "rule_count", "value": str(count)},
                    {"name": "coverage", "value": "detected" if count > 0 else "gap"},
                ],
            }
        )
    return _layer_shell(
        name,
        description,
        techniques,
        metadata=metadata,
        gradient_max=max_score,
        legend=[
            {"label": "no rules", "color": "#ffffff"},
            {"label": "low coverage", "color": "#ffcc66"},
            {"label": "high coverage", "color": "#66cc66"},
        ],
        gradient_colors=["#ffffff", "#ffcc66", "#66cc66"],
    )


def build_gap_layer(
    gap_technique_ids: list[str],
    *,
    name: str = "DFIR-Nexus Coverage Gaps",
    description: str = "Techniques with weak detection coverage",
    metadata: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Highlight techniques with <=2 rules (gaps)."""
    techniques = []
    for tid in gap_technique_ids:
        tid = _normalize_tid(tid)
        if not tid.startswith("T"):
            continue
        techniques.append(
            {
                "techniqueID": tid,
                "color": "#ff9900",
                "comment": "Detection gap (<=2 rules)",
                "enabled": True,
                "score": 0,
                "metadata": [{"name": "gap", "value": "true"}],
            }
        )
    return _layer_shell(
        name,
        description,
        techniques,
        metadata=metadata,
        legend=[{"label": "coverage gap", "color": "#ff9900"}],
    )


def build_actor_layer(
    actor_id: str,
    actor_name: str,
    technique_ids: list[str],
    *,
    description: str = "",
    metadata: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Threat actor technique overlay layer."""
    techniques = []
    for tid in technique_ids:
        tid = _normalize_tid(tid)
        if not tid.startswith("T"):
            continue
        techniques.append(
            {
                "techniqueID": tid,
                "color": "#6699ff",
                "comment": f"Profile: {actor_name}",
                "enabled": True,
                "score": 1,
                "metadata": [{"name": "actor_id", "value": actor_id}],
            }
        )
    meta = list(metadata or [])
    meta.append({"name": "actor_id", "value": actor_id})
    return _layer_shell(
        f"Actor: {actor_name}",
        description or f"MITRE techniques associated with {actor_name}",
        techniques,
        metadata=meta,
        legend=[{"label": "actor technique", "color": "#6699ff"}],
    )


def _layer_shell(
    name: str,
    description: str,
    techniques: list[dict[str, Any]],
    *,
    metadata: list[dict[str, str]] | None = None,
    gradient_max: int = 1,
    legend: list[dict[str, str]] | None = None,
    gradient_colors: list[str] | None = None,
) -> dict[str, Any]:
    colors = gradient_colors or ["#ffffff", "#ff6666"]
    return {
        "name": name,
        "description": description,
        "versions": {
            "attack": ATTACK_VERSION,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "techniques": techniques,
        "gradient": {
            "colors": colors,
            "minValue": 0,
            "maxValue": max(gradient_max, 1),
        },
        "legendItems": legend or [{"label": "observed", "color": "#ff6666"}],
        "metadata": metadata or [],
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
    }
