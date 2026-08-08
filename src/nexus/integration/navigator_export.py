"""ATT&CK Navigator layer export.

Generates ATT&CK Navigator v4.5 JSON layers from technique IDs mapped
to severity colors. Pure function — no side effects, no I/O.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#e22121",
    "high": "#f5864a",
    "medium": "#f5c34a",
    "low": "#f5e64a",
    "informational": "#4af5a8",
}


def _hex_for_severity(severity: str) -> str:
    """Return hex color for a severity level."""
    return _SEVERITY_COLORS.get(severity.lower(), "#838383")


def export_navigator_layer(technique_map: dict[str, str]) -> dict[str, Any]:
    """Generate an ATT&CK Navigator v4.5 JSON layer.

    Args:
        technique_map: Mapping of MITRE ATT&CK technique IDs to severity
            strings (e.g. ``{"T1059.001": "critical", "T1078": "high"}``).
            Severity values are used to color-code cells in the Navigator.

    Returns:
        A dict representing a Navigator v4.5 JSON layer that can be
        imported directly into the ATT&CK Navigator tool.
    """
    now = datetime.now(UTC).strftime("%Y-%m-%d")

    techniques: list[dict[str, Any]] = []
    for tech_id, severity in sorted(technique_map.items()):
        color = _hex_for_severity(severity)
        techniques.append({
            "techniqueID": tech_id,
            "tactic": "",
            "color": color,
            "comment": f"DFIR-Nexus: {severity}",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubTechniques": "." in tech_id,
        })

    return {
        "versions": {
            "navigator": "4.5",
            "layer": "4.5",
            "attack": "15",
        },
        "name": f"DFIR-Nexus Export ({now})",
        "domain": "enterprise-attack",
        "description": f"Technique layer exported from DFIR-Nexus on {now}.",
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "Network"],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [
                "#f5e64a",
                "#f5864a",
                "#e22121",
            ],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": "Critical", "color": _SEVERITY_COLORS["critical"]},
            {"label": "High", "color": _SEVERITY_COLORS["high"]},
            {"label": "Medium", "color": _SEVERITY_COLORS["medium"]},
            {"label": "Low", "color": _SEVERITY_COLORS["low"]},
            {"label": "Informational", "color": _SEVERITY_COLORS["informational"]},
        ],
        "metadata": [
            {"name": "tool", "value": "DFIR-Nexus"},
            {"name": "export_date", "value": now},
        ],
        "links": [],
    }
