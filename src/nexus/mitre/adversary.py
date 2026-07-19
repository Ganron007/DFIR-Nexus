"""Enhanced adversary emulation — TF-IDF ranked technique prediction.

Given a set of observed techniques in an investigation, ranks likely
"next techniques" the attacker may use based on MITRE ATT&CK group
profiles. Uses TF-IDF-like scoring: techniques that are common in
matching groups but uncommon overall rank highest.

Extends the existing mitre/catalog.py with prediction capability.
Pure/deterministic — no AI, no network.

Inspired by DFIR-Companion's adversaryEmulation.ts.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

_GROUP_TECHNIQUES: dict[str, dict[str, Any]] = {
    "apt29": {
        "name": "APT29 (Cozy Bear)",
        "aliases": ["Cozy Bear", "The Dukes", "NOBELIUM"],
        "country": "Russia",
        "techniques": [
            "T1566.001", "T1059.001", "T1059.003", "T1053.005",
            "T1078.003", "T1003.003", "T1003.001", "T1071.001",
            "T1071.004", "T1573", "T1105", "T1027", "T1027.002",
            "T1090", "T1090.003", "T1199", "T1195.002",
            "T1553.004", "T1558.003", "T1003.006",
        ],
    },
    "fin7": {
        "name": "FIN7 (Carbon Spider)",
        "aliases": ["Carbon Spider", "Gold Phoenix", "TAQ007"],
        "country": "Russia/Eastern Europe",
        "techniques": [
            "T1566.001", "T1059.001", "T1059.005", "T1059.003",
            "T1055.001", "T1055.012", "T1027", "T1027.001",
            "T1053.005", "T1218.005", "T1218.010",
            "T1071.001", "T1090", "T1005", "T1486",
            "T1078", "T1219",
        ],
    },
    "lazurus": {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "Zinc", "Diamond Sleet"],
        "country": "North Korea",
        "techniques": [
            "T1566.001", "T1059.001", "T1059.003", "T1204.002",
            "T1105", "T1027", "T1055", "T1070.004",
            "T1486", "T1490", "T1005", "T1041",
            "T1071.001", "T1048", "T1218.005",
            "T1195.002", "T1587.001",
        ],
    },
    "apt41": {
        "name": "APT41 (Wicked Panda)",
        "aliases": ["Wicked Panda", "Barium", "Winnti"],
        "country": "China",
        "techniques": [
            "T1190", "T1195.002", "T1059.001", "T1059.003",
            "T1053.005", "T1543.003", "T1547.001",
            "T1003.001", "T1003.002", "T1003.003",
            "T1021.001", "T1021.002", "T1071.001",
            "T1027", "T1070.003", "T1070.004",
            "T1105", "T1486", "T1005",
        ],
    },
    "sandworm": {
        "name": "Sandworm (Voodoo Bear)",
        "aliases": ["Voodoo Bear", "IRIDIUM", "UNIT 74455"],
        "country": "Russia",
        "techniques": [
            "T1190", "T1059.001", "T1059.003", "T1053.005",
            "T1486", "T1490", "T1489", "T1499",
            "T1078.003", "T1078.001", "T1021.001",
            "T1021.002", "T1021.004", "T1070.001",
            "T1070.003", "T1071.001", "T1046",
            "T1110", "T1195.002", "T1199",
        ],
    },
    "equation": {
        "name": "Equation Group",
        "aliases": ["Group 83", "Tangible Threat"],
        "country": "Unknown (suspected US)",
        "techniques": [
            "T1542.003", "T1547.006", "T1014", "T1027",
            "T1027.001", "T1027.002", "T1027.005",
            "T1195.002", "T1553.004", "T1055",
            "T1059", "T1070", "T1070.003",
            "T1090", "T1105", "T1505.001",
        ],
    },
    "cheshire": {
        "name": "Cheshire (TA453)",
        "aliases": ["TA453", "Secret Blizzard"],
        "country": "Iran",
        "techniques": [
            "T1566.001", "T1566.002", "T1059.001", "T1059.005",
            "T1053.005", "T1070.001", "T1005", "T1041",
            "T1048", "T1071.001", "T1105",
        ],
    },
    "twelve": {
        "name": "APT12 (IXESHE/DynCalc)",
        "aliases": ["IXESHE", "DynCalc", "Numbered Panda"],
        "country": "China",
        "techniques": [
            "T1566.001", "T1204.002", "T1059.001",
            "T1059.005", "T1055", "T1071.001",
            "T1105", "T1027", "T1005",
        ],
    },
}


@dataclass
class TechniquePrediction:
    """A predicted technique the attacker may use next."""
    technique_id: str
    score: float
    reason: str
    groups_using: list[str]
    observed_in_case: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "score": round(self.score, 3),
            "reason": self.reason,
            "groups_using": self.groups_using,
            "observed_in_case": self.observed_in_case,
        }


def predict_next_techniques(
    observed_techniques: list[str],
    top_n: int = 10,
    min_score: float = 0.01,
) -> list[TechniquePrediction]:
    """Predict likely next techniques based on observed TTPs.

    Uses TF-IDF-like scoring:
    - TF: frequency of technique across matching groups
    - IDF: inverse frequency across all groups (rare = higher score)

    Techniques already observed in the case are included but flagged.
    """
    if not observed_techniques:
        return []

    observed_set = set(observed_techniques)
    total_groups = len(_GROUP_TECHNIQUES)

    technique_group_count: dict[str, int] = {}
    for group_data in _GROUP_TECHNIQUES.values():
        for tech in group_data["techniques"]:
            technique_group_count[tech] = technique_group_count.get(tech, 0) + 1

    all_techniques = set(technique_group_count.keys())
    idf: dict[str, float] = {}
    for tech, count in technique_group_count.items():
        idf[tech] = math.log(total_groups / count) + 1

    matching_groups: dict[str, float] = {}
    for group_id, group_data in _GROUP_TECHNIQUES.items():
        overlap = set(group_data["techniques"]) & observed_set
        if overlap:
            matching_groups[group_id] = len(overlap) / len(observed_set)

    if not matching_groups:
        return []

    predictions: dict[str, list[str]] = {}
    for group_id in matching_groups:
        group_data = _GROUP_TECHNIQUES[group_id]
        for tech in group_data["techniques"]:
            predictions.setdefault(tech, []).append(group_id)

    scored: list[TechniquePrediction] = []
    for tech, groups in predictions.items():
        tf = len(groups) / len(matching_groups)
        score = tf * idf.get(tech, 1.0)

        if score < min_score:
            continue

        group_names = [
            _GROUP_TECHNIQUES[g]["name"]
            for g in groups
            if g in _GROUP_TECHNIQUES
        ]

        reason = f"Used by {len(groups)} matching group(s): {', '.join(group_names[:3])}"

        scored.append(TechniquePrediction(
            technique_id=tech,
            score=score,
            reason=reason,
            groups_using=groups,
            observed_in_case=tech in observed_set,
        ))

    scored.sort(key=lambda p: -p.score)
    return scored[:top_n]


def match_observed_to_groups(
    observed_techniques: list[str],
    min_overlap: int = 2,
) -> list[dict[str, Any]]:
    """Match observed techniques to threat actor groups.

    Returns groups ranked by overlap count with the observed techniques.
    """
    observed_set = set(observed_techniques)
    matches: list[dict[str, Any]] = []

    for group_id, group_data in _GROUP_TECHNIQUES.items():
        overlap = set(group_data["techniques"]) & observed_set
        if len(overlap) >= min_overlap:
            matches.append({
                "group_id": group_id,
                "name": group_data["name"],
                "aliases": group_data.get("aliases", []),
                "country": group_data.get("country", ""),
                "overlap_count": len(overlap),
                "overlap_techniques": sorted(overlap),
                "total_group_techniques": len(group_data["techniques"]),
                "confidence": len(overlap) / len(group_data["techniques"]),
            })

    matches.sort(key=lambda m: -m["overlap_count"])
    return matches
