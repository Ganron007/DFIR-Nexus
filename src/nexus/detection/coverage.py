"""Detection coverage analysis — per-tactic percentages and gap identification.

Maps indexed Sigma rules to MITRE ATT&CK tactics/techniques and computes:
- Per-tactic coverage percentages
- Top covered techniques per tactic
- Gap identification (techniques with zero detections)
- Weak spots (tactics with lowest coverage)

Inspired by Security-Detections-MCP's coverage analysis tools.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

TACTIC_ORDER = [
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
]

TACTIC_NAMES = {
    "TA0043": "Reconnaissance",
    "TA0042": "Resource Development",
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0011": "Command and Control",
    "TA0010": "Exfiltration",
    "TA0040": "Impact",
}

TECHNIQUE_TO_TACTIC: dict[str, list[str]] = {
    "T1059": ["TA0002"],
    "T1059.001": ["TA0002"],
    "T1059.003": ["TA0002"],
    "T1059.005": ["TA0002"],
    "T1053": ["TA0002", "TA0003"],
    "T1053.005": ["TA0002", "TA0003"],
    "T1547": ["TA0003"],
    "T1547.001": ["TA0003"],
    "T1078": ["TA0001", "TA0003", "TA0004"],
    "T1078.001": ["TA0001", "TA0003"],
    "T1078.003": ["TA0001", "TA0003"],
    "T1003": ["TA0006"],
    "T1003.001": ["TA0006"],
    "T1003.002": ["TA0006"],
    "T1003.003": ["TA0006"],
    "T1021": ["TA0008"],
    "T1021.001": ["TA0008"],
    "T1021.002": ["TA0008"],
    "T1021.004": ["TA0008"],
    "T1071": ["TA0011"],
    "T1071.001": ["TA0011"],
    "T1071.004": ["TA0011"],
    "T1055": ["TA0004", "TA0005"],
    "T1055.001": ["TA0004", "TA0005"],
    "T1055.012": ["TA0004", "TA0005"],
    "T1027": ["TA0005"],
    "T1027.001": ["TA0005"],
    "T1070": ["TA0005"],
    "T1070.001": ["TA0005"],
    "T1070.003": ["TA0005"],
    "T1070.004": ["TA0005"],
    "T1048": ["TA0010"],
    "T1041": ["TA0010"],
    "T1486": ["TA0040"],
    "T1490": ["TA0040"],
    "T1489": ["TA0040"],
    "T1046": ["TA0007"],
    "T1083": ["TA0007"],
    "T1057": ["TA0007"],
    "T1082": ["TA0007"],
    "T1007": ["TA0007"],
    "T1012": ["TA0007"],
    "T1016": ["TA0007"],
    "T1033": ["TA0007"],
    "T1005": ["TA0009"],
    "T1001": ["TA0009"],
    "T1030": ["TA0009"],
    "T1049": ["TA0007"],
    "T1018": ["TA0007"],
    "T1518": ["TA0007"],
    "T1518.001": ["TA0007"],
    "T1105": ["TA0011"],
    "T1106": ["TA0002"],
    "T1546": ["TA0003", "TA0004"],
    "T1546.011": ["TA0003", "TA0004"],
    "T1546.012": ["TA0003", "TA0004"],
    "T1548": ["TA0004"],
    "T1548.002": ["TA0004"],
    "T1134": ["TA0004", "TA0005"],
    "T1134.001": ["TA0004", "TA0005"],
    "T1056": ["TA0006"],
    "T1056.001": ["TA0006"],
    "T1056.004": ["TA0006"],
    "T1558": ["TA0006"],
    "T1003.004": ["TA0006"],
    "T1528": ["TA0006"],
    "T1539": ["TA0006"],
    "T1552": ["TA0006"],
    "T1552.001": ["TA0006"],
    "T1071.002": ["TA0011"],
    "T1090": ["TA0011"],
    "T1090.001": ["TA0011"],
    "T1090.003": ["TA0011"],
    "T1219": ["TA0011"],
    "T1199": ["TA0001", "TA0008"],
    "T1195": ["TA0001"],
    "T1195.002": ["TA0001"],
    "T1190": ["TA0001"],
    "T1133": ["TA0001", "TA0003"],
    "T1566": ["TA0001"],
    "T1566.001": ["TA0001"],
    "T1566.002": ["TA0001"],
    "T1204": ["TA0002"],
    "T1204.001": ["TA0002"],
    "T1204.002": ["TA0002"],
    "T1059.004": ["TA0002"],
    "T1059.006": ["TA0002"],
    "T1218": ["TA0005"],
    "T1218.005": ["TA0005"],
    "T1218.010": ["TA0005"],
    "T1218.011": ["TA0005"],
    "T1140": ["TA0005"],
    "T1036": ["TA0005"],
    "T1036.005": ["TA0005"],
    "T1027.002": ["TA0005"],
    "T1027.004": ["TA0005"],
    "T1027.005": ["TA0005"],
    "T1497": ["TA0005"],
    "T1497.001": ["TA0005"],
    "T1087": ["TA0007"],
    "T1087.001": ["TA0007"],
    "T1069": ["TA0007"],
    "T1069.001": ["TA0007"],
    "T1614": ["TA0007"],
    "T1614.001": ["TA0007"],
    "T1622": ["TA0007"],
}


@dataclass
class TacticCoverage:
    """Coverage data for a single tactic."""
    tactic_id: str
    tactic_name: str
    total_techniques: int = 0
    covered_techniques: int = 0
    coverage_percent: float = 0.0
    covered: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    rule_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "total_techniques": self.total_techniques,
            "covered_techniques": self.covered_techniques,
            "coverage_percent": round(self.coverage_percent, 1),
            "covered": self.covered,
            "gaps": self.gaps[:20],
            "top_techniques": sorted(
                self.rule_counts.items(), key=lambda x: -x[1]
            )[:10],
        }


@dataclass
class CoverageReport:
    """Full coverage analysis report."""
    total_rules: int = 0
    tactics: list[TacticCoverage] = field(default_factory=list)
    overall_coverage: float = 0.0
    weakest_tactics: list[str] = field(default_factory=list)
    strongest_tactics: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rules": self.total_rules,
            "overall_coverage_percent": round(self.overall_coverage, 1),
            "weakest_tactics": self.weakest_tactics[:5],
            "strongest_tactics": self.strongest_tactics[:5],
            "tactics": [t.to_dict() for t in self.tactics],
        }


def analyze_coverage(index_path: Path) -> CoverageReport:
    """Analyze detection coverage from an indexed rule directory.

    Walks the Sigma index produced by DetectionIndexer and maps
    rules to tactics/techniques.
    """
    report = CoverageReport()

    tactic_data: dict[str, dict[str, int]] = {}
    for tactic_id in TACTIC_ORDER:
        tactic_data[tactic_id] = {}

    if not index_path.exists():
        return report

    for json_file in index_path.rglob("*.json"):
        if json_file.name == "manifest.json":
            continue
        try:
            import json as json_mod
            rule = json_mod.loads(json_file.read_text(encoding="utf-8"))
        except Exception:
            continue

        report.total_rules += 1
        tactics = rule.get("tactic_ids", [])
        techniques = rule.get("technique_ids", [])

        for tech_id in techniques:
            mapped_tactics = TECHNIQUE_TO_TACTIC.get(tech_id, [])
            for tactic_id in mapped_tactics:
                if tactic_id in tactic_data:
                    tactic_data[tactic_id][tech_id] = tactic_data[tactic_id].get(tech_id, 0) + 1

        for tactic_id in tactics:
            if tactic_id in tactic_data:
                for tech_id in techniques:
                    tactic_data[tactic_id][tech_id] = tactic_data[tactic_id].get(tech_id, 0) + 1

    all_techniques = set()
    for tech_id in TECHNIQUE_TO_TACTIC:
        all_techniques.add(tech_id)

    total_all = 0
    covered_all = 0

    for tactic_id in TACTIC_ORDER:
        tc = TacticCoverage(
            tactic_id=tactic_id,
            tactic_name=TACTIC_NAMES.get(tactic_id, tactic_id),
        )

        tactic_techniques = set()
        for tech_id, tactics in TECHNIQUE_TO_TACTIC.items():
            if tactic_id in tactics:
                tactic_techniques.add(tech_id)

        tc.total_techniques = len(tactic_techniques)
        tc.covered = sorted(tactic_data.get(tactic_id, {}).keys())
        tc.covered_techniques = len(tc.covered)
        tc.rule_counts = tactic_data.get(tactic_id, {})
        tc.gaps = sorted(tactic_techniques - set(tc.covered))

        if tc.total_techniques > 0:
            tc.coverage_percent = (tc.covered_techniques / tc.total_techniques) * 100

        total_all += tc.total_techniques
        covered_all += tc.covered_techniques
        report.tactics.append(tc)

    if total_all > 0:
        report.overall_coverage = (covered_all / total_all) * 100

    sorted_by_coverage = sorted(report.tactics, key=lambda t: t.coverage_percent)
    report.weakest_tactics = [
        f"{t.tactic_name} ({t.coverage_percent:.0f}%)"
        for t in sorted_by_coverage[:5]
        if t.total_techniques > 0
    ]
    report.strongest_tactics = [
        f"{t.tactic_name} ({t.coverage_percent:.0f}%)"
        for t in sorted_by_coverage[-5:]
        if t.total_techniques > 0
    ]
    report.strongest_tactics.reverse()

    return report


def generate_coverage_summary(report: CoverageReport) -> str:
    """Generate a human-readable coverage summary."""
    lines = [
        "=== Detection Coverage Analysis ===",
        f"Total indexed rules: {report.total_rules}",
        f"Overall coverage: {report.overall_coverage:.1f}%",
        "",
        "Per-tactic coverage:",
    ]

    for t in report.tactics:
        bar_len = int(t.coverage_percent / 5)
        bar = "#" * bar_len + "-" * (20 - bar_len)
        lines.append(
            f"  [{bar}] {t.tactic_name:25s} {t.coverage_percent:5.1f}% "
            f"({t.covered_techniques}/{t.total_techniques} techniques)"
        )

    if report.weakest_tactics:
        lines.append("")
        lines.append("Weakest areas:")
        for w in report.weakest_tactics:
            lines.append(f"  - {w}")

    if report.strongest_tactics:
        lines.append("")
        lines.append("Strongest areas:")
        for s in report.strongest_tactics:
            lines.append(f"  - {s}")

    return "\n".join(lines)


class MITRECoverage:
    """Coverage analysis from a DetectionSearcher instance.

    Provides per-technique coverage lookup, coverage matrix, and gap analysis.
    """

    def __init__(self, searcher: Any) -> None:
        self._searcher = searcher

    def coverage_for_technique(self, technique_id: str) -> dict[str, Any]:
        """Get coverage data for a single technique."""
        rules = self._searcher.search(technique_id=technique_id)
        by_severity: dict[str, int] = {}
        for r in rules:
            sev = r.severity.value if hasattr(r.severity, "value") else str(r.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1
        return {
            "technique_id": technique_id,
            "total_rules": len(rules),
            "by_severity": by_severity,
        }

    def coverage_matrix(self, technique_ids: list[str]) -> dict[str, dict[str, int]]:
        """Get coverage counts per technique per severity."""
        matrix: dict[str, dict[str, int]] = {}
        for tech_id in technique_ids:
            rules = self._searcher.search(technique_id=tech_id)
            sev_counts: dict[str, int] = {}
            for r in rules:
                sev = r.severity.value if hasattr(r.severity, "value") else str(r.severity)
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            matrix[tech_id] = sev_counts
        return matrix

    def gap_analysis(self, technique_ids: list[str]) -> list[dict[str, Any]]:
        """Identify techniques with zero detection coverage."""
        gaps = []
        for tech_id in technique_ids:
            rules = self._searcher.search(technique_id=tech_id)
            if len(rules) == 0:
                gaps.append({
                    "technique_id": tech_id,
                    "status": "UNCOVERED",
                    "total_rules": 0,
                })
        return gaps
