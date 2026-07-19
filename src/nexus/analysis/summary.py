"""LLM-powered executive summary generator.

Generates an executive summary from a set of artifacts. Two modes:
1. Rule-based (no LLM): builds a summary from statistics alone.
2. LLM-powered: uses the configured LLM to generate a narrative.

The LLM mode is preferred when an API key is configured. Otherwise the
rule-based mode is used.
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import UTC, datetime

from nexus.analysis.schemas import (
    AnalysisResult,
    ExecutiveSummary,
)
from nexus.ingest.schemas import Artifact, Severity
from nexus.llm import ChatMessage, LLMRouter

log = logging.getLogger(__name__)


class SummaryGenerator:
    """Generate an executive summary from a set of artifacts.

    Usage:
        gen = SummaryGenerator(llm_router=router)  # LLM mode
        gen = SummaryGenerator()                   # rule-based mode
        summary = gen.generate(artifacts, case_id="case-001")
    """

    def __init__(self, llm_router: LLMRouter | None = None) -> None:
        self.llm_router = llm_router

    def generate(
        self,
        artifacts: list[Artifact],
        case_id: str = "case",
        force_llm: bool = False,
    ) -> ExecutiveSummary:
        """Generate an executive summary for a set of artifacts."""
        # Always start with rule-based for facts
        base = self._rule_based(artifacts, case_id)
        if self.llm_router is not None and (force_llm or len(artifacts) > 0):
            try:
                return self._llm_enhance(artifacts, base)
            except Exception as e:  # noqa: BLE001
                log.warning("LLM summary failed: %s — falling back to rule-based", e)
                return base
        return base

    def _rule_based(
        self, artifacts: list[Artifact], case_id: str
    ) -> ExecutiveSummary:
        """Build a summary from artifact statistics alone (no LLM)."""
        # Aggregate facts
        techniques: set[str] = set()
        hosts: set[str] = set()
        users: set[str] = set()
        iocs: set[str] = set()
        type_counts: Counter[str] = Counter()
        severity_counts: Counter[str] = Counter()
        for a in artifacts:
            techniques.update(a.technique_ids)
            if a.host:
                hosts.add(a.host)
            if a.user:
                users.add(a.user)
            iocs.update(a.iocs)
            type_counts[a.artifact_type.value] += 1
            severity_counts[a.severity.value] += 1

        # Time range
        if artifacts:
            timestamps = [a.timestamp for a in artifacts]
            _ = min(timestamps)
            _ = max(timestamps)

        # Overview
        overview_parts = [
            f"Investigation of case {case_id} analyzed {len(artifacts)} forensic artifacts.",
        ]
        if techniques:
            overview_parts.append(
                f"Observed {len(techniques)} MITRE ATT&CK techniques across {len(hosts)} host(s)."
            )
        if severity_counts.get("critical", 0) > 0:
            overview_parts.append(
                f"{severity_counts['critical']} CRITICAL severity event(s) detected."
            )
        if severity_counts.get("high", 0) > 0:
            overview_parts.append(
                f"{severity_counts['high']} HIGH severity event(s) detected."
            )

        # Key findings (top 5 by severity)
        findings: list[str] = []
        critical_high = [a for a in artifacts if a.severity in (Severity.CRITICAL, Severity.HIGH)]
        # Dedupe by (technique_ids, host, source_ip) for variety
        seen_keys: set[tuple[tuple[str, ...], str | None, str | None]] = set()
        for a in sorted(critical_high, key=lambda x: x.severity.value, reverse=True):
            key = (tuple(sorted(a.technique_ids)), a.host, a.source_ip)
            if key in seen_keys:
                continue
            seen_keys.add(key)
            tech_str = f" ({', '.join(a.technique_ids)})" if a.technique_ids else ""
            host_str = f" on {a.host}" if a.host else ""
            user_str = f" as {a.user}" if a.user else ""
            desc = f"{a.severity.value.upper()}: {a.description[:200]}{tech_str}{host_str}{user_str}"
            findings.append(desc)
            if len(findings) >= 5:
                break

        # Timeline phases (basic)
        phases: list[str] = []
        if any("T1078" in a.technique_ids or "T1110" in a.technique_ids for a in artifacts):
            phases.append("Initial Access / Credential Theft")
        if any("T1003" in t for t in techniques):
            phases.append("Credential Dumping")
        if any("T1059" in t for t in techniques):
            phases.append("Execution")
        if any("T1543" in t or "T1547" in t for t in techniques):
            phases.append("Persistence")
        if any("T1021" in t for t in techniques):
            phases.append("Lateral Movement")
        if any("T1070" in t or "T1562" in t for t in techniques):
            phases.append("Defense Evasion")
        if any("T1486" in t or "T1485" in t for t in techniques):
            phases.append("Impact")

        # Recommended actions
        actions: list[str] = []
        if techniques:
            actions.append("Investigate the source of initial access; rotate compromised credentials.")
        if severity_counts.get("critical", 0) > 0:
            actions.append("Isolate affected hosts and contain the breach.")
        if any(t.startswith("T1003") for t in techniques):
            actions.append("Reset all credentials on hosts where credential access was observed.")
        if any(t.startswith("T1021") for t in techniques):
            actions.append("Audit recent logons (Event 4624) on all domain controllers.")
        if not actions:
            actions.append("Review findings in detail; consider scoping analysis to a wider time range.")

        # Confidence
        if len(artifacts) > 50 and len(techniques) > 5:
            confidence = "high"
        elif len(artifacts) > 10:
            confidence = "medium"
        else:
            confidence = "low"

        return ExecutiveSummary(
            case_id=case_id,
            generated_at=datetime.now(UTC),
            overview=" ".join(overview_parts),
            key_findings=findings,
            timeline_phases=phases,
            techniques_observed=sorted(techniques),
            hosts_affected=sorted(hosts),
            users_involved=sorted(users),
            iocs_extracted=sorted(iocs)[:50],  # cap
            recommended_actions=actions,
            confidence=confidence,
            artifact_count=len(artifacts),
            llm_generated=False,
        )

    def _llm_enhance(
        self, artifacts: list[Artifact], base: ExecutiveSummary
    ) -> ExecutiveSummary:
        """Use the LLM to generate a narrative overview, key_findings, and actions.

        Replaces overview, key_findings, recommended_actions with LLM output.
        Other fields stay as-is.
        """
        # Build a concise prompt
        facts = self._build_prompt_facts(artifacts, base)
        system_prompt = (
            "You are a senior DFIR analyst writing an executive incident summary. "
            "Your audience is a CISO or security director. Be precise, factual, and avoid speculation. "
            "Cite specific evidence (Event IDs, MITRE techniques, IPs, users, hosts). "
            "Structure your response as JSON with these keys: "
            "'overview' (2-3 sentence executive summary), 'key_findings' (3-5 bullets, "
            "each citing evidence), 'recommended_actions' (3-5 prioritized next steps)."
        )
        user_prompt = (
            "Generate an executive summary for the following case based on these facts.\n\n"
            f"FACTS:\n{facts}\n\n"
            "Respond with JSON only. No prose. No markdown."
        )
        messages = [
            ChatMessage(role="system", content=system_prompt),
            ChatMessage(role="user", content=user_prompt),
        ]
        # Use synchronous call (we're in an async context but the LLM router is async)
        import asyncio
        router = self.llm_router
        assert router is not None  # mypy
        response = asyncio.run(router.chat(messages=messages, temperature=0.2))
        # Parse JSON from response
        try:
            data = json.loads(response.content)
        except json.JSONDecodeError:
            # Try to extract JSON from the response
            import re
            m = re.search(r"\{.*\}", response.content, re.DOTALL)
            if m:
                data = json.loads(m.group(0))
            else:
                log.warning("LLM response was not valid JSON: %s", response.content[:200])
                return base
        # Merge
        base.overview = str(data.get("overview", base.overview))
        findings = data.get("key_findings", base.key_findings)
        if isinstance(findings, list):
            base.key_findings = [str(f) for f in findings]
        actions = data.get("recommended_actions", base.recommended_actions)
        if isinstance(actions, list):
            base.recommended_actions = [str(a) for a in actions]
        base.llm_generated = True
        return base

    def _build_prompt_facts(
        self, artifacts: list[Artifact], base: ExecutiveSummary
    ) -> str:
        """Build a concise facts list for the LLM prompt."""
        lines: list[str] = []
        lines.append(f"- Total artifacts: {len(artifacts)}")
        lines.append(f"- Hosts affected: {', '.join(base.hosts_affected) or 'unknown'}")
        lines.append(f"- Users involved: {', '.join(base.users_involved) or 'unknown'}")
        lines.append(f"- Techniques: {', '.join(base.techniques_observed) or 'none'}")
        if artifacts:
            earliest = min(a.timestamp for a in artifacts)
            latest = max(a.timestamp for a in artifacts)
            lines.append(f"- Time range: {earliest.isoformat()} -> {latest.isoformat()}")
        # Top 10 most-severe events
        critical_high = sorted(
            [a for a in artifacts if a.severity in (Severity.CRITICAL, Severity.HIGH)],
            key=lambda a: (a.severity.value, a.timestamp),
            reverse=True,
        )[:10]
        if critical_high:
            lines.append("- Critical/High severity events:")
            for a in critical_high:
                tech_str = f" [{', '.join(a.technique_ids)}]" if a.technique_ids else ""
                host_str = f" host={a.host}" if a.host else ""
                user_str = f" user={a.user}" if a.user else ""
                lines.append(f"  * {a.source.value} {a.severity.value}: {a.description[:150]}{tech_str}{host_str}{user_str}")
        return "\n".join(lines)

    def analyze(
        self,
        artifacts: list[Artifact],
        case_id: str = "case",
        force_llm: bool = False,
    ) -> AnalysisResult:
        """Generate summary and return a partial AnalysisResult."""
        summary = self.generate(artifacts, case_id=case_id, force_llm=force_llm)
        return AnalysisResult(
            artifact_count=len(artifacts),
            summary=summary,
        )
