"""Tests for Phase 3 real agentic components (WPs 3.14-3.21)."""


import pytest

from nexus.langgraph.correlation import EntityGraph, correlate_entities
from nexus.langgraph.correlation_agent import CorrelationAgent, correlate_agent_runs
from nexus.langgraph.entities import entities_to_dict, extract_entities
from nexus.langgraph.pattern_agent import PatternAgent
from nexus.langgraph.synthesis_agent import SynthesisAgent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_hit(family: str, text: str, **kwargs) -> dict:
    """Create a minimal N4 hit dict."""
    return {
        "family": family,
        "file": kwargs.get("file", f"{family}/output.csv"),
        "line": kwargs.get("line", "1"),
        "terms": kwargs.get("terms", "powershell"),
        "text": text,
        "fields": kwargs.get("fields", {}),
        "host": kwargs.get("host", "WS01"),
        "ts": kwargs.get("ts", ""),
        "audit_id": kwargs.get("audit_id", f"{family}-001"),
    }


@pytest.fixture
def evtx_hits():
    """EVTX hits with process execution and network connection."""
    return [
        _make_hit("evtx", "Process Create: powershell.exe -enc ABC123",
                  fields={"Image": "powershell.exe", "CommandLine": "powershell.exe -enc ABC123",
                          "SourceIp": "10.0.0.5", "User": "CORP\\analyst"},
                  ts="2026-09-10T10:23:41"),
        _make_hit("evtx", "Network Connection: powershell.exe → 10.0.0.5:443",
                  fields={"Image": "powershell.exe", "DestinationIp": "10.0.0.5",
                          "DestinationPort": "443"},
                  ts="2026-09-10T10:23:44"),
    ]


@pytest.fixture
def prefetch_hits():
    """Prefetch hits for the same process."""
    return [
        _make_hit("prefetch", "POWERSHELL.EXE-ABC123.pf run count 3",
                  fields={"ExecutableName": "powershell.exe", "RunCount": "3"},
                  ts="2026-09-10T10:23:42"),
    ]


@pytest.fixture
def netstat_hits():
    """Netstat hits for the same IP."""
    return [
        _make_hit("netstat", "TCP 10.0.0.5:443 ESTABLISHED powershell.exe",
                  fields={"LocalAddress": "10.0.0.5", "RemoteAddress": "10.0.0.5",
                          "ProcessName": "powershell.exe"},
                  ts="2026-09-10T10:23:44"),
    ]


# ---------------------------------------------------------------------------
# WP 3.14 — Entity extraction service
# ---------------------------------------------------------------------------

class TestEntityExtraction:
    def test_extract_process_name(self, evtx_hits):
        entities = extract_entities(evtx_hits)
        assert "process_name" in entities
        values = [e["value"].lower() for e in entities["process_name"]]
        assert "powershell.exe" in values

    def test_extract_ipv4(self, evtx_hits):
        entities = extract_entities(evtx_hits)
        assert "ipv4" in entities
        values = [e["value"] for e in entities["ipv4"]]
        assert "10.0.0.5" in values

    def test_extract_domain_user(self, evtx_hits):
        entities = extract_entities(evtx_hits)
        assert "domain_user" in entities
        values = [e["value"] for e in entities["domain_user"]]
        assert "CORP\\analyst" in values

    def test_extract_from_fields(self, evtx_hits):
        entities = extract_entities(evtx_hits)
        # Fields should produce entities even if text doesn't match regex
        assert len(entities) > 0

    def test_entity_has_hit_references(self, evtx_hits):
        entities = extract_entities(evtx_hits)
        for entity_list in entities.values():
            for ent in entity_list:
                assert "hits" in ent
                assert len(ent["hits"]) > 0
                assert "families" in ent
                assert len(ent["families"]) > 0

    def test_entities_to_dict(self, evtx_hits):
        entities = extract_entities(evtx_hits)
        flat = entities_to_dict(entities)
        assert isinstance(flat, dict)
        for v in flat.values():
            assert isinstance(v, list)


# ---------------------------------------------------------------------------
# WP 3.15 — Entity correlation engine
# ---------------------------------------------------------------------------

class TestCorrelationEngine:
    def test_cross_family_entity(self, evtx_hits, prefetch_hits, netstat_hits):
        graph = EntityGraph()
        graph.add_from_hits(extract_entities(evtx_hits))
        graph.add_from_hits(extract_entities(prefetch_hits))
        graph.add_from_hits(extract_entities(netstat_hits))
        corroborated = graph.get_cross_family_entities("process_name")
        assert len(corroborated) >= 1
        ps = [e for e in corroborated if e["value"].lower() == "powershell.exe"]
        assert len(ps) == 1
        assert len(ps[0]["families"]) >= 2

    def test_temporal_chain(self, evtx_hits, prefetch_hits, netstat_hits):
        graph = EntityGraph()
        graph.add_from_hits(extract_entities(evtx_hits))
        graph.add_from_hits(extract_entities(prefetch_hits))
        graph.add_from_hits(extract_entities(netstat_hits))
        chains = graph.get_chains(window_seconds=300)
        # Should find chains for powershell.exe across families
        assert len(chains) >= 1
        ps_chains = [c for c in chains if c["entity"].lower() == "powershell.exe"]
        assert len(ps_chains) >= 1

    def test_correlate_entities(self, evtx_hits, prefetch_hits):
        graph = EntityGraph()
        graph.add_from_hits(extract_entities(evtx_hits))
        graph.add_from_hits(extract_entities(prefetch_hits))
        result = correlate_entities(graph)
        assert "corroborated_entities" in result
        assert "chains" in result
        assert "summary" in result
        assert result["summary"]["cross_family_count"] >= 1


# ---------------------------------------------------------------------------
# WP 3.18 — CorrelationAgent
# ---------------------------------------------------------------------------

class TestCorrelationAgent:
    def test_feed_and_run(self, evtx_hits, prefetch_hits, netstat_hits):
        agent = CorrelationAgent()
        agent.feed_entities(extract_entities(evtx_hits))
        agent.feed_entities(extract_entities(prefetch_hits))
        agent.feed_entities(extract_entities(netstat_hits))
        result = agent.run()
        assert "corroborated_entities" in result
        assert "chains" in result
        assert "confidence" in result.get("corroborated_entities", [{}])[0] if result.get("corroborated_entities") else True

    def test_correlate_agent_runs(self, evtx_hits, prefetch_hits):
        runs = [
            {"entities": extract_entities(evtx_hits)},
            {"entities": extract_entities(prefetch_hits)},
        ]
        result = correlate_agent_runs(runs)
        assert "corroborated_entities" in result


# ---------------------------------------------------------------------------
# WP 3.19 — PatternAgent
# ---------------------------------------------------------------------------

class TestPatternAgent:
    def test_load_patterns(self):
        agent = PatternAgent()
        assert len(agent._patterns) > 0

    def test_detect_patterns(self, evtx_hits, prefetch_hits, netstat_hits):
        agent = PatternAgent()
        all_entities = extract_entities(evtx_hits + prefetch_hits + netstat_hits)
        chains = correlate_agent_runs([
            {"entities": extract_entities(evtx_hits)},
            {"entities": extract_entities(prefetch_hits)},
        ]).get("chains", [])
        result = agent.detect_patterns(all_entities, chains)
        assert "patterns" in result
        assert "narrative_fragments" in result
        assert "total_patterns_checked" in result
        # Should find at least one pattern (process + IP = lateral movement or C2)
        assert result["total_matches"] >= 1

    def test_pattern_has_evidence(self, evtx_hits, prefetch_hits):
        agent = PatternAgent()
        all_entities = extract_entities(evtx_hits + prefetch_hits)
        result = agent.detect_patterns(all_entities)
        for pattern in result["patterns"]:
            assert "matched_entities" in pattern
            assert "confidence" in pattern
            assert "mitre" in pattern


# ---------------------------------------------------------------------------
# WP 3.20 — SynthesisAgent
# ---------------------------------------------------------------------------

class TestSynthesisAgent:
    def test_synthesize(self, evtx_hits, prefetch_hits, netstat_hits):
        agent = SynthesisAgent()
        runs = [
            {"entities": extract_entities(evtx_hits)},
            {"entities": extract_entities(prefetch_hits)},
            {"entities": extract_entities(netstat_hits)},
        ]
        corr = correlate_agent_runs(runs)
        pattern_agent = PatternAgent()
        all_entities = {}
        for run in runs:
            for etype, elist in run["entities"].items():
                all_entities.setdefault(etype, []).extend(elist)
        patterns = pattern_agent.detect_patterns(all_entities, corr.get("chains", []))
        result = agent.synthesize(runs, corr, patterns, "find suspicious powershell")
        assert "narrative" in result
        assert "findings" in result
        assert "confidence" in result
        assert len(result["findings"]) > 0

    def test_findings_have_evidence_refs(self, evtx_hits, prefetch_hits):
        agent = SynthesisAgent()
        runs = [
            {"entities": extract_entities(evtx_hits)},
            {"entities": extract_entities(prefetch_hits)},
        ]
        corr = correlate_agent_runs(runs)
        pattern_agent = PatternAgent()
        all_entities = {}
        for run in runs:
            for etype, elist in run["entities"].items():
                all_entities.setdefault(etype, []).extend(elist)
        patterns = pattern_agent.detect_patterns(all_entities)
        result = agent.synthesize(runs, corr, patterns)
        for finding in result["findings"]:
            assert "evidence_refs" in finding or "agent_id" in finding
            assert finding["status"] == "DRAFT"
            assert finding["examiner_selected"] is False


# ---------------------------------------------------------------------------
# Integration: full pipeline
# ---------------------------------------------------------------------------

class TestFullPipeline:
    def test_full_pipeline(self, evtx_hits, prefetch_hits, netstat_hits):
        """End-to-end: extract → correlate → pattern → synthesize."""
        # Extract
        entities = extract_entities(evtx_hits + prefetch_hits + netstat_hits)
        assert len(entities) > 0

        # Correlate
        agent = CorrelationAgent()
        agent.feed_entities(entities)
        corr = agent.run()
        assert len(corr["corroborated_entities"]) >= 1

        # Pattern
        pattern_agent = PatternAgent()
        patterns = pattern_agent.detect_patterns(entities, corr["chains"])
        assert patterns["total_matches"] >= 1

        # Synthesize
        synth = SynthesisAgent()
        result = synth.synthesize(
            [{"entities": entities}], corr, patterns, "find suspicious powershell"
        )
        assert len(result["findings"]) > 0
        assert result["confidence"] > 0
        assert result["narrative"] != ""
