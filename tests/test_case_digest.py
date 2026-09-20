"""GATE-A regression tests — context budget, Case Digest, reconciliation,
n4_sample, and the run-options plumbing."""
from __future__ import annotations

import json
from pathlib import Path

from nexus.langgraph import prompt_budget
from nexus.langgraph.case_digest import (
    _classify,
    _signal_map,
    build_case_digest,
    reconciliation_checklist,
    render_digest_markdown,
    write_case_digest,
)

# ── prompt_budget ────────────────────────────────────────────────────────

def test_budget_from_window_and_ratio(monkeypatch):
    monkeypatch.setenv("NEXUS_LLM_CONTEXT_WINDOW", "1000000")
    monkeypatch.setenv("NEXUS_CONTEXT_FILL_RATIO", "0.7")
    assert prompt_budget.context_window() == 1_000_000
    assert prompt_budget.budget_chars() == int(1_000_000 * 0.7 * 4)


def test_budget_defaults_without_env(monkeypatch):
    monkeypatch.delenv("NEXUS_LLM_CONTEXT_WINDOW", raising=False)
    monkeypatch.delenv("NEXUS_CONTEXT_FILL_RATIO", raising=False)
    assert prompt_budget.context_window() == 1_000_000
    assert prompt_budget.fill_ratio() == 0.7


def test_budget_bad_env_falls_back(monkeypatch):
    monkeypatch.setenv("NEXUS_LLM_CONTEXT_WINDOW", "not-a-number")
    monkeypatch.setenv("NEXUS_CONTEXT_FILL_RATIO", "nope")
    assert prompt_budget.context_window() == 1_000_000
    assert prompt_budget.fill_ratio() == 0.7


def test_pack_sections_priority_and_report():
    sections = [
        (1, "second", "B" * 500),
        (0, "first", "A" * 500),
    ]
    packed, report = prompt_budget.pack_sections(sections, chars=1000)
    assert packed.startswith("A")  # priority 0 first regardless of list order
    assert len(packed) <= 1000 + 2  # join separators
    assert report["sections"]["first"]["chars"] > 0
    assert report["used_chars"] <= 1000


def test_pack_sections_giant_first_section_does_not_starve_second():
    # A huge priority-0 section must not eat the whole budget in pass 1.
    sections = [
        (0, "digest", "D" * 100_000),
        (1, "pack", "P" * 100_000),
    ]
    packed, report = prompt_budget.pack_sections(sections, chars=10_000)
    assert report["sections"]["pack"]["chars"] > 0
    assert "P" in packed
    assert report["used_chars"] <= 10_000


def test_pack_sections_truncation_flag():
    packed, report = prompt_budget.pack_sections(
        [(0, "only", "x" * 5000)], chars=1000
    )
    assert report["sections"]["only"]["truncated"] is True
    assert len(packed) == 1000


def test_retry_budget_halves(monkeypatch):
    monkeypatch.setenv("NEXUS_CONTEXT_RETRY_RATIO", "0.5")
    assert prompt_budget.retry_budget_chars(10_000) == 5_000


def test_persist_context_writes_file(tmp_path):
    packed, report = prompt_budget.pack_sections([(0, "digest", "facts")], chars=1000)
    path = prompt_budget.persist_context(
        tmp_path, "mode2-interpret", packed, report, meta={"case_id": "CASE-1"}
    )
    assert path is not None and path.is_file()
    text = path.read_text(encoding="utf-8")
    assert "LLM context" in text
    assert "facts" in text
    assert "CASE-1" in text


def test_estimate_tokens_nonzero():
    assert prompt_budget.estimate_tokens("") == 0
    assert prompt_budget.estimate_tokens("abcd") >= 1


# ── case_digest ──────────────────────────────────────────────────────────

def _fake_brief() -> dict:
    return {
        "inventory": {"hayabusa": {"files": 1, "rows": 120}, "zeek": {"files": 1, "rows": 40}},
        "families": ["hayabusa", "zeek"],
        "ledger": {"ok": 2, "skip": 0, "fail": 0, "entries": [
            {"tool": "EvtxECmd", "status": "OK", "family": "hayabusa", "reason": ""},
        ]},
        "hosts": ["ws01"],
        "time_range": {"start": "2024-01-01T00:00:00", "end": "2024-01-02T00:00:00"},
        "alerts": [
            {"level": "high", "family": "hayabusa", "title": "Mimikatz detected",
             "host": "ws01", "time": "2024-01-01T10:00:00"},
            {"level": "low", "family": "zeek", "title": "Weird DNS", "host": "ws01", "time": ""},
        ],
        "entities": {"processes": [{"value": "m.exe", "hits": 5}]},
        "intake": {"question": "What did m.exe do?"},
        "hits_examined": 160,
        "backend": "elasticsearch",
    }


def test_classify_scope(tmp_path):
    classes = _classify(["hayabusa", "zeek", "splunk", "memory_dump"])
    assert "hayabusa" in classes["host"]
    assert "zeek" in classes["network"]
    assert "splunk" in classes["siem"]
    assert "memory_dump" in classes["memory"]


def test_signal_map_zero_hits_are_negative_evidence(tmp_path):
    analysis = tmp_path / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "signal_map.csv").write_text(
        "needle,hits,source\nmimikatz,4,playbook\nsdelete,0,playbook\n", encoding="utf-8"
    )
    smap = _signal_map(tmp_path, {})
    assert [r["needle"] for r in smap["with_hits"]] == ["mimikatz"]
    assert smap["zero_hit"] == ["sdelete"]
    assert smap["scanned"] == 2
    assert smap["unscanned"] == []


def test_signal_map_unscanned_is_not_negative_evidence(tmp_path):
    """scanned=no must never masquerade as 'checked, absent'."""
    analysis = tmp_path / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "signal_map.csv").write_text(
        "needle,hits,source,scanned\n"
        "mimikatz,4,playbook,yes\n"
        "sdelete,0,playbook,yes\n"
        "rdp,0,playbook,no\n",
        encoding="utf-8",
    )
    smap = _signal_map(tmp_path, {})
    assert smap["zero_hit"] == ["sdelete"]
    assert smap["unscanned"] == ["rdp"]
    md = render_digest_markdown({
        "case_id": "CASE-X", "signal_map": smap, "scope": {}, "inventory": {},
    })
    assert "NOT scanned" in md and "rdp" in md


def test_build_digest_scopes_absent_classes(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.briefing.case_briefing", lambda case_dir: _fake_brief()
    )
    monkeypatch.setattr(
        "nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None
    )
    digest = build_case_digest(tmp_path)
    assert digest["backend"] == "elasticsearch"
    absent = digest["scope"]["explicitly_absent"]
    assert any("memory" in a for a in absent)
    assert any("disk" in a for a in absent)
    assert not any("network flows" in a for a in absent)  # zeek present


def test_render_and_write_digest(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "nexus.langgraph.briefing.case_briefing", lambda case_dir: _fake_brief()
    )
    monkeypatch.setattr(
        "nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None
    )
    analysis = tmp_path / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "signal_map.csv").write_text(
        "needle,hits,source\nmimikatz,4,playbook\nsdelete,0,playbook\n", encoding="utf-8"
    )
    digest = build_case_digest(tmp_path)
    md = render_digest_markdown(digest)
    assert "Case Digest" in md
    assert "NOT in evidence" in md
    assert "Negative evidence" in md
    paths = write_case_digest(tmp_path, digest)
    assert Path(paths["json"]).is_file()
    assert Path(paths["md"]).is_file()
    loaded = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    assert loaded["case_id"] == digest["case_id"]


def test_reconciliation_flags_unmentioned_items():
    digest = {
        "alerts": [
            {"level": "high", "title": "Mimikatz detected", "host": "ws01"},
            {"level": "critical", "title": "Ransomware note", "host": "ws01"},
        ],
        "signal_map": {"with_hits": [{"needle": "psexec", "hits": 9}]},
    }
    findings = [{"title": "Mimikatz detected on ws01", "interpretation": "credential theft"}]
    result = reconciliation_checklist(digest, findings)
    unaddressed = [i["value"] for i in result["unaddressed"]]
    assert any("Ransomware note" in u for u in unaddressed)
    assert any("psexec" in u for u in unaddressed)
    assert not any("Mimikatz" in u for u in unaddressed)


def test_reconciliation_ignores_structural_keys():
    """A finding with evidence rows must not accidentally 'mention' a needle
    named like a dict key (source/detail/time/artifact)."""
    digest = {
        "alerts": [{"level": "high", "title": "source", "host": "ws01"}],
        "signal_map": {"with_hits": [{"needle": "detail", "hits": 5}]},
    }
    findings = [{
        "title": "Unrelated finding",
        "observation": "something else",
        "interpretation": "unrelated",
        "evidence": [{"time": "2024-01-01", "source": "hayabusa",
                      "artifact": "evtx", "detail": "unrelated row"}],
    }]
    result = reconciliation_checklist(digest, findings)
    kinds = {i["kind"] for i in result["unaddressed"]}
    assert "alert" in kinds and "needle" in kinds
    assert len(result["unaddressed"]) == 2


def test_pack_sections_duplicate_names_not_double_counted():
    """Two sections with the same name must not be silently emitted twice
    (that would double content AND the budget accounting)."""
    from nexus.langgraph.prompt_budget import pack_sections

    packed, report = pack_sections([
        (0, "case_digest", "DIGEST-CONTENT"),
        (0, "case_digest", "DIGEST-CONTENT"),
    ], chars=10_000)
    assert packed.count("DIGEST-CONTENT") == 2  # both kept, namespaced
    assert set(report["sections"]) == {"case_digest", "case_digest#2"}


def test_case_window_reads_run_options(tmp_path, monkeypatch):
    from nexus.langgraph.prompt_budget import case_window, context_window

    monkeypatch.setenv("NEXUS_LLM_CONTEXT_WINDOW", "500000")
    assert case_window(tmp_path) == 500_000  # no options file → env default
    (tmp_path / "analysis").mkdir(parents=True)
    (tmp_path / "analysis" / "mode2_run_options.json").write_text(
        json.dumps({"context_window": 128000}), encoding="utf-8"
    )
    assert case_window(tmp_path) == 128_000  # case's own window wins
    assert context_window() == 500_000       # env untouched


def test_build_digest_accepts_cached_brief(tmp_path, monkeypatch):
    """The portal passes its cached briefing — the digest must not re-scan."""
    called = {"n": 0}

    def _boom(case_dir):
        called["n"] += 1
        return _fake_brief()

    monkeypatch.setattr("nexus.langgraph.briefing.case_briefing", _boom)
    monkeypatch.setattr(
        "nexus.langgraph.case_index.es_aggregate", lambda *a, **k: None
    )
    digest = build_case_digest(tmp_path, brief=_fake_brief())
    assert called["n"] == 0
    assert digest["case_id"] == tmp_path.name


# ── n4_sample ────────────────────────────────────────────────────────────

def test_n4_sample_spreads_over_timeline(monkeypatch, tmp_path):
    from nexus.langgraph import query_pack

    hits = [
        {"family": "hayabusa", "ts": f"2024-01-01T00:{i:02d}:00", "host": "ws01",
         "text": f"row {i}"}
        for i in range(30)
    ]
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: (hits, "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda intake: ["x"])
    result = query_pack.n4_sample(tmp_path, family="hayabusa", n=6)
    assert result["matched"] == 30
    assert result["sampled"] == 6
    assert result["spread_every"] == 5
    # Spread: first and last hits are present (not a single burst)
    assert result["hits"][0]["text"] == "row 0"
    assert result["hits"][-1]["text"] == "row 25"


def test_n4_sample_family_filter(monkeypatch, tmp_path):
    from nexus.langgraph import query_pack

    hits = [
        {"family": "hayabusa", "text": "a"},
        {"family": "zeek", "text": "b"},
        {"family": "zeek", "text": "c"},
    ]
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: (hits, "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda intake: ["x"])
    result = query_pack.n4_sample(tmp_path, family="zeek", n=5)
    assert result["matched"] == 2
    assert all(h["family"] == "zeek" for h in result["hits"])


def test_n4_sample_envelope_fields_and_event_alias(monkeypatch, tmp_path):
    """CSV-shaped hits (no attached fields) must match on envelope keys, and
    `event` must alias `event_id` — the planner is told to request both."""
    from nexus.langgraph import query_pack

    hits = [
        {"family": "hayabusa", "text": "row1", "host": "WS01", "event_id": "4624",
         "user": "alice"},
        {"family": "hayabusa", "text": "row2", "host": "WS02", "event_id": "4688"},
    ]
    monkeypatch.setattr(query_pack, "n4_hits", lambda *a, **k: (hits, "csv"))
    monkeypatch.setattr(query_pack, "load_case_intake", lambda d: {})
    monkeypatch.setattr(query_pack, "collect_query_terms", lambda intake: ["x"])

    by_host = query_pack.n4_sample(tmp_path, family="hayabusa", field="host",
                                   value="WS01")
    assert by_host["matched"] == 1

    by_event = query_pack.n4_sample(tmp_path, family="hayabusa", field="event",
                                    value="4688")
    assert by_event["matched"] == 1

    by_user = query_pack.n4_sample(tmp_path, family="hayabusa", field="user")
    assert by_user["matched"] == 1  # presence filter


def test_backbone_allowlist_has_es_sample():
    """4k.5.5: the Mode 2/3 sample tool is the ES-native one."""
    from nexus.langgraph.backbone import MODE2_TOOL_ALLOWLIST, tool_contracts_block

    assert MODE2_TOOL_ALLOWLIST.get("es_sample") == "evidence"
    assert "es_sample" in tool_contracts_block(2)


def test_backbone_call_binding_exists():
    import inspect

    from nexus.langgraph import backbone

    src = inspect.getsource(backbone.backbone_call)
    assert 'name == "n4_sample"' in src


# ── interpretation reconciliation ────────────────────────────────────────

def test_interpretation_file_includes_reconciliation(tmp_path):
    import asyncio

    from nexus.langgraph.interpretation import write_interpretation_summary

    out = asyncio.run(write_interpretation_summary(
        tmp_path,
        findings=[{"title": "F1", "interpretation": "i", "confidence": "HIGH"}],
        reconciliation={
            "addressed": [{"kind": "alert", "value": "F1"}],
            "unaddressed": [{"kind": "needle", "value": "psexec (9 hits)"}],
            "alerts_total": 2,
            "needles_with_hits": 3,
        },
        model=None,
    ))
    assert out is not None
    text = Path(out).read_text(encoding="utf-8")
    assert "Reconciliation" in text
    assert "psexec (9 hits)" in text

def test_digest_render_flags_truncated_scan():
    """The digest must tell the LLM when hit counts are lower bounds."""
    md = render_digest_markdown({
        "case_id": "CASE-X",
        "scan_stats": {"truncated": True, "truncated_reasons": ["result cap", "2 capped file(s)"]},
        "signal_map": {}, "scope": {}, "inventory": {},
    })
    assert "LOWER BOUNDS" in md
    assert "result cap" in md
