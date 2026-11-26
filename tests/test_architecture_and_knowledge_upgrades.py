"""Regression tests covering the Modes 1/2/3 architecture, LLM routing/egress, and knowledge upgrades."""
from __future__ import annotations

import asyncio
import json

from nexus.analysis.behavioural_analytics import (
    PLATFORM_PACK_PATH,
    analytics,
    load_pack,
    validate_pack,
)
from nexus.analysis.llm_journal import LLMJournal
from nexus.analysis.skill_steps import citation_grade
from nexus.audit import AuditWriter
from nexus.knowledge.loader import get_artifact, get_skill, skill_sources
from nexus.knowledge.skills import skills_for
from nexus.langgraph.backbone import _audited_examiner_call
from nexus.langgraph.context_loop import _result_summary
from nexus.langgraph.interpret_loop import _EXTRA_TOOL_NAMES, _render_results
from nexus.langgraph.llm_pipeline import _SqliteCheckpointSaver
from nexus.llm.egress import egress_required
from nexus.llm.router import LLMRouter
from nexus.modes.mode1_verify import apply_verifier
from nexus.modes.multi_agent import (
    _ground_confirmed_verdicts,
    _verdict_subject,
    _verifier_spawn,
    settled_candidates,
    stage_mode3,
)
from nexus.modes.multi_role import (
    ROLES,
    _investigative_extras,
    _retrieve_skill_refs,
)


class _DummySink:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, event: dict) -> None:
        self.events.append(event)


def test_examiner_check_has_audit_provenance_and_full_context_summary(tmp_path):
    audit = AuditWriter("nexus", audit_dir=tmp_path / "audit")
    result = _audited_examiner_call(
        "deobfuscate_command",
        audit,
        {"command": "powershell -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgAGgAZQBsAGwAbwA="},
    )
    assert result["provenance"]["audit_id"]
    summary = _result_summary("deobfuscate_command", result)
    assert summary.get("interpretation_constraint")
    assert summary.get("layers") or summary.get("decoded")
    assert "Write-Host hello" in str(summary)

    lolbin_summary = _result_summary(
        "check_lolbin",
        {
            "found": True,
            "verdict": "lolbin",
            "reasons": ["matched mshta.exe"],
            "lolbin": {"Name": "Mshta.exe"},
        },
    )
    assert lolbin_summary["verdict"] == "lolbin"
    assert lolbin_summary["lolbin"] == {"Name": "Mshta.exe"}
    assert "matched mshta.exe" in lolbin_summary["reasons"]


def test_interpret_loop_exposes_rag_and_examiner_checks_and_renders_summary():
    assert "rag_search" in _EXTRA_TOOL_NAMES
    assert "forensic_rag_search" in _EXTRA_TOOL_NAMES
    assert "check_driver" in _EXTRA_TOOL_NAMES
    assert "check_lots_domain" in _EXTRA_TOOL_NAMES
    assert "check_loobin" in _EXTRA_TOOL_NAMES

    rendered = _render_results([
        {
            "kind": "tool",
            "tool": "rag_search",
            "why": "check procedure",
            "audit_id": "aud-1",
            "summary": {"count": 1, "results": [{"title": "LSASS", "text": "Inspect Sysmon 10"}]},
        }
    ])
    assert "Inspect Sysmon 10" in rendered


def test_sqlite_checkpoint_saver_persists_across_restarts(tmp_path):
    from langgraph.checkpoint.base import empty_checkpoint

    db_path = tmp_path / "ckpt.sqlite"
    cfg = {"configurable": {"thread_id": "t-resume", "checkpoint_ns": ""}}
    ckpt = empty_checkpoint()
    ckpt["channel_values"] = {"phase": "orient_done"}
    saver1 = _SqliteCheckpointSaver(db_path)
    next_cfg = saver1.put(cfg, ckpt, {"step": 2}, {"phase": ckpt["channel_versions"].get("phase", 1)}) if ckpt.get("channel_versions") else saver1.put(cfg, ckpt, {"step": 2}, {})
    saver1.put_writes(next_cfg, [("evidence_paths", ["a.evtx"])], task_id="task-1")
    saver1._conn.close()

    saver2 = _SqliteCheckpointSaver(db_path)
    try:
        tup = saver2.get_tuple(cfg)
        assert tup is not None
        assert tup.checkpoint["id"] == ckpt["id"]
        assert tup.metadata["step"] == 2
        assert tup.pending_writes
    finally:
        saver2._conn.close()


def test_mode1_verify_uses_es_native_audit_ids_without_terms(tmp_path):
    audit = AuditWriter("nexus", audit_dir=tmp_path / "audit")
    hit_id = audit.log(
        tool="es_search",
        params={"family": "evtxecmd"},
        result_summary={"total": 2, "hits": [{"family": "evtxecmd", "event_id": "4624", "host": "WS01"}]},
    )
    zero_id = audit.log(
        tool="es_search",
        params={"family": "prefetch"},
        result_summary={"total": 0, "hits": []},
    )
    confirmed_draft = {
        "title": "Remote logon observed",
        "observation": "Event 4624 observed on WS01.",
        "audit_ids": [hit_id],
    }
    res_ok = apply_verifier(tmp_path, confirmed_draft)
    assert res_ok["verdict"] == "CONFIRMED"

    zero_draft = {
        "title": "No prefetch execution",
        "observation": "Prefetch search showed 0 rows.",
        "audit_ids": [zero_id],
    }
    res_zero = apply_verifier(tmp_path, zero_draft)
    assert res_zero["verdict"] == "REFUTED"


def test_mode2_evidence_tools_detection_extras_and_technique_skill_ranking(tmp_path):
    assert {"check_driver", "check_lots_domain", "check_loobin"}.issubset(set(ROLES["evidence"].tools))

    refs = _retrieve_skill_refs(["evtxecmd"], ["lsass"], limit=3, techniques=["T1003.001"])
    assert refs and any("credential" in str(r.get("skill") or "").lower() for r in refs)

    leads_dir = tmp_path / "analysis"
    leads_dir.mkdir(parents=True, exist_ok=True)
    (leads_dir / "leads.jsonl").write_text(
        json.dumps({"family": "vol", "subject": "T1014 rootkit hook", "techniques": ["T1014"]}) + "\n",
        encoding="utf-8",
    )
    extras = _investigative_extras(tmp_path)
    assert "DOMAIN DETECTION NOTES" in extras


def test_mode3_typed_verdicts_zero_hit_refutation_downgrade_uncapped_verifier_and_stage_guard(tmp_path):
    # 1. Typed _verdict_subject avoids collision across host/user
    assert _verdict_subject({"subject": "host=WS01"}) == ("host", "ws01")
    cands, _ = settled_candidates(
        [
            {"status": "complete", "role": "verifier", "verdicts": [{"subject": "user=WS01", "class": "refuted"}]},
            {
                "status": "complete",
                "role": "evidence",
                "claims": [
                    {
                        "entity_type": "host",
                        "entity_value": "WS01",
                        "claim_kind": "execution",
                        "statement": "Executed malware",
                        "audit_ids": ["a1"],
                        "confidence": "medium",
                        "confidence_justification": "Observed process execution audit row a1",
                    }
                ],
            },
        ],
        [],
        case_dir=tmp_path,
    )
    assert len(cands) == 1

    # 2. Zero-hit refutation downgrades to unverifiable
    audit = AuditWriter("nexus", audit_dir=tmp_path / "audit")
    zero_aid = audit.log(tool="es_search", params={"family": "evtxecmd"}, result_summary={"total": 0, "hits": []})
    entry = {
        "agent_id": "v1",
        "verdicts": [{"subject": "host=WS01", "class": "refuted", "audit_ids": [zero_aid]}],
    }
    sink = _DummySink()
    _ground_confirmed_verdicts(entry, tmp_path, run_id="RUN-M3", sink=sink)
    assert entry["verdicts"][0]["class"] == "unverifiable"
    assert sink.events and sink.events[0].event_type == "verify.downgraded"

    # 3. Verifier spawn is uncapped (>12 claims)
    unverified = [
        {"entity_type": "host", "entity_value": f"H{i}", "claim_kind": "exec", "statement": f"claim {i}"}
        for i in range(15)
    ]
    spawn = _verifier_spawn(unverified, question="verify hosts", superstep=1)
    assert spawn is not None
    assert len(spawn["verification_targets"]) == 15
    assert "h14" in spawn["question"].lower()

    # 4. stage_mode3 refuses fallback staging if synthesis explicitly failed
    runs_dir = tmp_path / "analysis" / "mode3_runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    run_id = "M3-FAILSYN"
    (runs_dir / f"{run_id}.json").write_text(
        json.dumps(
            {
                "run_id": run_id,
                "status": "capped",
                "gaps": ["the case was not composed: synthesis seat failed"],
                "candidates": [],
                "settled_claims": [{"statement": "raw"}],
                "board": [],
            }
        ),
        encoding="utf-8",
    )
    staged = stage_mode3(tmp_path, run_id)
    assert staged.get("staged") == []


def test_egress_required_provider_aware_and_journal_redaction(tmp_path):
    assert egress_required("") is False
    assert egress_required("", provider="openai") is True
    assert egress_required("", provider="anthropic") is True
    assert egress_required("http://127.0.0.1:11434", provider="ollama") is False

    journal = LLMJournal(tmp_path, run_id="R1")
    entry = journal.record_call(
        provider="openai",
        model="gpt-test",
        prompt="Host CORP-DC01.contoso.local connected from 10.20.30.40",
        response="ok",
    )
    assert entry["redaction_profile"] == "anonymized"
    assert "10.20.30.40" not in entry["prompt_excerpt"]


def test_llm_router_captures_dict_tool_calls_usage_and_scrubs_multimodal(tmp_path, monkeypatch):
    seen_messages: list = []

    class _FakeProv:
        name = "openai"
        base_url = "https://api.openai.com/v1"
        default_model = "gpt-test"

        async def chat(self, *, messages, model=None, temperature=None, max_tokens=None, tools=None, tool_choice=None):
            seen_messages.append(messages)
            return {
                "model": "gpt-test",
                "choices": [
                    {
                        "message": {
                            "content": "checked",
                            "tool_calls": [{"id": "c1", "function": {"name": "es_search", "arguments": '{"query": "ok"}'}}],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
                "usage": {"prompt_tokens": 120, "completion_tokens": 45},
            }

        async def close(self) -> None:
            return None

    case_dir = tmp_path / "CASE-R"
    case_dir.mkdir()
    monkeypatch.setattr("nexus.llm.egress._active_case_dir", lambda: case_dir)
    router = LLMRouter(openai_api_key="test")
    router._providers["openai"] = _FakeProv()
    resp = asyncio.run(
        router.chat(
            messages=[
                {
                    "role": "user",
                    "content": [{"type": "text", "text": "Inspect 192.168.55.12 on host VICTIM-PC"}],
                    "tool_calls": [{"id": "t1", "function": {"name": "x", "arguments": '{"ip": "192.168.55.12"}'}}],
                }
            ],
            provider="openai",
        )
    )
    assert resp.content == "checked"
    # Multimodal text part and tool_calls arguments were scrubbed before hitting provider
    sent = seen_messages[0][0]
    assert "192.168.55.12" not in sent["content"][0]["text"]
    assert "192.168.55.12" not in sent["tool_calls"][0]["function"]["arguments"]

    journal_path = case_dir / "analysis" / "llm_journal.jsonl"
    assert journal_path.is_file()
    entry = json.loads(journal_path.read_text(encoding="utf-8").strip().splitlines()[-1])
    assert entry["tool_calls"] == ["es_search"]
    assert entry["input_tokens"] == 120
    assert entry["output_tokens"] == 45


def test_knowledge_platform_scoping_artifacts_step_citations_and_non_windows_analytics():
    # 1. Windows host families do NOT pull email_phishing
    selected = [s.get("skill") for s in skills_for({"evtxecmd", "pecmd", "mftecmd"}, limit=20)]
    assert "email_phishing" not in selected
    assert "windows_event_log_analysis" in selected

    # 2. Linux-only host does NOT receive Windows-only skills
    linux_selected = [s.get("skill") for s in skills_for({"authlog", "auditd"})]
    assert "powershell_abuse" not in linux_selected
    assert "registry_artifact_analysis" not in linux_selected
    assert "linux_compromise" in linux_selected

    # 3. azure_signin resolves in cloud identity forensics and loads artifact metadata
    art = get_artifact("azure_signin", platform="cloud")
    assert art is not None and art["platform"] == "cloud"
    assert get_artifact("unified_logs", platform="macos")["platform"] == "macos"
    assert get_artifact("zeek_conn", platform="network")["platform"] == "network"

    # 4. Step-level citations propagate when top-level source: is absent
    sam_skill = get_skill("sam_ntds_credential_theft")
    assert sam_skill is not None
    assert skill_sources(sam_skill)
    assert citation_grade(sam_skill) in {"chunk", "document"}

    # 5. All 8 new non-Windows behavioral analytics validate cleanly and route by family
    assert validate_pack() == []
    assert validate_pack(load_pack(PLATFORM_PACK_PATH)) == []
    ba_ids = {item["id"] for item in analytics(PLATFORM_PACK_PATH)}
    assert {
        "ba-linux-sudo-privesc",
        "ba-linux-ssh-root-or-burst",
        "ba-linux-persistence-cron-systemd",
        "ba-cloud-iam-priv-change",
        "ba-cloud-logging-disabled",
        "ba-net-suricata-high-sev",
        "ba-net-c2-suspicious-port-proto",
        "ba-mem-hidden-or-injected-proc",
    }.issubset(ba_ids)
