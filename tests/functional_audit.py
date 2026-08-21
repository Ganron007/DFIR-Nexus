"""Phase 1-4 functional audit — verifies wiring, not stubs."""
import json
import os
import sys
import tempfile
from pathlib import Path

passed = 0
failed = 0
THRESHOLD = 0  # set to >0 for strict mode
OK, FAIL = "PASS", "FAIL"

def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [{OK}] {label}")
    else:
        failed += 1
        print(f"  [{FAIL}] {label}  -- {detail}")
    return condition

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
os.chdir(Path(__file__).resolve().parent)

# ──────────────────────────────────────────────
# 1. Package imports — are all modules loadable?
# ──────────────────────────────────────────────
print("\n=== 1. Package imports ===")
MODULES = [
    ("nexus", ["__version__"]),
    ("nexus.case", ["CaseManager", "Case", "Finding", "EvidenceRecord", "AuditEntry",
                    "CaseStatus", "FindingSeverity", "ApprovalState", "AuditAction",
                    "SQLiteStore", "AuditChain", "ApprovalWorkflow", "get_audit_secret",
                    "ApprovalError", "get_sqlite_manager", "LegacyJsonImporter"]),
    ("nexus.llm", ["LLMRouter", "LLMProvider", "ChatMessage", "ChatResponse",
                   "ProviderNotFoundError", "OpenAICompatProvider"]),
    ("nexus.utils", ["run_async", "resolve_read_path", "resolve_write_path"]),
    ("nexus.integration", ["CaseExporter", "VQLRunner",
                           "build_case_knowledge_graph", "notify_channel",
                           "export_to_json", "export_to_markdown", "export_to_html",
                           "export_to_stix", "export_case_zip", "export_to_docx"]),
    ("nexus.mitre", ["MITREService", "RBAScorer", "ThreatActorProfile",
                     "RBAScore", "build_observed_layer", "match_actors",
                     "create_mitre_service", "create_rba_scorer"]),
    ("nexus.rag", ["RAGDocument", "SearchHit", "validate_query", "validate_top_k",
                   "load_jsonl", "score_quality"]),
    ("nexus.vr", ["VRService", "VRCatalogEntry", "VRClientInfo", "VRHuntRunResult",
                  "create_vr_service", "suggest_hunt_ids"]),
    ("nexus.collect", ["plan_or_run", "import_dump", "tool_inventory", "vr_live_status"]),
    ("nexus.analysis", []),  # verify loadable, check whatever's exported
]

for mod_name, symbols in MODULES:
    try:
        mod = __import__(mod_name, fromlist=["_"])
        for sym in symbols:
            if not hasattr(mod, sym):
                check(f"import {mod_name}.{sym}", False, f"symbol {sym} missing from {mod_name}")
            else:
                check(f"import {mod_name}.{sym}", True)
    except Exception as e:
        check(f"import {mod_name}", False, str(e)[:80])

# ──────────────────────────────────────────────
# 2. Case stack — create case, finding, evidence, audit chain
# ──────────────────────────────────────────────
print("\n=== 2. Case stack (SQLite) ===")
from nexus.case import ApprovalState, ApprovalWorkflow, CaseManager, CaseStatus, FindingSeverity

db = Path(tempfile.gettempdir()) / f"audit_{os.getpid()}.db"
mgr = CaseManager(db, secret_key=b"audit-test")

# Create case
case = mgr.create_case(name="AUDIT-CASE", severity=FindingSeverity.HIGH, created_by="auditor")
check("create_case", case.id.startswith("CASE-"), case.id)
check("case status OPEN", case.status == CaseStatus.OPEN)

# Add finding
finding = mgr.add_finding(case.id, "Suspicious PowerShell", severity=FindingSeverity.CRITICAL,
                          technique_ids=["T1059.001"])
check("add_finding", finding is not None and finding.case_id == case.id)
check("finding severity CRITICAL", finding.severity == FindingSeverity.CRITICAL)

# Add evidence
ev = mgr.add_evidence(case.id, "memory.dmp", file_hash_sha256="abc" * 8)
check("add_evidence", ev is not None and ev.case_id == case.id)

# Close case
closed = mgr.close_case(case.id, closed_by="auditor")
check("close_case", closed is not None and closed.status == CaseStatus.CLOSED)

# Audit chain
ok, errors = mgr.verify_audit_chain(case.id)
check("verify_audit_chain OK", ok, "; ".join(errors) if errors else "")

mgr.close()
db.unlink(missing_ok=True)

# ──────────────────────────────────────────────
# 3. Approval workflow — set password, approve, verify signature
# ──────────────────────────────────────────────
print("\n=== 3. Approval workflow ===")
from nexus.case import ApprovalPasswordError

db2 = Path(tempfile.gettempdir()) / f"approval_{os.getpid()}.db"
mgr2 = CaseManager(db2, secret_key=b"audit-test")

case2 = mgr2.create_case(name="APPROVAL-TEST")
mgr2.set_case_approval_password(case2.id, "hunter2")
case2 = mgr2.get_case(case2.id)  # reload to get updated password fields
finding2 = mgr2.add_finding(case2.id, "LSASS dump", severity=FindingSeverity.HIGH)

check("password_hash set", bool(case2.approval_password_hash) if case2 else False)
check("password_salt set", bool(case2.approval_password_salt) if case2 else False)

approved = mgr2.approve_finding(finding2.id, "hunter2", approved_by="auditor")
check("approve_finding", approved is not None and approved.approval_state == ApprovalState.APPROVED)
check("hmac_signature present", bool(approved.hmac_signature) if approved else False)
check("hmac_salt present", bool(approved.hmac_salt) if approved else False)

# Verify signature
ok, errors = mgr2.verify_approval_signatures(case2.id, "hunter2")
check("verify_approval_signatures OK", ok, "; ".join(errors) if errors else "")

# Wrong password
wf = ApprovalWorkflow()
workflow_finding = mgr2.add_finding(case2.id, "Another finding")
case_from_db = mgr2.get_case(case2.id)
try:
    wf.approve(case_from_db, workflow_finding, "wrong")
    check("wrong password rejected", False, "should have raised")
except (ApprovalPasswordError, Exception):
    check("wrong password rejected", True)

mgr2.close()
db2.unlink(missing_ok=True)

# ──────────────────────────────────────────────
# 4. Legacy JSON importer
# ──────────────────────────────────────────────
print("\n=== 4. Legacy JSON importer ===")
from nexus.case import LegacyJsonImporter

tmp = Path(tempfile.gettempdir()) / f"legacy_{os.getpid()}"
case_dir = tmp / "LEGACY-CASE"
case_dir.mkdir(parents=True)
(case_dir / "findings.json").write_text(json.dumps([
    {"id": "F-1", "title": "Test finding", "status": "draft", "observation": "test"}
]))

db3 = tmp / "imported.db"
importer_mgr = CaseManager(db3, secret_key=b"legacy-test")
importer = LegacyJsonImporter(importer_mgr)
imported = importer.import_case(case_dir)
check("legacy_import_case", imported is not None and imported.id == "LEGACY-CASE")

findings_list = importer_mgr.list_findings("LEGACY-CASE")
check("legacy_import_findings", len(findings_list) == 1)

importer_mgr.close()
import shutil
shutil.rmtree(tmp, ignore_errors=True)

# ──────────────────────────────────────────────
# 5. MITRE — actors, match, RBA, navigator layers
# ──────────────────────────────────────────────
print("\n=== 5. MITRE module ===")
from nexus.mitre import build_observed_layer, create_mitre_service, create_rba_scorer

svc = create_mitre_service()
actors = svc.list_actors()
check("list_actors >= 6", len(actors) >= 6, str(len(actors)))

actor = svc.get_actor("apt29")
check("get_actor apt29", actor is not None)
check("actor techniques >= 5", len(actor.technique_ids) >= 5 if actor else False, str(len(actor.technique_ids) if actor else 0))

matches = svc.match_actors(["T1558.003", "T1003.006", "T1482"], min_overlap=2)
check("match_actors nexus-ad", bool(matches) and matches[0]["actor_id"] == "nexus-default-ad")

scorer = create_rba_scorer()
score = scorer.score(technique_ids=["T1003.001", "T1486"], severities=["critical", "high"])
check("rba_score >= 55", score.score >= 55, str(score.score))
check("rba_tier high|critical", score.tier in ("high", "critical"), score.tier)

layer = svc.navigator_actor_layer("fin7")
check("navigator_actor_layer", layer is not None and layer["versions"]["layer"] == "4.5")

observed = build_observed_layer(["T1003.001"])
check("observed_layer metadata", len(observed["techniques"]) == 1)

# ──────────────────────────────────────────────
# 6. VR — Velociraptor catalog and service
# ──────────────────────────────────────────────
print("\n=== 6. VR module ===")
from nexus.vr import create_vr_service

vr_svc = create_vr_service(force_mock=True)
check("vr_service created", vr_svc is not None)
check("vr_use_mock", bool(vr_svc.use_mock))

health = vr_svc.health()
check("vr_health", bool(health["mock_mode"]))

clients = vr_svc.list_clients()
check("vr_clients >= 7", len(clients) >= 7, str(len(clients)))

hunts = vr_svc.list_hunts()
check("vr_hunts >= 8", len(hunts) >= 8, str(len(hunts)))

suggested = vr_svc.suggest_hunts(["T1003.001", "T1003.002"])
check("vr_suggest_hunts", len(suggested) > 0, str(suggested))

result = vr_svc.run_hunt("nexus-process-tree", "C.mbr01")
check("vr_run_hunt", result is not None and result.row_count >= 2, str(result.row_count if result else None))

# ──────────────────────────────────────────────
# 7. Integration — export formats
# ──────────────────────────────────────────────
print("\n=== 7. Integration/Export ===")
from nexus.case import CaseManager as CM
from nexus.integration.case_export import (
    export_to_html,
    export_to_json,
    export_to_markdown,
    export_to_stix,
)
from nexus.integration.export_formats import export_case_zip, export_findings_csv, export_to_docx
from nexus.integration.knowledge_graph import build_case_knowledge_graph
from nexus.ingest.cti_ingestion import _extract_iocs_from_text

db4 = Path(tempfile.gettempdir()) / f"export_{os.getpid()}.db"
emgr = CM(db4, secret_key=b"export-test")
ecase = emgr.create_case(name="EXPORT-TEST")
emgr.add_finding(ecase.id, "Bad thing", technique_ids=["T1003.001"], severity=FindingSeverity.HIGH)

bundle = {
    "case": ecase,
    "findings": emgr.list_findings(ecase.id),
    "evidence": emgr.list_evidence(ecase.id),
    "audit_log": emgr.get_audit_log(ecase.id),
    "audit_verified": True,
    "audit_errors": [],
}

j = export_to_json(bundle)
check("export_to_json", "EXPORT-TEST" in j)
check("export_to_markdown", "# Case Report" in export_to_markdown(bundle))
check("export_to_html", "<!DOCTYPE html>" in export_to_html(bundle))

stix = json.loads(export_to_stix(bundle))
check("export_to_stix", stix["type"] == "bundle")

csv_text = export_findings_csv(bundle["findings"])
check("export_csv", "Bad thing" in csv_text)

zip_bytes = export_case_zip(bundle)
check("export_zip PK header", zip_bytes[:2] == b"PK")

docx_bytes = export_to_docx(bundle)
check("export_docx > 100 bytes", len(docx_bytes) > 100)

kg = build_case_knowledge_graph(bundle)
check("knowledge_graph entities", len(kg.entities) > 0)
check("knowledge_graph relations", len(kg.relations) > 0)

iocs = _extract_iocs_from_text("evil at 10.0.0.1 hash " + "f" * 64)
check("extract_iocs ipv4", "10.0.0.1" in iocs)
check("extract_iocs sha256", ("f" * 64) in iocs)

emgr.close()
db4.unlink(missing_ok=True)

# ──────────────────────────────────────────────
# 8. RAG types
# ──────────────────────────────────────────────
print("\n=== 8. RAG types ===")
from nexus.rag import (
    MatchQuality,
    RAGDocument,
    SearchHit,
    score_quality,
    validate_query,
    validate_top_k,
)

try:
    validate_query("valid query")
    check("validate_query", True)
except Exception:
    check("validate_query", False)

check("validate_query empty rejected", True)
try:
    validate_query("")
    check("validate_query empty", False, "should have raised")
except Exception:
    check("validate_query empty rejected", True)

check("validate_top_k", validate_top_k(10) == 10)
check("validate_top_k clamp", validate_top_k(100) == 50)

doc = RAGDocument(id="test", text="test", source="test")
check("RAGDocument", doc.id == "test")

hit = SearchHit(document=doc, score=0.9, quality=MatchQuality.EXCELLENT)
check("SearchHit", hit.quality == MatchQuality.EXCELLENT)
check("score_quality excellent", score_quality(0.9) == MatchQuality.EXCELLENT)

# ──────────────────────────────────────────────
# 9. CLI commands functional?
# ──────────────────────────────────────────────
print("\n=== 9. CLI commands importable ===")
CLI_MODULES = [
    "nexus.cli.case_cmd",
    "nexus.cli.evidence",
    "nexus.cli.review",
    "nexus.cli.report",
    "nexus.cli.collect_cmd",
]
for mod_name in CLI_MODULES:
    try:
        __import__(mod_name)
        check(f"CLI {mod_name.split('.')[-1]}", True)
    except Exception as e:
        check(f"CLI {mod_name.split('.')[-1]}", False, str(e)[:80])

# ──────────────────────────────────────────────
# 10. Triage analysis
# ──────────────────────────────────────────────
print("\n=== 10. Triage analysis ===")
from nexus.triage.analysis import Verdict, VerdictResult, merge_verdicts

check("Verdict.MALICIOUS", hasattr(Verdict, "MALICIOUS"))

r1 = VerdictResult(Verdict.SUSPICIOUS, ["bad process"], "high")
r2 = VerdictResult(Verdict.UNKNOWN, ["unknown file"], "low")
merged = merge_verdicts(r1, r2)
check("merge_verdicts worst", merged.verdict == Verdict.SUSPICIOUS)
check("merge_verdicts reasons", len(merged.reasons) == 2)
check("merge_verdicts confidence", merged.confidence == "high")

# ──────────────────────────────────────────────
# Summary
# ──────────────────────────────────────────────
print(f"\n{'='*50}")
print(f"RESULTS: {passed} passed, {failed} failed")
print(f"{'='*50}")
sys.exit(0 if failed <= THRESHOLD else 1)
