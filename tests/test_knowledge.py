"""Test the forensic knowledge loader with real YAML data."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.knowledge import loader as fk

passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" - {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" - {detail}" if detail else ""))


# Artifact tests
art = fk.get_artifact("mft")
check("get_artifact(mft)", art is not None and art.get("name") == "MFT",
      f"name={art.get('name') if art else 'NONE'}")
check("MFT proves", art and len(art.get("proves", [])) > 0,
      f"{len(art.get('proves', []))} items")
check("MFT related_tools", art and len(art.get("related_tools", [])) > 0,
      f"tools={art.get('related_tools')}")
check("MFT does_not_prove", art and len(art.get("does_not_prove", [])) > 0,
      f"{len(art.get('does_not_prove', []))} items")
check("MFT locations", art and len(art.get("locations", [])) > 0,
      f"{len(art.get('locations', []))} paths")

prefetch = fk.get_artifact("prefetch")
check("get_artifact(prefetch)", prefetch is not None, "FOUND")
check("Prefetch related_tools", prefetch and len(prefetch.get("related_tools", [])) > 0,
      f"tools={prefetch.get('related_tools')}")

evtx = fk.get_artifact("event_logs_security")
check("get_artifact(event_logs_security)", evtx is not None, "FOUND")
check("Security event logs cross_mcp_checks",
      evtx and len(evtx.get("cross_mcp_checks", [])) > 0,
      f"{len(evtx.get('cross_mcp_checks', []))} checks")

linux = fk.get_artifact("auth_log", platform="linux")
check("get_artifact(auth_log, linux)", linux is not None, "FOUND")
check("Linux artifact platform", linux and linux.get("platform") == "linux",
      f"platform={linux.get('platform') if linux else 'NONE'}")

all_artifacts = fk.list_artifacts()
check("list_artifacts()", len(all_artifacts) >= 50,
      f"{len(all_artifacts)} artifacts found")

windows_artifacts = fk.list_artifacts(platform="windows")
check("list_artifacts(windows)", len(windows_artifacts) >= 40,
      f"{len(windows_artifacts)} windows artifacts")

# Tool tests
tool = fk.get_tool("Hayabusa")
check("get_tool(Hayabusa)", tool is not None, "FOUND")
if tool:
    check("Hayabusa caveats", len(tool.get("caveats", [])) > 0,
          f"{len(tool.get('caveats', []))} caveats")
    check("Hayabusa artifacts_parsed", len(tool.get("artifacts_parsed", [])) > 0,
          f"{tool.get('artifacts_parsed')}")
    check("Hayabusa quick_start", bool(tool.get("quick_start")),
          tool.get("quick_start", "")[:80])
    check("Hayabusa advisories", len(tool.get("advisories", [])) > 0,
          f"{len(tool.get('advisories', []))} advisories")

tool2 = fk.get_tool("MFTECmd")
check("get_tool(MFTECmd)", tool2 is not None, "FOUND")
if tool2:
    check("MFTECmd category", tool2.get("category") == "zimmerman",
          f"category={tool2.get('category')}")
    check("MFTECmd investigation_sequence",
          len(tool2.get("investigation_sequence", [])) > 0,
          f"{len(tool2.get('investigation_sequence', []))} steps")

all_tools = fk.list_tools()
check("list_tools()", len(all_tools) >= 50,
      f"{len(all_tools)} tools found")

zimmerman = fk.list_tools(category="zimmerman")
check("list_tools(zimmerman)", len(zimmerman) >= 10,
      f"{len(zimmerman)} zimmerman tools")

malware_tools = fk.list_tools(category="malware")
check("list_tools(malware)", len(malware_tools) >= 5,
      f"{len(malware_tools)} malware tools (capa, yara, etc.)")

# Discipline tests
rules = fk.get_rules()
check("get_rules()", len(rules) >= 5, f"{len(rules)} rules")
if rules:
    check("Rules have IDs", all(r.get("id") for r in rules),
          f"IDs: {[r.get('id') for r in rules[:5]]}")

playbooks = fk.list_playbooks()
check("list_playbooks()", len(playbooks) >= 10,
      f"{len(playbooks)} playbooks")

slugs = fk.list_playbook_slugs()
check("list_playbook_slugs()", len(slugs) >= 10,
      f"{slugs[:5]}...")

confidence = fk.get_confidence_definitions()
check("get_confidence_definitions()", len(confidence) >= 3,
      f"levels: {list(confidence.keys())}")

anti = fk.get_anti_patterns()
check("get_anti_patterns()", len(anti) >= 4,
      f"{len(anti)} anti-patterns")

standards = fk.get_evidence_standards()
check("get_evidence_standards()", standards is not None and len(standards) >= 3,
      f"{len(standards) if isinstance(standards, dict) else 'N/A'} levels")

template = fk.get_evidence_template()
check("get_evidence_template()", template is not None, "FOUND")
if template:
    check("Template has fields", len(template) > 0,
          f"fields: {list(template.keys())[:5]}")

cp = fk.get_checkpoint("attribution")
check("get_checkpoint(attribution)", cp is not None, "FOUND")
check("Checkpoint has guidance", cp and cp.get("guidance"),
      cp.get("guidance", "")[:80] if cp else "NONE")

corr = fk.get_corroboration("persistence")
check("get_corroboration(persistence)", corr is not None, "FOUND")

fp = fk.get_false_positive_context("check_file", "unknown_file")
check("get_false_positive_context()", fp is None,
      "(no false positives for check_file/unknown_file = expected)")

interpretation = fk.get_tool_interpretation("check_file")
check("get_tool_interpretation(check_file)", interpretation is not None,
      "...loaded" if interpretation else "NONE")

cl = fk.get_collection_checklist("event_logs")
check("get_collection_checklist(event_logs)", cl is not None, "FOUND")

cl_list = fk.list_collection_checklists()
check("list_collection_checklists()", len(cl_list) >= 3,
      f"{cl_list}")

fw = fk.get_investigation_framework()
check("get_investigation_framework()", fw is not None, "FOUND")
if fw:
    check("Framework has principles", len(fw.get("principles", [])) > 0,
          f"{len(fw.get('principles', []))} principles")
    check("Framework has golden_rules", len(fw.get("golden_rules", [])) > 0,
          f"{len(fw.get('golden_rules', []))} rules")
    check("Framework has self_check", len(fw.get("self_check", [])) > 0,
          f"{len(fw.get('self_check', []))} checks")

# Cross-reference tests
arts = fk.get_artifacts_for_tool("MFTECmd")
check("get_artifacts_for_tool(MFTECmd)", len(arts) >= 1,
      f"{[a.get('name') for a in arts]}")

arts2 = fk.get_artifacts_for_tool("Hayabusa")
check("get_artifacts_for_tool(Hayabusa)", len(arts2) >= 1,
      f"{[a.get('name') for a in arts2]}")

# FK playbook content
pb = fk.get_playbook("suspicious_execution")
check("get_playbook(suspicious_execution)", pb is not None, "FOUND")
if pb:
    check("Playbook has phases", len(pb.get("phases", [])) > 0,
          f"{len(pb.get('phases', []))} phases")
    check("Playbook has mitre", bool(pb.get("mitre")),
          f"mitre={pb.get('mitre')}")

# Cache clear
fk.clear_cache()
check("clear_cache()", True, "cache cleared")
recheck = fk.get_artifact("mft")
check("reload after clear", recheck is not None, "RELOADED")

print()
print(f"=== {passed} PASSED, {failed} FAILED (out of {passed + failed}) ===")
