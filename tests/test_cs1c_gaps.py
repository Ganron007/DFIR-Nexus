"""WO-CS1c (§0 35m): the last common-schema gaps, on verbatim real rows.

1. a 4104 ScriptBlockText keeps up to 32 KB;
2. LECmd/JLECmd paths are FIRST-non-empty (never a join — a join produced
   `Unmapped GUID: ...\\C:\\Users\\...`);
3. Sysmon 22 gives ecs.dns.question.name;
4. the standard EVTX set does not select usb_device_intrusion (third round);
6. a `-` placeholder never fills an ecs field.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))


def _norm(fam, fields, record=None):
    from nexus.langgraph.ecs_normalize import normalize
    return normalize(fam, fields, record)


def test_scriptblocktext_keeps_up_to_32k():
    """WO-CS1c item 1: a real 20,411-char script block is not cut at 4,096."""
    long_text = "A" * 20411
    fields = {"EventId": "4104", "Channel": "Microsoft-Windows-PowerShell/Operational",
              "Payload": json.dumps({"EventData": {"Data": [
                  {"@Name": "ScriptBlockText", "#text": long_text}]}})}
    ecs = _norm("evtxecmd", fields)
    sbt = ecs["winlog"]["event_data"]["ScriptBlockText"]
    assert len(sbt) == 20411, len(sbt)  # < 32 KB -> kept whole
    assert sbt == long_text


def test_scriptblocktext_is_cut_at_32k_not_4k():
    over = "B" * 40000
    fields = {"EventId": "4104", "Channel": "Microsoft-Windows-PowerShell/Operational",
              "Payload": json.dumps({"EventData": {"Data": [
                  {"@Name": "ScriptBlockText", "#text": over}]}})}
    ecs = _norm("evtxecmd", fields)
    assert len(ecs["winlog"]["event_data"]["ScriptBlockText"]) == 32768


def _map():
    from nexus.langgraph.ecs_normalize import load_ecs_map
    return load_ecs_map()


def test_lecmd_paths_are_first_non_empty_not_a_join():
    """WO-CS1c item 2: the first non-empty column wins; the rest never concat."""
    fields = {"LocalPath": r"C:\Users\bob\file.txt",
              "NetworkPath": r"\\server\share\file.txt",
              "TargetIDAbsolutePath": r"C:\old\target.txt"}
    ecs = _norm("lecmd", fields)
    assert ecs["file"]["path"] == r"C:\Users\bob\file.txt"


def test_lecmd_falls_through_to_the_next_non_empty():
    fields = {"LocalPath": "", "NetworkPath": r"\\server\share\f.txt",
              "TargetIDAbsolutePath": r"C:\old\t.txt"}
    ecs = _norm("lecmd", fields)
    assert ecs["file"]["path"] == r"\\server\share\f.txt"


def test_jlecmd_no_join_of_two_paths():
    """The reviewer's exact broken shape: two absolute paths concatenated."""
    fields = {"LocalPath": r"C:\Program Files (x86)",
              "TargetIDAbsolutePath": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"}
    ecs = _norm("jlecmd", fields)
    p = ecs["file"]["path"]
    assert p.count("C:") == 1, p


def test_mftecmd_still_joins_parent_and_name():
    """The join is MFTECmd's own transform (ParentPath + FileName)."""
    fields = {"ParentPath": r"C:\Users\bob", "FileName": "mimikatz.exe"}
    ecs = _norm("mftecmd", fields)
    assert ecs["file"]["path"] == r"C:\Users\bob\mimikatz.exe"
    assert ecs["file"]["name"] == "mimikatz.exe"


def test_the_join_transform_is_explicit_per_family():
    """'join' must be declared in the map, never the default (WO-CS1c item 2)."""
    mfte = (_map().get("family_columns") or {}).get("mftecmd") or {}
    assert str(mfte.get("__path_transform__")) == "join"
    for fam in ("lecmd", "jlecmd", "sbecmd", "rbcmd"):
        table = (_map().get("family_columns") or {}).get(fam) or {}
        assert str(table.get("__path_transform__") or "") != "join", fam


def test_sysmon_22_dns_question_name():
    """WO-CS1c item 3: Sysmon 22 restored (QueryName + Image)."""
    fields = {"EventId": "22", "Channel": "Microsoft-Windows-Sysmon/Operational",
              "Payload": json.dumps({"EventData": {"Data": [
                  {"@Name": "QueryName", "#text": "evil.example.com"},
                  {"@Name": "Image", "#text": r"C:\Windows\System32\nslookup.exe"}]}})}
    ecs = _norm("evtxecmd", fields)
    assert ecs["dns"]["question"]["name"] == "evil.example.com"
    assert ecs["process"]["executable"] == r"C:\Windows\System32\nslookup.exe"


def test_sysmon_22_rules_do_not_fire_on_other_channels():
    fields = {"EventId": "22", "Channel": "Security",
              "Payload": json.dumps({"EventData": {"Data": [
                  {"@Name": "QueryName", "#text": "x"}]}})}
    ecs = _norm("evtxecmd", fields)
    assert "dns" not in ecs, ecs


def test_dash_placeholder_never_fills_an_ecs_field():
    """WO-CS1c item 6: a 4624 with no IpAddress marks it `-` in the Payload."""
    fields = {"EventId": "4624", "Channel": "Security",
              "Payload": json.dumps({"EventData": {"Data": [
                  {"@Name": "TargetUserName", "#text": "bob"},
                  {"@Name": "IpAddress", "#text": "-"},
                  {"@Name": "LogonType", "#text": "5"}]}})}
    ecs = _norm("evtxecmd", fields)
    assert "ecs.source.ip" not in _flat(ecs), _flat(ecs)
    assert ecs["user"]["target"]["name"] == "bob"


def _flat(node, prefix="ecs", out=None):
    out = {} if out is None else out
    for k, v in (node or {}).items():
        key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            _flat(v, key, out)
        else:
            out[key] = v
    return out


def test_the_standard_evtx_set_does_not_select_usb():
    """WO-CS1c item 4 (third round): pinned on the reviewer's exact set."""
    from nexus.knowledge.skills import skills_for
    sel = [s.get("skill") for s in skills_for(
        families=["evtxecmd", "hayabusa", "chainsaw", "security", "system"], limit=8)]
    assert "usb_device_intrusion" not in sel, sel
