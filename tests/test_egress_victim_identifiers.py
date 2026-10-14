"""D192 (operator decision 2026-10-15): LLM egress tokenizes the case's own identifiers only.

The shape-based anonymizer turned 382 distinct values of one real Mode 1 prompt into tokens,
290 of them "hosts" such as powershell.exe, plus every path and hash. The victim-aware egress
reads the case's hosts, domains and accounts from its index (domains are those whose accounts
carry an S-1-5-21 SID; user names are those with a RID of 1000 or more) and leaves the evidence
readable: file names, paths, commands, hashes, public addresses and external domains.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus.llm import egress
from nexus.llm.victim_identifiers import IDENTIFIERS_FILE, known_from_values

PRINCIPALS = [
    ("corp", "jdoe", "S-1-5-21-1-2-3-1136"),
    ("CORP.LOCAL", "jdoe", "S-1-5-21-1-2-3-1136"),
    ("corp", "FS01$", "S-1-5-21-1-2-3-1201"),
    ("WS01", "Administrator", "S-1-5-21-9-8-7-500"),
    ("NT AUTHORITY", "SYSTEM", "S-1-5-18"),
    ("Window Manager", "DWM-1", "S-1-5-90-0-1"),
    ("WORKGROUP", "WS02$", "S-1-5-18"),
]
HOSTS = ["ws01.corp.local", "-", "WS01", "ws01", "localhost"]


def test_identifiers_come_from_sids_not_from_a_list_of_names():
    known = known_from_values(HOSTS, PRINCIPALS)
    assert {h.lower() for h in known.hosts} == {"ws01.corp.local", "ws01", "fs01"}
    assert {d.lower() for d in known.internal_domains} == {"corp.local", "corp", "ws01"}
    assert [c.value for c in known.custom] == ["jdoe"]  # Administrator is RID 500: no one
    names = {v.lower() for v in [*known.hosts, *known.internal_domains]}
    assert not names & {"nt authority", "window manager", "workgroup", "-", "localhost"}


@pytest.fixture()
def victim_case(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-EGRESS"
    (case / "analysis").mkdir(parents=True)
    known = known_from_values(HOSTS, PRINCIPALS)
    (case / "analysis" / IDENTIFIERS_FILE).write_text(json.dumps({
        "version": 1, "index_built_at": "",
        "known": {"hosts": known.hosts, "internal_domains": known.internal_domains,
                  "users": [c.value for c in known.custom]},
        "tokens": {},
    }), encoding="utf-8")
    return case


SHA256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
PROMPT = (
    "4624 logon corp\\jdoe from ws01.corp.local (10.1.2.3) to 8.8.8.8; "
    "C:\\Users\\jdoe\\AppData\\Local\\Temp\\mimikatz.exe sha256 " + SHA256 + " "
    "SID S-1-5-21-1-2-3-1136, mail jdoe@corp.local, beacon to evil.example.org, "
    "NT AUTHORITY\\SYSTEM ran powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBi "
    "(rule text: DET0593\\nTechnique)"
)


def test_the_case_identifiers_are_tokenized_and_the_evidence_is_not(victim_case: Path):
    out = egress.anonymize_text(PROMPT, victim_case)
    for identifier in ("jdoe", "corp", "ws01", "10.1.2.3", "1-2-3-1136"):
        assert identifier not in out.lower(), (identifier, out)
    for evidence in ("mimikatz.exe", "\\AppData\\Local\\Temp\\", "C:\\Users\\", "8.8.8.8", SHA256,
                     "evil.example.org", "NT AUTHORITY\\SYSTEM", "powershell.exe",
                     "-EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBi", "DET0593\\nTechnique", "-1136"):
        assert evidence in out, (evidence, out)
    assert egress.restore_text(out, victim_case) == PROMPT


def test_a_value_keeps_its_token_across_calls(victim_case: Path):
    first = egress.anonymize_text("host ws01.corp.local", victim_case)
    second = egress.anonymize_text("again ws01.corp.local and corp\\jdoe", victim_case)
    assert first.split()[-1] == second.split()[1]
    saved = json.loads((victim_case / "analysis" / IDENTIFIERS_FILE).read_text(encoding="utf-8"))
    assert "ws01.corp.local" in saved["tokens"].values()


def test_an_account_inside_json_text_is_tokenized(victim_case: Path):
    out = egress.anonymize_text(json.dumps({"user": "corp\\jdoe", "host": "WS01"}), victim_case)
    assert "jdoe" not in out and "corp" not in out.lower() and "WS01" not in out


def test_a_streamed_token_split_across_chunks_is_restored(victim_case: Path):
    out = egress.anonymize_text("on ws01.corp.local", victim_case)
    token = out.split()[-1]
    restorer = egress._StreamRestorer(victim_case)
    cut = len(token) // 2
    text = restorer.push("seen " + token[:cut]) + restorer.push(token[cut:] + " done") + restorer.flush()
    assert text == "seen ws01.corp.local done"


def test_a_case_whose_index_cannot_be_read_keeps_the_shape_based_anonymizer(tmp_path: Path):
    case = tmp_path / "CASE-NOINDEX"
    (case / "analysis").mkdir(parents=True)
    out = egress.anonymize_text("logon from ws01.corp.local", case)
    assert "ws01.corp.local" not in out and "{{HOST_" in out
    assert egress.restore_text(out, case) == "logon from ws01.corp.local"
