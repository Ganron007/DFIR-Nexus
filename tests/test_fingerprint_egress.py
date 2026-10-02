"""Pre-processed CSV headers and stable LLM tokens."""
from __future__ import annotations

from nexus.ingest.fingerprint import (
    family_for_csv_header,
    place_loose_csvs,
    place_recognized_csv,
    propose_pairs,
)
from nexus.llm.egress import anonymize_text, restore_text, restore_tool_calls


def test_evtxecmd_header_is_recognized():
    header = "RecordNumber,EventRecordId,TimeCreated,MapDescription,PayloadData1"
    assert family_for_csv_header(header) == "evtxecmd"


def test_generic_csv_is_not_a_tool():
    assert family_for_csv_header("name,value,note") is None


def test_prefetch_and_registry_headers():
    assert family_for_csv_header("ExecutableName,RunCount,LastRun") == "pecmd"
    assert family_for_csv_header("HivePath,KeyPath,ValueName") == "recmd"


def test_recognized_csv_is_copied_under_its_family(tmp_path):
    source = tmp_path / "in" / "prefetch.csv"
    source.parent.mkdir()
    source.write_text("ExecutableName,RunCount,LastRun\npowershell.exe,3,2026-01-01\n", encoding="utf-8")
    placed = place_recognized_csv(source, tmp_path / "extractions")
    assert placed is not None
    assert placed.parent.name == "pecmd"
    assert source.is_file()
    assert "powershell.exe" in placed.read_text(encoding="utf-8")


def test_a_preprocessed_csv_proposes_its_raw_artifact():
    proposals = propose_pairs([
        {"name": "$LogFile", "sha256": "aa"},
        {"name": "LogFile.csv", "sha256": "bb", "recognized_family": "logfileparser"},
        {"name": "notes.csv", "sha256": "cc"},
    ])
    assert proposals == [{
        "raw_name": "$LogFile",
        "output_name": "LogFile.csv",
        "output_sha256": "bb",
        "family": "logfileparser",
    }]
    assert propose_pairs([{"name": "notes.csv", "sha256": "cc"}]) == []


def test_a_csv_dropped_at_the_ingest_root_is_placed_by_family(tmp_path):
    root = tmp_path / "ingest"
    root.mkdir()
    (root / "prefetch.csv").write_text(
        "ExecutableName,RunCount,LastRun\npowershell.exe,1,2026-01-01\n",
        encoding="utf-8",
    )
    (root / "pecmd" / "already.csv").parent.mkdir()
    (root / "pecmd" / "already.csv").write_text(
        "ExecutableName,RunCount,LastRun\nkeep.exe,1,2026-01-01\n",
        encoding="utf-8",
    )
    placed = place_loose_csvs(root)
    assert len(placed) == 1
    assert placed[0].parent.name == "pecmd"
    assert not (root / "prefetch.csv").is_file()
    assert (root / "pecmd" / "already.csv").is_file()


def test_private_ip_token_is_stable(tmp_path):
    case = tmp_path / "CASE-E"
    (case / "analysis").mkdir(parents=True)
    first = anonymize_text("logon from 10.1.1.5", case)
    second = anonymize_text("again 10.1.1.5", case)
    assert "10.1.1.5" not in first
    assert "10.1.1.5" not in second
    assert first.split()[-1] == second.split()[-1]
    assert restore_text(second, case).endswith("10.1.1.5")


def test_tool_call_arguments_round_trip(tmp_path):
    case = tmp_path / "CASE-E"
    (case / "analysis").mkdir(parents=True)
    token = anonymize_text("host 10.1.1.5", case).split()[-1]
    calls = restore_tool_calls(
        [{
            "id": "1",
            "function": {"name": "search", "arguments": '{"host": "' + token + '"}'},
        }],
        case,
    )
    assert "10.1.1.5" in calls[0]["function"]["arguments"]
    restored = restore_tool_calls([{"name": "es_search", "args": {"host": token}}], case)
    assert restored[0]["args"]["host"] == "10.1.1.5"
