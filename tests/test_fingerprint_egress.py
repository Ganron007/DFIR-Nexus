"""Pre-processed CSV headers and stable LLM tokens."""
from __future__ import annotations

from nexus.ingest.fingerprint import family_for_csv_header
from nexus.llm.egress import anonymize_text, restore_text, restore_tool_calls


def test_evtxecmd_header_is_recognized():
    header = "RecordNumber,EventRecordId,TimeCreated,MapDescription,PayloadData1"
    assert family_for_csv_header(header) == "evtxecmd"


def test_generic_csv_is_not_a_tool():
    assert family_for_csv_header("name,value,note") is None


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
