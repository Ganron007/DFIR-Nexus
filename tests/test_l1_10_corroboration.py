"""D226: L1.10 reads each value of a cited row with the field that holds it.

It read a short list of descriptor fields, so all five findings approved on CASE-C5B04D31 on
2026-10-15 failed it: a Defender detection names the detected file in its own event data, which the
check never read, and rows about another entity of the same claim read as mentions. The rows are the
case's, as staging attaches them (`tests/fixtures/l1_10_rows.json`).
"""
from __future__ import annotations

import json
from pathlib import Path

ROWS = json.loads((Path(__file__).parent / "fixtures" / "l1_10_rows.json").read_text(encoding="utf-8"))


def _l1_10(title: str, *rows: dict) -> dict:
    from nexus.analysis.claim_verification import _l1_10 as check

    res: dict = {}
    check({"title": title, "observation": title, "evidence": list(rows)}, res)
    return res["L1.10"]


def test_a_detection_records_the_file_in_its_own_event_data():
    from nexus.analysis.claim_verification import _row_corroboration

    assert _row_corroboration(ROWS["defender_1116_srlupdate"], ["srlupdate.exe"]) == "instance"
    result = _l1_10("Defender detected C:\Windows\System32\SRLUpdate.exe",
                    ROWS["defender_1116_srlupdate"], ROWS["hayabusa_svchost_behaviour"])
    assert result["status"] == "pass", result


def test_a_row_about_another_entity_is_context_not_a_mention():
    from nexus.analysis.claim_verification import _row_corroboration

    behaviour = ROWS["hayabusa_svchost_behaviour"]
    assert _row_corroboration(behaviour, ["srlupdate.exe"]) == "context"
    assert _row_corroboration(behaviour, ["svchost.exe"]) == "instance"


def test_a_script_that_names_an_executable_is_a_mention():
    from nexus.analysis.claim_verification import _row_corroboration

    script = ROWS["powershell_4104_script_names_netsh"]
    assert _row_corroboration(script, ["netsh.exe"]) == "mention"
    result = _l1_10("netsh.exe read the proxy settings", script)
    assert result["status"] == "fail" and "mention" in result["detail"], result
    # The script itself is what the row records.
    assert _row_corroboration(script, ["get-effectiveproxy.ps1"]) == "instance"


def test_a_row_without_parser_columns_records_its_host():
    result = _l1_10("Windows Firewall exception rules deleted on rd01.shieldbase.com",
                    ROWS["hayabusa_firewall_rule_deleted"])
    assert result["status"] == "pass", result


def test_rows_that_never_name_the_subject_do_not_corroborate_it():
    result = _l1_10("Credential dumping from LSASS on rd01.example.org", ROWS["hayabusa_svchost_behaviour"])
    assert result["status"] == "fail" and "no cited row records" in result["detail"], result
