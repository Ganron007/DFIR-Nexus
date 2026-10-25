"""WO-A9 acceptance: malfind rows carry typed fields.

The live G7 image produced no malfind rows (a clean Windows memory image), so
the typed-field claim is proven on a real Volatility 3 malfind fixture instead
of left unexercised.
"""
from __future__ import annotations

import json

from nexus.ingest.df.volatility import parse_volatility_content


def test_malfind_rows_parse_with_injection_severity_and_technique():
    rows = [
        {
            "PID": 4812,
            "Process": "powershell.exe",
            "Start VPN": "0x1f0000",
            "End VPN": "0x20f000",
            "Tag": "VadS",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "CommitCharge": 1,
            "Hexdump": "4d 5a 90 00",
            "Disasm": "MZ",
        }
    ]
    artifacts = parse_volatility_content(json.dumps(rows), filename="windows.malfind.json")
    assert len(artifacts) == 1
    artifact = artifacts[0]
    assert artifact.process_name == "powershell.exe"
    assert artifact.severity.value == "high"
    assert "T1055" in artifact.technique_ids
    assert "malfind" in artifact.tags
    assert artifact.raw["row"]["Protection"] == "PAGE_EXECUTE_READWRITE"


def test_malfind_columns_are_registry_typed_for_the_vol_family():
    """The index types the columns the timeline and N4 queries read."""
    from nexus.langgraph.field_registry import merged_columns

    columns = merged_columns()
    for name, kind in (
        ("Protection", "text"),
        ("CommitCharge", "long"),
        ("Start VPN", "long"),
        ("End VPN", "long"),
        ("Tag", "text"),
        ("Hexdump", "text"),
        ("Disasm", "text"),
    ):
        assert columns[name]["type"] == kind, name
        assert "vol" in {str(f).lower() for f in columns[name]["families"]}, name
