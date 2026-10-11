"""An evidence row quotes every field of the hit, whole (operator decision, 2026-10-11).

The snapshot kept 24 fields at 240 characters each, and a detail at 500 characters, so a finding
quoted a cut copy of a 35 KB command line. The 12-row limit per finding is a separate decision.
"""

from __future__ import annotations

from nexus.langgraph.evidence_rows import evidence_rows_for_hits


def test_an_evidence_row_keeps_every_field_whole():
    fields = {f"Col{n}": f"value {n}" for n in range(30)}
    fields["Payload"] = "p" * 5000
    hit = {"family": "evtxecmd", "file": "evtx.csv", "line": 7, "text": "row text", "fields": fields}
    row = evidence_rows_for_hits([hit])[0]
    assert len(row["fields"]) == 31
    assert row["fields"]["Payload"] == "p" * 5000
    assert row["fields"]["Col29"] == "value 29"


def test_an_evidence_row_keeps_the_identity_keys_whole():
    host = "h" * 300
    hit = {"family": "evtxecmd", "file": "evtx.csv", "line": 7, "text": "row", "host": host}
    row = evidence_rows_for_hits([hit])[0]
    assert row["host"] == host
