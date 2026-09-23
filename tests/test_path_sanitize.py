"""Machine-path normalization in derived text (index/scan) — proof tests.

Live report (2026-09-23): parsers write the absolute source-file path into
their output CSVs (EvtxECmd ``SourceFile`` etc.). Indexing that column put
``C:\\STUDY\\Github\\...`` into every scan/entity pass. Derived text is now
normalized to ``<repo>``/``<case>``/``<evidence>`` placeholders; raw evidence
files are never modified and genuine evidence paths are preserved.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPO_EVIDENCE = str(
    REPO_ROOT / "Evidence-files" / "ES-Mapping" / "evidence" / "evtx" / "System.evtx"
)
CMD = str(Path("C:/Windows/System32/cmd.exe"))  # C:\Windows\System32\cmd.exe on Windows


def test_sanitize_machine_paths_unit(tmp_path):
    from nexus.langgraph.path_sanitize import sanitize_machine_paths

    case = tmp_path / "CASE-PATH"
    case.mkdir()
    text = f"row has {REPO_EVIDENCE} and {case}\\extractions\\a.csv and genuine {CMD}"
    out = sanitize_machine_paths(text, case)

    assert "STUDY" not in out
    assert "CADRE-Platform" not in out
    assert "<repo>" in out and "<case>" in out
    assert CMD in out  # evidence content untouched


def _case_with_source_column(tmp_path: Path) -> Path:
    case = tmp_path / "CASE-SRC"
    (case / "extractions" / "evtxecmd").mkdir(parents=True)
    (case / "extractions" / "evtxecmd" / "out.csv").write_text(
        f"TimeCreated,EventId,Payload,SourceFile\n"
        f"2020-11-14 03:56:46,4688,{CMD} -k netsvcs,{REPO_EVIDENCE}\n",
        encoding="utf-8",
    )
    return case


def test_scan_never_matches_machine_paths(tmp_path):
    from nexus.langgraph.query_pack import parse_window, scan_extractions

    case = _case_with_source_column(tmp_path)
    start, end = parse_window("")

    machine_hits = scan_extractions(case, ["STUDY", "CADRE-Platform"], (start, end))
    assert machine_hits == [], "the analysis host's path must never be searchable"

    genuine_hits = scan_extractions(case, ["netsvcs"], (start, end))
    assert genuine_hits, "evidence content must still match"
    assert "STUDY" not in genuine_hits[0]["text"]
    assert "<source>" in genuine_hits[0]["text"]
    assert CMD in genuine_hits[0]["text"]


def test_indexed_docs_are_sanitized(tmp_path):
    from nexus.langgraph.case_index import iter_index_docs

    case = _case_with_source_column(tmp_path)
    docs = list(iter_index_docs(case))
    assert docs
    texts = [str(d.get("text") or "") for d in docs]
    fields = [str(v) for d in docs for v in ((d.get("fields") or {}).values())]
    assert all("STUDY" not in t and "CADRE-Platform" not in t for t in texts), texts
    assert any(CMD in t for t in texts), texts  # genuine evidence paths stay intact
    # The SourceFile column carried the machine path: replaced outright, so it
    # can never leak even when the evidence lived outside every known root.
    assert any("<source>" in v for v in fields), fields
    assert any("<source>" in t for t in texts), texts


def test_source_columns_are_replaced_regardless_of_root(tmp_path):
    """A source column value is routing metadata wherever the file lived."""
    from nexus.langgraph.path_sanitize import sanitize_field_map, sanitize_row_text

    line = r"1,2020-11-14,D:\anywhere\case\System.evtx,C:\Users\fredr\secret.docx"
    fields = {
        "Row": "1",
        "TimeCreated": "2020-11-14",
        "SourceFile": r"D:\anywhere\case\System.evtx",       # machine (any root)
        "TargetFilename": r"C:\Users\fredr\secret.docx",      # evidence content
    }
    out_line = sanitize_row_text(line, fields, tmp_path, family="evtxecmd")
    out_fields = sanitize_field_map(fields, tmp_path, family="evtxecmd")

    assert "D:\\anywhere" not in out_line and "<source>" in out_line
    assert out_fields["SourceFile"] == "<source>"
    assert out_fields["TargetFilename"] == r"C:\Users\fredr\secret.docx"
    assert r"C:\Users\fredr\secret.docx" in out_line  # evidence preserved


def test_family_scoped_source_columns(tmp_path):
    from nexus.langgraph.path_sanitize import sanitize_field_map

    chainsaw = sanitize_field_map(
        {"path": r"E:\evidence\System.evtx", "CommandLine": "evil.exe"},
        tmp_path, family="chainsaw",
    )
    assert chainsaw["path"] == "<source>"
    assert chainsaw["CommandLine"] == "evil.exe"

    # Another family's `Path` column is evidence content, not provenance.
    amcache = sanitize_field_map(
        {"Path": r"C:\Users\fredr\Downloads\tool.exe"}, tmp_path, family="amcache",
    )
    assert amcache["Path"] == r"C:\Users\fredr\Downloads\tool.exe"


def test_sift_machine_prefixes_are_masked(tmp_path):
    from nexus.langgraph.path_sanitize import sanitize_machine_paths

    staging = (
        "OS:/home/sansforensics/nexus-es-mapping/evidence/evtx/System.evtx"
    )
    out = sanitize_machine_paths(staging, tmp_path)
    assert "sansforensics" not in out and "<staging>" in out
    assert "System.evtx" in out  # tail preserved

    case_store = "/home/sansforensics/.nexus/cases/CASE-ABC123/extractions/a.csv"
    out2 = sanitize_machine_paths(case_store, tmp_path)
    assert "sansforensics" not in out2
    assert "CASE-ABC123" not in out2 and "<case>" in out2

    symbols = "file:///home/sansforensics/.cache/volatility3/symbols/ntkrnlmp.pdb"
    out3 = sanitize_machine_paths(symbols, tmp_path)
    assert "sansforensics" not in out3 and "<home>" in out3
    assert "ntkrnlmp.pdb" in out3

    # Evidence-internal POSIX paths are NOT machine paths.
    evidence = "/var/log/auth.log and /home/fredr/.ssh/authorized_keys"
    assert sanitize_machine_paths(evidence, tmp_path) == evidence


def test_json_escaped_and_short_path_variants_are_masked(tmp_path):
    """Two real leaks the audit surfaced: JSON-escaped and 8.3 short paths."""
    from nexus.langgraph.path_sanitize import sanitize_machine_paths

    escaped = (
        r'{"argv":["-j","C:\\STUDY\\Github\\CADRE-Platform\\DFIR-Nexus\\Tools\\x.exe"]}'
    )
    out = sanitize_machine_paths(escaped, tmp_path)
    assert "STUDY" not in out and "CADRE-Platform" not in out and "<repo>" in out

    short = (
        r"C:\STUDY\Github\CAF47A~1\DFIR-N~1\EVIDEN~1\outputs\x.csv: missing columns"
    )
    out2 = sanitize_machine_paths(short, tmp_path)
    assert "STUDY" not in out2 and "<repo>" in out2
    assert "x.csv" in out2  # tail preserved


def test_doubled_separator_case_store_is_masked(tmp_path):
    from nexus.langgraph.path_sanitize import sanitize_machine_paths

    doubled = r"C:\\Users\\x\\.nexus\\cases\\CASE-ABC\\extractions\\a.csv"
    out = sanitize_machine_paths(doubled, tmp_path)
    assert "CASE-ABC" not in out and "<case>" in out


def test_ingest_rows_are_sanitized(tmp_path):
    from nexus.langgraph.query_pack import parse_window, scan_extractions

    case = tmp_path / "CASE-ING"
    (case / "ingest").mkdir(parents=True)
    record = {
        "source": "zeek",
        "description": f"conn from {REPO_EVIDENCE}",
        "timestamp": "2020-11-14T03:56:46Z",
        "host": "WS01",
    }
    (case / "ingest" / "artifacts.jsonl").write_text(
        json.dumps(record) + "\n", encoding="utf-8"
    )
    start, end = parse_window("")
    assert scan_extractions(case, ["STUDY", "CADRE-Platform"], (start, end)) == []
    assert scan_extractions(case, ["conn"], (start, end))
