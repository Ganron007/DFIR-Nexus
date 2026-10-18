"""D287: a tool family's host and user come from what its columns mean, not from their names (2026-10-18).

On sample S03 a Zeek ftp.log row carries `user` = `<unknown>`, Zeek's FTP default when no USER command was seen
(Zeek 9.0.0 base/protocols/ftp/info.zeek:34), and the rarity lead made it an account. On S04 Zeek http.log's `host`,
the HTTP Host header, was the row's host. The rows are read in place from the samples' own Zeek output (they carry
personal data and are not committed); the tests skip where the samples are absent.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from nexus.langgraph.case_index import _host_user_event, _zeek_header, _zeek_row_fields
from nexus.langgraph.ecs_normalize import normalize

REPO = Path(__file__).resolve().parents[1]


def _rows(case: str, log: str) -> list[dict[str, str]]:
    found = sorted((REPO / "cases" / case / "runs").glob(f"*/sift/extractions/network/*/zeek/{log}"))
    if not found:
        pytest.skip(f"{case}'s Zeek {log} is not on this host")
    header = _zeek_header(found[-1])
    lines = found[-1].read_text(encoding="utf-8", errors="replace").splitlines()
    return [_zeek_row_fields(line, header) for line in lines if line and not line.startswith("#")]


def test_zeek_s_ftp_default_is_no_user():
    [row] = [r for r in _rows("CASE-EA24B279", "ftp.log") if r.get("user") == "<unknown>"]
    host, user, _event = _host_user_event(row, "zeek")
    assert (host, user) == ("", "")
    ecs = normalize("zeek", row)
    assert "user" not in ecs and ecs["source"]["ip"] == row["id.orig_h"], "the row keeps its other ECS fields"


def test_an_http_host_header_is_not_the_row_s_host():
    rows = [r for r in _rows("CASE-5891325B", "http.log") if r.get("host")]
    assert rows
    for row in rows:
        assert _host_user_event(row, "zeek")[0] == ""
        assert "host" not in normalize("zeek", row)


def test_an_importer_row_keeps_its_typed_slots(tmp_path):
    # A real S3 server access log line (sample S07, verbatim in tests/test_aws_logs.py) through the importer, then its
    # slots as the ingest projection passes them: the importer's `user` (the requester) is the row's user.
    import importlib.util
    import json

    from nexus.langgraph.timeline_merge import ingest_into_case

    spec = importlib.util.spec_from_file_location("aws_logs_lines", Path(__file__).parent / "test_aws_logs.py")
    aws = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aws)
    S3 = aws.S3
    src = tmp_path / "ev" / "2021-07-29-14-12-58-9643D3A6992B04CB"
    src.parent.mkdir()
    src.write_text("\n".join(S3) + "\n", encoding="utf-8")
    case = tmp_path / "CASE-S07"
    (case / "audit").mkdir(parents=True)
    ingest_into_case(src, case)
    record = json.loads((case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").splitlines()[0])
    slots = {k: str(record[k]) for k in ("source", "host", "user", "source_ip") if record.get(k)}
    assert slots["user"] == "arn:aws:iam::342082656213:user/jmerckle"
    assert _host_user_event(slots, "aws_s3_access", importer=True)[1] == slots["user"]
    assert normalize("aws_s3_access", slots, importer=True)["user"]["name"] == slots["user"]
