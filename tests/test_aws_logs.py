"""D275, D277, D278: sample S07's AWS logs are read (2026-10-18).

S07 is an AWS account's CloudTrail, VPC flow logs and S3 server access logs: 3,960 files, of which the importer pass
read 13. CloudTrail and the flow logs arrive gzipped and no importer read gzip; no importer read flow logs or S3 access
logs at all. The lines are S07's, verbatim; the gzip is made here, as AWS writes it.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from nexus.ingest.detect import detect_format
from nexus.ingest.schemas import ArtifactSource
from nexus.langgraph.timeline_merge import gunzipped_working_copy, ingest_into_case

FIXTURES = Path(__file__).parent / "fixtures"
VPC = [
    "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action "
    "log-status",
    "2 342082656213 eni-0ad40226b07c9fe75 10.0.0.82 91.189.89.199 53165 123 17 1 76 1627483093 1627483150 REJECT OK",
    "2 342082656213 eni-0ad40226b07c9fe75 162.142.125.154 10.0.0.82 39552 18047 6 1 44 1627483093 1627483150 REJECT "
    "OK",
]
S3 = [
    '701a23465480cca98d94a2f326ad22a9c26fec7b7a9c17ee8e10e8d50a91878e falsimentis-eng [29/Jul/2021:13:09:55 +0000] '
    '3.238.12.183 arn:aws:iam::342082656213:user/jmerckle T7X3D7QX7X6GZ0NN REST.GET.BUCKET - "GET '
    '/?list-type=2&prefix=&delimiter=%2F&encoding-type=url HTTP/1.1" 200 - 7983 - 37 36 "-" "aws-cli/2.2.23 '
    'Python/3.8.8 Linux/4.14.238-182.422.amzn2.x86_64 exe/x86_64.amzn.2 prompt/off command/s3.ls" - '
    'nWH0+ldF4vxbvpaMka7kLbRAFPVRP/QL9KfZwUP/lfVT12TExikGmfIKLT3Aac13Pyr+1ww+GaA= SigV4 '
    'ECDHE-RSA-AES128-GCM-SHA256 AuthHeader falsimentis-eng.s3.us-west-1.amazonaws.com TLSv1.2 -',
]


@pytest.fixture
def case(tmp_path):
    case_dir = tmp_path / "CASE-S07"
    (case_dir / "audit").mkdir(parents=True)
    return case_dir


def _stored(case_dir: Path) -> list[dict]:
    text = (case_dir / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _gz(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(gzip.compress(text.encode("utf-8")))
    return path


def test_a_gzipped_cloudtrail_file_is_read_through_its_working_copy(case, tmp_path):
    record = (FIXTURES / "d275_cloudtrail_record.json").read_text(encoding="utf-8")
    src = _gz(tmp_path / "ev" / "342082656213_CloudTrail_us-west-1_20210728T1530Z_UdeZkqf59OzXn8KY.json.gz", record)
    info = ingest_into_case(src, case)
    assert info["source"] == "cloudtrail" and info["artifacts"] == 1 and info["path"] == str(src)
    work = gunzipped_working_copy(src, case)
    assert work.name.endswith(".json") and "_staged" in work.parts, "a staging copy, never indexed as rows"
    assert _stored(case)[0]["timestamp"].startswith("2021-07-28T15:28:12")


def test_a_file_that_is_not_gzip_has_no_working_copy(case, tmp_path):
    plain = tmp_path / "ev" / "notes.txt"
    plain.parent.mkdir(parents=True)
    plain.write_text("x", encoding="utf-8")
    assert gunzipped_working_copy(plain, case) is None


def test_a_vpc_flow_log_is_read_flow_by_flow(case, tmp_path):
    src = _gz(tmp_path / "ev" / "342082656213_vpcflowlogs_us-west-1_fl-05f68526597e740af_20210728T1435Z_1a0796f0.log.gz",
              "\n".join(VPC) + "\n")
    info = ingest_into_case(src, case)
    assert info["source"] == "aws_vpc_flow" and info["artifacts"] == 2
    first = _stored(case)[0]
    assert first["timestamp"].startswith("2021-07-28T14:38:13")  # start = 1627483093
    assert (first["source_ip"], first["source_port"], first["dest_ip"], first["dest_port"]) == (
        "10.0.0.82", 53165, "91.189.89.199", 123)
    assert first["protocol"] == "udp" and first["action"] == "reject"


def test_an_s3_access_log_is_read_request_by_request(case, tmp_path):
    src = tmp_path / "ev" / "2021-07-29-14-12-58-9643D3A6992B04CB"
    src.parent.mkdir(parents=True)
    src.write_text("\n".join(S3) + "\n", encoding="utf-8")
    assert detect_format(src) == ArtifactSource.AWS_S3_ACCESS
    info = ingest_into_case(src, case)
    assert info["artifacts"] == 1
    row = _stored(case)[0]
    assert row["timestamp"].startswith("2021-07-29T13:09:55")
    assert row["user"] == "arn:aws:iam::342082656213:user/jmerckle" and row["source_ip"] == "3.238.12.183"
    assert row["action"] == "REST.GET.BUCKET" and row["raw"]["http_status"] == "200"
    assert row["raw"]["user_agent"].startswith("aws-cli/2.2.23")
