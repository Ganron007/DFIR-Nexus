"""The ingest store is deduplicated without re-reading the whole store on every append (2026-10-11).

Reproduced on CASE-C5B04D31: the importer stage on one volume made thousands of appends, and each one
re-parsed the whole artifacts.jsonl to build its duplicate set (timeline_merge.append_ingest_artifacts).
The keys are now read once and kept while the file is unchanged.
"""
import json


def _artifact(description: str):
    from nexus.ingest.schemas import Artifact

    return Artifact.from_dict({
        "id": description, "source": "suricata", "artifact_type": "http",
        "severity": "informational", "timestamp": "2026-08-11T23:10:37+00:00",
        "source_ip": "10.0.0.5", "dest_ip": "10.0.0.6", "source_port": 5000,
        "dest_port": 80, "protocol": "tcp", "description": description,
    })


def _rows(case):
    return (case / "ingest" / "artifacts.jsonl").read_text(encoding="utf-8").strip().splitlines()


def test_overlapping_appends_across_many_calls_store_each_event_once(tmp_path):
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    case = tmp_path / "CASE-DUP1"
    case.mkdir()
    append_ingest_artifacts(case, [_artifact("a"), _artifact("b")])
    append_ingest_artifacts(case, [_artifact("b"), _artifact("c")])
    append_ingest_artifacts(case, [_artifact("a"), _artifact("c"), _artifact("d")])

    assert len(_rows(case)) == 4


def test_a_row_written_by_another_writer_is_seen_and_not_stored_twice(tmp_path):
    from nexus.langgraph.timeline_merge import append_ingest_artifacts

    case = tmp_path / "CASE-DUP2"
    case.mkdir()
    append_ingest_artifacts(case, [_artifact("a")])
    # Another writer appends a row directly: the size and mtime change, so the cache must not be trusted.
    other = _artifact("external")
    with (case / "ingest" / "artifacts.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(other.to_dict(), default=str) + "\n")

    append_ingest_artifacts(case, [_artifact("external"), _artifact("b")])

    assert len(_rows(case)) == 3


def test_a_warm_append_does_not_parse_the_whole_store_again(tmp_path, monkeypatch):
    from nexus.langgraph import timeline_merge

    case = tmp_path / "CASE-DUP3"
    case.mkdir()
    timeline_merge.append_ingest_artifacts(case, [_artifact(f"row-{i}") for i in range(200)])

    parsed = {"n": 0}
    real_loads = json.loads

    def counting_loads(text, *args, **kwargs):
        parsed["n"] += 1
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(json, "loads", counting_loads)
    timeline_merge.append_ingest_artifacts(case, [_artifact("row-new")])

    assert parsed["n"] == 0, "the second append re-parsed the store it already had the keys for"
    assert len(_rows(case)) == 201
