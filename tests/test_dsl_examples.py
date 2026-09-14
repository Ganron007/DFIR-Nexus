"""WP 9.8 — N4 DSL few-shot pattern pack tests."""
from __future__ import annotations

from nexus.knowledge.loader import dsl_prompt_block, get_query_examples
from nexus.langgraph.query_dsl import parse_query


def test_query_examples_pack_loads():
    data = get_query_examples()
    assert data, "dsl/query_examples.yaml should load"
    assert data.get("grammar")
    assert isinstance(data.get("schema"), list) and data["schema"]
    examples = data.get("examples") or []
    assert len(examples) >= 12, f"expected a useful few-shot set, got {len(examples)}"


def test_every_example_parses():
    """Every few-shot DSL query must pass the real N4 parser."""
    failures = []
    for ex in get_query_examples().get("examples") or []:
        dsl = str((ex or {}).get("dsl") or "")
        nl = str((ex or {}).get("nl") or "")
        try:
            q = parse_query(dsl)
            assert not q.is_empty(), f"empty parse for {dsl!r}"
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{nl!r} -> {dsl!r}: {exc}")
    assert not failures, "unparseable DSL examples:\n" + "\n".join(failures)


def test_examples_cover_all_fields():
    blob = " ".join(
        str((ex or {}).get("dsl") or "")
        for ex in get_query_examples().get("examples") or []
    ).lower()
    for field in ("family:", "event:", "host:", "user:", "file:", "regex:"):
        assert field in blob, f"no example demonstrates {field}"


def test_dsl_prompt_block_shape():
    block = dsl_prompt_block()
    assert "family:" in block
    assert "Examples" in block
    assert block.count("->") >= 5
