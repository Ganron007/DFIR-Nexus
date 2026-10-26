"""Producer contracts must exclude real refused requests without relaxing consumers."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import Field

from nexus.langgraph import context_loop, es_native
from nexus.langgraph.tool_generation import response_schema
from tests.test_egress_paths import HOST, RecordingChatModel

REQUESTS = json.loads((Path(__file__).parent / "fixtures/t19_mode3_requests.json").read_text())


def field_enum(schema, kind):
    definition = schema["$defs"]["case_fields_" + kind]
    while "$ref" in definition:
        definition = schema["$defs"][definition["$ref"].rsplit("/", 1)[1]]
    return definition["enum"]


@pytest.fixture
def schema(monkeypatch):
    from tests.test_t19_query_surface import TYPES

    monkeypatch.setattr(es_native, "_field_types", lambda _: {**TYPES, "text": "text"})
    return response_schema("CASE-TEST", context_loop._TOOL_ARGS, context_loop._REQUIRED_ARGS,
                           context_loop._STRING_FIELDS_BY_TOOL)


@pytest.mark.parametrize("suffix", ["538", "637", "748"])
def test_exact_refusals_are_excluded_at_generation(schema, suffix):
    entry = next(row for row in REQUESTS if row["audit_id"].endswith("-" + suffix))
    args = copy.deepcopy(entry["params"])
    args.pop("case_id")
    reply = {"tool_calls": [{"tool": entry["tool"], "args": args}]}
    assert list(Draft202012Validator(schema).iter_errors(reply))


def test_es_names_and_final_domain_objects_remain_open(schema):
    Draft202012Validator.check_schema(schema)
    reply = {"tool_calls": [{"tool": "es_aggregate", "args": {"aggs": {
        "arbitrary investigator bucket": {"filter": {"match_all": {}}, "aggs": {
            "span": {"stats": {"field": "ts"}},
            "examples": {"top_hits": {"size": es_native.TOP_HITS_MAX}},
        }},
    }}}]}
    Draft202012Validator(schema).validate(reply)
    Draft202012Validator(schema).validate({"tool_calls": [], "claims": [{"text": "unknown"}],
                                          "dispositions": [], "pivots": [], "answer": "done"})


def test_shared_aggregate_types_and_read_signatures_are_preserved(schema):
    nodes = schema["$defs"]["aggregation"]["anyOf"]
    assert {node["required"][0] for node in nodes} == es_native._AGG_TYPES
    calls = schema["properties"]["tool_calls"]["items"]["anyOf"]
    args = {row["properties"]["tool"]["const"]: row["properties"]["args"] for row in calls}
    assert set(args) == set(context_loop._TOOL_ARGS)
    for tool, names in es_native.READ_TOOL_PARAMETERS.items():
        assert set(args[tool]["properties"]) == set(names)
        assert args[tool]["required"] == list(es_native.READ_TOOL_REQUIRED_ARGS[tool])


def test_known_field_eligibility_uses_the_consumer_rule(schema):
    assert "text" not in field_enum(schema, "terms")
    assert "ts" in field_enum(schema, "stats")
    assert "ts" in field_enum(schema, "terms")


@pytest.mark.parametrize("kind,body", [
    ("terms", {"field": "family", "size": 20}),
    ("date_histogram", {"field": "ts", "fixed_interval": "1h"}),
    ("date_range", {"field": "ts", "ranges": [{"from": "2020-01-01", "to": "2021-01-01"}]}),
    ("range", {"field": "ts", "ranges": [{"from": 0, "to": 10}]}),
    ("histogram", {"field": "ts", "interval": 1000}),
    ("composite", {"sources": [{"arbitrary source": {"terms": {"field": "family", "missing_bucket": True}}}],
                   "size": es_native.COMPOSITE_SIZE_MAX}),
    ("filter", {"term": {"family": "example"}}),
    ("filters", {"filters": {"arbitrary condition": {"match_all": {}}}, "other_bucket": True}),
    ("top_hits", {"size": es_native.TOP_HITS_MAX, "_source": ["family", "ts"], "sort": ["ts"]}),
    *[(kind, {"field": "ts"}) for kind in ("cardinality", "value_count", "min", "max", "avg", "sum", "stats")],
])
def test_every_supported_canonical_aggregation_passes_the_consumer(schema, kind, body):
    aggs = {"arbitrary bucket name": {kind: body}}
    Draft202012Validator(schema).validate({"tool_calls": [{"tool": "es_aggregate", "args": {"aggs": aggs}}]})
    es_native.validate_aggs(aggs)


def test_all_generation_field_enums_agree_with_the_consumer(schema):
    from tests.test_t19_query_surface import TYPES

    types = {**TYPES, "text": "text"}
    for kind in es_native._AGG_TYPES:
        assert set(field_enum(schema, kind)) == {
            field for field in types if not field.startswith("_")
            and not es_native.aggregation_field_problem(kind, field, types)
        }


class SchemaRecordingModel(RecordingChatModel):
    wire_options: list = Field(default_factory=list)

    @property
    def _llm_type(self):
        return "openai-chat"

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.wire_options.append(copy.deepcopy(kwargs))
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

    async def _agenerate(self, messages, stop=None, run_manager=None, **kwargs):
        self.wire_options.append(copy.deepcopy(kwargs))
        return RecordingChatModel._generate(self, messages, stop=stop, run_manager=run_manager, **kwargs)

    def _stream(self, messages, stop=None, run_manager=None, **kwargs):
        self.wire_options.append(copy.deepcopy(kwargs))
        yield from super()._stream(messages, stop=stop, run_manager=run_manager, **kwargs)

    async def _astream(self, messages, stop=None, run_manager=None, **kwargs):
        self.wire_options.append(copy.deepcopy(kwargs))
        async for chunk in super()._astream(messages, stop=stop, run_manager=run_manager, **kwargs):
            yield chunk


@pytest.mark.parametrize("method", ["invoke", "ainvoke", "stream", "astream"])
def test_schema_field_identifiers_are_tokenized_on_every_entry(method, tmp_path, monkeypatch):
    import asyncio

    from langchain_core.messages import AIMessage

    from nexus.langgraph.tool_generation import generation_format
    from nexus.llm.egress import anonymize_text, attach_egress, egress_case

    case = tmp_path / "CASE-SCHEMA"
    (case / "analysis").mkdir(parents=True)
    (case / "CASE.yaml").write_text("id: CASE-SCHEMA\n")
    field = "fields." + HOST
    monkeypatch.setattr(es_native, "_field_types", lambda _: {field: "keyword", "ts": "date"})
    schema = response_schema("CASE-SCHEMA", context_loop._TOOL_ARGS, context_loop._REQUIRED_ARGS,
                             context_loop._STRING_FIELDS_BY_TOOL)
    with egress_case(case):
        token = anonymize_text(field, case)
        assert HOST not in token
        response = {"tool_calls": [], "answer": token}
        model = attach_egress(SchemaRecordingModel(script=[AIMessage(content=json.dumps(response))]))
        fmt = generation_format(model, schema)
        client = model.bind(response_format=fmt)
        messages = [{"role": "user", "content": "Syntax control"}]
        if method == "invoke":
            content = client.invoke(messages).content
        elif method == "ainvoke":
            content = asyncio.run(client.ainvoke(messages)).content
        elif method == "stream":
            content = "".join(chunk.content for chunk in client.stream(messages))
        else:
            async def drain():
                return "".join([chunk.content async for chunk in client.astream(messages)])
            content = asyncio.run(drain())
    assert json.loads(content)["answer"] == field
    assert len(model.wire_options) == 1
    wire = model.wire_options[0]["response_format"]
    assert HOST not in json.dumps(wire)
    assert field in field_enum(schema, "terms")  # no mutation of local contract
    assert wire["json_schema"]["schema"]["type"] == "object"


def test_real_loop_binds_persists_and_consumes_the_contract(schema, tmp_path, monkeypatch):
    from langchain_core.messages import AIMessage

    from nexus.langgraph import prompt_budget
    from tests.test_context_loop import _fake_backbone

    case = tmp_path / "CASE-LOOP"
    (case / "analysis").mkdir(parents=True)
    calls = []
    _fake_backbone(monkeypatch, calls)
    records = []
    original = prompt_budget.persist_context

    def capture(*args, **kwargs):
        records.append((copy.deepcopy(args[3]), copy.deepcopy(kwargs["meta"])))
        return original(*args, **kwargs)

    monkeypatch.setattr(prompt_budget, "persist_context", capture)
    model = SchemaRecordingModel(script=[
        AIMessage(content=json.dumps({"tool_calls": [{"tool": "es_search", "args": {
            "query": {"match_all": {}}, "size": 5,
        }}]})),
        AIMessage(content=json.dumps({"tool_calls": [], "claims": [], "dispositions": [], "pivots": []})),
    ])
    result = context_loop.run_context_loop(case_dir=case, case_id="CASE-LOOP", question="inspect",
        model=model, terminal_keys=("claims", "dispositions"), allowed_tools=("es_search",),
        budget=context_loop.LoopBudget(rounds=3, calls=2, seconds=60))
    assert result["finish_reason"] == "answer_terminal"
    assert len(result["hits"]) == 2
    assert len(model.wire_options) == 2
    for report, meta in records:
        fmt = meta["response_format"]
        assert fmt["json_schema"]["strict"] is True
        tools = fmt["json_schema"]["schema"]["properties"]["tool_calls"]["items"]["anyOf"]
        assert [item["properties"]["tool"]["const"] for item in tools] == ["es_search"]
        assert report["generation_contract_chars"] > 0
        assert report["budget_chars"] + report["generation_contract_chars"] + report["system_chars"] == prompt_budget.budget_chars(window=report["ceiling_tokens"])
    assert all("response_format" in path.read_text() for path in (case / "analysis/llm_context").glob("*.md"))


def test_schema_ignoring_transport_fails_without_a_free_json_retry(schema):
    from jsonschema import ValidationError
    from langchain_core.messages import AIMessage

    from nexus.langgraph.tool_generation import generation_format

    model = SchemaRecordingModel(script=[AIMessage(content=json.dumps({"tool_calls": [
        {"tool": "es_search", "args": {"query": {"match_all": {}}, "size": 0}},
    ]}))])
    with pytest.raises(ValidationError):
        context_loop._call_model(model, [{"role": "user", "content": "syntax"}],
                                 response_format=generation_format(model, schema))
    assert len(model.wire_options) == 1


def test_schema_anonymization_discovers_hostless_case_identifiers_once(schema, tmp_path, monkeypatch):
    from nexus.llm import egress, victim_identifiers

    case = tmp_path / "CASE-HOSTLESS"
    (case / "analysis").mkdir(parents=True)
    discovery_calls = []

    def no_hosts(case_id):
        discovery_calls.append(case_id)
        return None

    monkeypatch.setattr(victim_identifiers, "derive_known_entities", no_hosts)
    fmt = {"type": "json_schema", "json_schema": {"schema": schema}}
    egress._anonymize_generation_options({"response_format": fmt}, case)
    assert discovery_calls == ["CASE-HOSTLESS"]


@pytest.mark.parametrize("victim_aware", [False, True])
def test_batch_preserves_scalar_tokens_and_restoration(victim_aware, tmp_path, monkeypatch):
    from nexus.analysis.anonymize import CustomEntity, KnownEntities
    from nexus.llm import egress, victim_identifiers

    known = KnownEntities(hosts=[HOST], internal_domains=["corp.local"],
                          custom=[CustomEntity("alice", "USER")]) if victim_aware else None
    monkeypatch.setattr(victim_identifiers, "derive_known_entities", lambda _: known)
    scalar_case, batch_case = tmp_path / "CASE-SCALAR", tmp_path / "CASE-BATCH"
    for case in (scalar_case, batch_case):
        (case / "analysis").mkdir(parents=True)
    texts = ["fields." + HOST, "10.1.2.3", "alice@corp.local", r"C:\Users\alice\file.txt",
             "legitimate.exe", "string", "fields." + HOST]
    scalar = [egress.anonymize_text(text, scalar_case) for text in texts]
    owner, method = (victim_identifiers, "_engine") if victim_aware else (egress, "load_anonymizer")
    real_engine = getattr(owner, method)
    engines = []

    def record_engine(*args, **kwargs):
        engines.append(True)
        return real_engine(*args, **kwargs)

    monkeypatch.setattr(owner, method, record_engine)
    batch = egress.anonymize_texts(texts, batch_case)
    assert len(engines) == 1
    assert batch == scalar
    assert [egress.restore_text(text, batch_case) for text in batch] == texts
    name = "egress_identifiers.json" if victim_aware else "egress_tokens.json"
    scalar_tokens = json.loads((scalar_case / "analysis" / name).read_text())
    batch_tokens = json.loads((batch_case / "analysis" / name).read_text())
    assert scalar_tokens.get("tokens", scalar_tokens) == batch_tokens.get("tokens", batch_tokens)
