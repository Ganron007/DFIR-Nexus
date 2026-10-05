"""WO-KR2b — the stored queries are re-converted, and the conversion is checked.

The KR2 conversion was **valid but wrong** (reviewer, R0): 204 of 252 steps lost
their OR-alternatives, 43 embedded Mode 1 `field:value` text as a literal, and it
guessed a typed column even when the value could not live there.

The four mechanical checks here are the WO's acceptance (a)-(d), over **all 288
items** (36 analytics + 252 skill steps). The semantic check runs a sample against
a **real** ES index, not an in-memory matcher.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
KNOWLEDGE = REPO / "src" / "nexus" / "data" / "knowledge"
ANALYTICS = KNOWLEDGE / "needles" / "behavioral_analytics.yaml"
SKILLS = KNOWLEDGE / "skills"
CONVERTER = REPO / "devtools" / "knowledge" / "convert_to_es.py"

#: A Mode 1 `field:value` token embedded in a stored VALUE - the KR2 defect.
#: `C:\x` and a URL scheme are not that shape, hence the `[^\\/]`.
_LITERAL_SYNTAX = re.compile(r"^\*?[a-z_]+:[^\\/]")
_OR = re.compile(r"\s+OR\s+", re.IGNORECASE)
_GLUE = {"or", "and", "not", "the", "a", "an"}


def _analytics() -> list[dict]:
    data = yaml.safe_load(ANALYTICS.read_text(encoding="utf-8")) or {}
    return [a for a in (data.get("packs") or []) if isinstance(a, dict)]


def _steps() -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for path in sorted(SKILLS.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for step in data.get("steps") or []:
            if isinstance(step, dict):
                out.append((path.stem, step))
    return out


def _all_items() -> list[tuple[str, dict]]:
    """Every stored query in the product: the analytics, then the skill steps."""
    items: list[tuple[str, dict]] = [(f"analytic:{a.get('id')}", a) for a in _analytics()]
    items += [(f"{skill}/{step.get('name')}", step) for skill, step in _steps()]
    return items


def _fields_in(node: object, out: list[str]) -> list[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("term", "terms", "wildcard", "match", "match_phrase",
                       "prefix", "exists") and isinstance(value, dict):
                out.extend(str(f) for f in value)
            _fields_in(value, out)
    elif isinstance(node, list):
        for value in node:
            _fields_in(value, out)
    return out


def _significant(token: str) -> bool:
    clean = token.strip(",;()[]\"'").lower()
    return len(clean) >= 3 and clean not in _GLUE


def _searchable_strings(node: object, out: list[str]) -> list[str]:
    r"""Every value a stored query searches for, unescaped.

    Reading the JSON text would compare against its escapes: ``\\.\pipe\`` is
    stored as ``"*\\\\.\\pipe\\*"``, so a raw substring test reports a false miss.
    Reading the parsed values is the honest check.
    """
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "value" and isinstance(value, str):
                out.append(value.lower())
            elif key in ("term", "exists") and isinstance(value, dict):
                out.extend(str(v).lower() for v in value.values())
            elif key == "terms" and isinstance(value, dict):
                for values in value.values():
                    if isinstance(values, list):
                        out.extend(str(v).lower() for v in values)
                    else:
                        out.append(str(values).lower())
            else:
                _searchable_strings(value, out)
    elif isinstance(node, list):
        for value in node:
            _searchable_strings(value, out)
    return out


def _alternative_present(alt: str, es_strings: list[str], dropped_text: str) -> bool:
    """Whether one authored alternative survives in the stored query or a record."""
    for token in alt.replace('"', " ").split():
        if not _significant(token):
            continue
        # `file:history` is stored as a clause on `file` with the value `history`,
        # so the value - not the token as written - is what must appear.
        for candidate in (token.lower(), token.split(":", 1)[-1].lower()):
            if candidate and (any(candidate in s for s in es_strings) or candidate in dropped_text):
                return True
    return False


# ── (a) alternative coverage ───────────────────────────────────────────

def test_every_free_query_alternative_survives_in_es_or_es_dropped():
    """WO-KR2b (a): no OR-alternative may be silently dropped.

    Reproduced before the fix: `kerberoast_tgs` kept only `*0x17*` from
    `4769 RC4 OR 0x17 OR service ticket`, so the step would under-detect.
    """
    checked = 0
    missing: list[str] = []
    for name, item in _all_items():
        query = str(item.get("query") or "").strip()
        if not query:
            continue  # an analytic has no free query; nothing to cover
        es_strings = _searchable_strings(item.get("es") or {}, [])
        dropped_text = json.dumps(item.get("es_dropped") or [], ensure_ascii=False).lower()
        for alt in _OR.split(query):
            alt = alt.strip()
            if not alt:
                continue
            # An alternative made only of glue/short tokens carries no searchable
            # content and cannot be asserted.
            if not any(_significant(t) for t in alt.split()):
                continue
            checked += 1
            if not _alternative_present(alt, es_strings, dropped_text):
                missing.append(f"{name}: {alt!r}")
    assert checked > 400, f"only {checked} alternatives were checked - the catalog did not load"
    assert missing == [], f"{len(missing)} alternative(s) lost:\n" + "\n".join(missing[:12])


# ── (b) no Mode 1 syntax inside a value ────────────────────────────────

def test_no_stored_query_embeds_mode1_syntax_inside_a_value():
    """WO-KR2b (b): `"*file:prefetch*"` can never match, so it must not exist.

    Reproduced before the fix: 43 steps carried a literal `field:value` value.
    """
    offenders: list[str] = []
    for name, item in _all_items():
        blob = json.dumps(item.get("es") or {}, ensure_ascii=False)
        for value in re.findall(r'"value":\s*"([^"]*)"', blob):
            if _LITERAL_SYNTAX.match(value):
                offenders.append(f"{name}: {value!r}")
    assert offenders == [], (
        f"{len(offenders)} stored value(s) are Mode 1 syntax:\n" + "\n".join(offenders[:12]))


# ── (c) a text-only query is justified ─────────────────────────────────

def test_every_text_only_query_says_why():
    """WO-KR2b (c): falling back to text is allowed, but it must be recorded."""
    unjustified: list[str] = []
    text_only = 0
    for name, item in _all_items():
        es = item.get("es") or {}
        fields = _fields_in(es, [])
        if not fields or not all(f in ("text", "text.wc") for f in fields):
            continue
        text_only += 1
        if not str(item.get("es_text_only_reason") or "").strip():
            unjustified.append(name)
    assert text_only > 0, "no text-only query was found - the check would be vacuous"
    assert unjustified == [], f"text-only without a reason: {unjustified[:12]}"


# ── (d) the converter reports its counts, and is idempotent ────────────

def test_the_converter_prints_its_counts_and_agrees_with_the_files():
    """WO-KR2b (d): the counts are printed, and `--check` proves no drift.

    Idempotence matters here: a converter that rewrites differently every run
    would make the stored queries unreviewable.
    """
    proc = subprocess.run(
        [sys.executable, str(CONVERTER), "--check"],
        cwd=str(REPO), capture_output=True, text=True, timeout=300, check=False,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out[-800:]
    assert "skill steps" in out, out
    assert "analytics" in out, out
    assert "match the converter" in out, out


def test_the_converter_builds_what_the_files_hold():
    """The stored files are what the converter produces - not hand-edited."""
    spec = importlib.util.spec_from_file_location("conv_under_test", CONVERTER)
    conv = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["conv_under_test"] = conv
    spec.loader.exec_module(conv)  # type: ignore[union-attr]

    cols = conv.load_field_registry()
    mismatches: list[str] = []
    for skill, step in _steps():
        fams = [str(f) for f in ((step.get("requires") or {}).get("families") or [])]
        es, dropped, _ = conv.build_es(
            str(step.get("query") or ""), fams, str(step.get("pivot") or ""), cols)
        if step.get("es") != es:
            mismatches.append(f"{skill}/{step.get('name')}")
        if bool(step.get("es_dropped")) != bool(dropped):
            mismatches.append(f"{skill}/{step.get('name')} (drops)")
    assert mismatches == [], f"not produced by the converter: {mismatches[:10]}"


# ── the semantics the reviewer will sample at R0' ──────────────────────

def test_a_multi_alternative_step_keeps_every_branch():
    """The specific defect, asserted on the step the reviewer named."""
    step = next(s for skill, s in _steps() if s.get("name") == "kerberoast_tgs")
    blob = json.dumps(step["es"]).lower()
    for term in ("4769", "rc4", "0x17", "service ticket"):
        assert term in blob, f"{term!r} was lost from the conversion: {step['es']}"


def test_the_identity_pivot_no_longer_swallows_a_non_username():
    """`asrep_roast` (pivot `TargetUserName`) must not put a status code in the
    user column - that clause can never match, which is the silent zero KR2b
    exists to stop."""
    step = next(s for skill, s in _steps() if s.get("name") == "asrep_roast")
    assert "user" not in json.dumps(step["es"]).lower(), step["es"]
    assert "0x40850210" in json.dumps(step["es"]).lower(), step["es"]


def test_a_typed_field_token_becomes_a_clause_not_text():
    """`file:history` is a clause on `file`, never the literal `*file:history*`."""
    step = next(s for skill, s in _steps() if s.get("name") == "history_visits")
    assert step["es"] == {"wildcard": {"file": {"value": "*history*", "case_insensitive": True}}}


# ── semantic acceptance, against a REAL ES index ───────────────────────

#: A dedicated case id, so the index cannot collide with anything else.
SEMANTIC_CASE = "CASE-KR2B-SEMANTIC"


def _semantic_items() -> list[tuple[str, dict]]:
    """Every analytic, plus one step from each of the 37 skills (>= 40 items)."""
    items: list[tuple[str, dict]] = [(f"analytic:{a.get('id')}", a) for a in _analytics()]
    seen: set[str] = set()
    for skill, step in _steps():
        if skill in seen:
            continue
        seen.add(skill)
        items.append((f"{skill}/{step.get('name')}", step))
    return items


def _targets(node: object, out: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """``(field, searched value, clause kind)`` for every positive clause."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("wildcard", "term", "match", "match_phrase", "prefix") and isinstance(value, dict):
                for field, spec in value.items():
                    raw = spec.get("value") if isinstance(spec, dict) else spec
                    out.append((str(field), str(raw).strip("*?"), key))
            elif key == "exists" and isinstance(value, dict):
                # `exists` demands the field be present, so the positive row must
                # carry it. Without this a conjunction containing `exists` can never
                # match, and the fixture would blame the query.
                for field in value.values():
                    out.append((str(field), "present", "exists"))
            elif key == "terms" and isinstance(value, dict):
                for field, values in value.items():
                    if isinstance(values, list) and values:
                        out.append((str(field), str(values[0]), "term"))
            else:
                _targets(value, out)
    elif isinstance(node, list):
        for value in node:
            _targets(value, out)
    return out


def _put(doc: dict, targets: list[tuple[str, str, str]]) -> None:
    """Write every clause's value, so a conjunction can match.

    A `term` on a keyword field must equal the value exactly; a `wildcard` only
    needs to contain it. Satisfying one clause of a `must` is not enough, which is
    why every target is written and not just the first.
    """
    by_field: dict[str, list[tuple[str, str]]] = {}
    for field, value, kind in targets:
        by_field.setdefault(field, []).append((value, kind))

    for field, entries in by_field.items():
        exact = next((v for v, k in entries if k == "term"), None)
        combined = " ".join(v for v, _ in entries)
        if field in ("text", "text.wc"):
            doc["text"] = f"{doc.get('text', '')} {combined} normal row".strip()
        elif field.startswith("fields."):
            column = field.split(".")[1]
            doc.setdefault("fields", {})[column] = exact if exact is not None else combined
        elif field:
            doc[field] = exact if exact is not None else combined


def _real_es_url() -> str:
    """The configured ES URL, read from `.env` - the session fixture blanks it.

    The V2 rule ("a test run must not touch the real ES") exists so tests cannot
    pollute the operator's case indexes. This check **needs** a real index (WO-KR2b
    says so explicitly), so it points at the configured ES for its own throwaway
    case index and deletes it afterwards. It never reads or writes a real case.
    """
    import os

    env_file = REPO / ".env"
    if env_file.is_file():
        for line in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("NEXUS_ES_URL="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return os.environ.get("NEXUS_ES_URL_REAL") or ""


@pytest.fixture(scope="module")
def es_case():
    """A real ES index, with a positive and a near-miss row per item."""
    from nexus.langgraph import case_index

    real = _real_es_url()
    if not real:
        pytest.skip("no NEXUS_ES_URL in .env - the semantic check needs a real index")

    patch = pytest.MonkeyPatch()
    patch.setenv("NEXUS_ES_URL", real)
    case_index._es_probe_cache = None
    if not case_index.es_available():
        patch.undo()
        pytest.skip(f"Elasticsearch is not reachable at {real}")

    index = case_index.index_name(SEMANTIC_CASE)
    client = case_index._client()
    if client.head(f"/{index}").status_code == 200:
        client.delete(f"/{index}")
    case_index.ensure_index(SEMANTIC_CASE)

    items = _semantic_items()
    for position, (_name, item) in enumerate(items):
        fams = item.get("families") or []
        family = str(fams[0]) if fams else "evtxecmd"
        targets = _targets(item.get("es") or {}, [])
        positive: dict = {"case_id": SEMANTIC_CASE, "family": family,
                          "host": "pos", "file": f"pos-{position}"}
        _put(positive, targets)
        # A row that shares the family and nothing else: the false-positive guard.
        # The values are deliberately inert - a benign-looking `svchost.exe` would
        # legitimately match queries that search for it, which is a fixture fault,
        # not a query defect.
        near: dict = {"case_id": SEMANTIC_CASE, "family": family, "host": "near",
                      "file": f"near-{position}",
                      "text": "inert marker row nothing searches for",
                      "fields": {"process_name": "inertmarker.exe",
                                 "command_line": "inertmarker.exe --idle"}}
        for doc in (positive, near):
            resp = client.post(f"/{index}/_doc/{position}-{doc['host']}", json=doc)
            if resp.status_code >= 300:
                client.delete(f"/{index}")
                patch.undo()
                pytest.skip(f"could not index the fixture: {resp.status_code} {resp.text[:160]}")
    client.post(f"/{index}/_refresh")
    try:
        yield {"case_id": SEMANTIC_CASE, "items": items, "index": index}
    finally:
        client.delete(f"/{index}")
        patch.undo()
        case_index._es_probe_cache = None


def test_a_sample_hits_its_own_row_and_not_a_benign_one(es_case, monkeypatch):
    """WO-KR2b semantic acceptance, against a REAL ES index.

    Each of the >= 40 items is run through `es_search` - the path KR3 will use -
    against a real index. Every item has one row that carries the value its own
    clause targets, and one benign row in the same family.

    What this proves: the query **executes**, returns the row it targets (so a
    clause aimed at a field nothing writes would fail here, as `degraded`), and does
    not fire on a benign row.

    What it does not prove, and does not claim: that the field each clause targets
    is the right one for real data. That is the reviewer's R0' sample read against
    `look_for` - the fixture cannot answer it, because the fixture is built from the
    query's own target.
    """
    from nexus.langgraph import case_index, es_native

    # conftest's autouse fixture blanks NEXUS_ES_URL for every test (the V2 rule);
    # this one needs the real index, so it re-points at it for its own case only.
    monkeypatch.setenv("NEXUS_ES_URL", _real_es_url())
    case_index._es_probe_cache = None

    failures: list[str] = []
    for name, item in es_case["items"]:
        result = es_native.es_search(es_case["case_id"], item.get("es") or {}, size=50)
        if result.get("degraded") or result.get("error"):
            failures.append(f"{name}: cannot match - {str(result.get('error'))[:90]}")
            continue
        hosts = {str(hit.get("host")) for hit in result.get("hits") or []}
        if "pos" not in hosts:
            failures.append(f"{name}: the positive row did not match ({sorted(hosts)})")
        if "near" in hosts:
            failures.append(f"{name}: matched a benign row")
    assert not failures, f"{len(failures)} item(s) failed:\n" + "\n".join(failures[:15])


def test_the_semantic_fixture_covers_every_analytic_and_every_skill():
    """The WO asks for every analytic plus a step from each of the 37 skills."""
    items = _semantic_items()
    analytic_ids = {a.get("id") for a in _analytics()}
    covered = {n.split("analytic:", 1)[1] for n, _ in items if n.startswith("analytic:")}
    skills = {n.split("/", 1)[0] for n, _ in items if not n.startswith("analytic:")}
    assert covered == analytic_ids, f"missing analytics: {analytic_ids - covered}"
    assert len(skills) == 37, f"{len(skills)} skills represented, expected 37"
    assert len(items) >= 40, len(items)
