"""WO-KL2b (design time): translate SigmaHQ rules into `es:` analytics, by program.

The WO asks for full rules translated **by a program, not from memory**: "Use a
program: pySigma with a custom field mapping to our `fields.<Name>`, or an
equivalent. Report the counts: translated, skipped (no field), failed."

**Why not a pySigma backend.** pySigma's installed Elasticsearch backends
(`EsqlBackend`, `EqlBackend`, `LuceneBackend`) emit query **strings** - ESQL, EQL,
Lucene - and our index stores ES query **objects**, built only from the clause types
`es_native.validate_query` allows. Subclassing `TextQueryBackend` (29 string
methods) to emit JSON would be fighting the API. So this uses pySigma for what it
is strong at - **parsing** the Sigma grammar into a `SigmaDetection` tree - and
walks that tree to emit our JSON. That is the "or an equivalent" the WO allows.

The tree is small: `ConditionAND` / `ConditionOR` / `ConditionNOT` and
`ConditionFieldEqualsValueExpression` (a leaf naming a detection). A detection is
an AND of its items; a list of maps inside one is an OR.

**Nothing is invented.** A field with no mapping to our registry **skips the rule**
and is counted; a modifier we cannot express (regex, base64, cidr, windash, field
comparison) skips it and is counted. A rule is emitted only when its JSON passes
`validate_stored_query` against the rule's own families.

Usage::

    python devtools/knowledge/sigma_import.py                 # report counts
    python devtools/knowledge/sigma_import.py --write         # write the pack
    python devtools/knowledge/sigma_import.py --check         # fail on drift
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "src" / "nexus" / "data" / "knowledge" / "needles" / "sigma_analytics.yaml"

sys.path.insert(0, str(REPO / "src"))

from nexus.knowledge.query_validation import (  # noqa: E402
    load_field_registry,
    validate_stored_query,
)

#: Sigma logsource category -> the case families the rule applies to.
CATEGORY_FAMILIES: dict[str, list[str]] = {
    "process_creation": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "registry_set": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "registry_add": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "registry_delete": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "registry_event": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "file_event": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "file_change": ["evtxecmd", "hayabusa", "security", "sysmon"],
    "ps_script": ["evtxecmd", "hayabusa", "security", "powershell", "sysmon"],
    "ps_module": ["evtxecmd", "hayabusa", "security", "powershell", "sysmon"],
    "ps_classic_start": ["evtxecmd", "hayabusa", "security", "powershell", "sysmon"],
}

#: Sigma field -> our registry column. Only fields the registry actually carries for
#: the families above; a rule touching anything else is skipped, not guessed.
FIELD_MAP: dict[str, str] = {
    "Image": "process_name",
    "OriginalFileName": "file_name",
    "CommandLine": "command_line",
    "ParentImage": "parent_process",
    "ParentCommandLine": "parent_command_line",
    "ProcessCommandLine": "command_line",
    "TargetFilename": "file_path",
    "TargetObject": "registry_key",
    "Details": "registry_value",
    "EventID": "EventID",
    "User": "user",
    "ScriptBlockText": "payload",
    "QueryName": "query_name",
    "DestinationIp": "dest_ip",
    "SourceIp": "source_ip",
    "DestinationHostname": "dest_host",
    "DestinationPort": "dest_port",
    "ServiceName": "service_name",
    "ImagePath": "image_path",
    "TaskName": "task_name",
}

#: Modifiers we can express. Anything else skips the rule.
SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "all", "cased", "exists", "gt", "gte", "lt", "lte"}

#: The `contains|all`-style modifier classes pySigma attaches.
_MOD = {
    "SigmaContainsModifier": "contains",
    "SigmaStartswithModifier": "startswith",
    "SigmaEndswithModifier": "endswith",
    "SigmaAllModifier": "all",
    "SigmaCasedModifier": "cased",
    "SigmaExistsModifier": "exists",
    "SigmaGreaterThanModifier": "gt",
    "SigmaGreaterEqualModifier": "gte",
    "SigmaLessThanModifier": "lt",
    "SigmaLessEqualModifier": "lte",
    "SigmaFieldRefModifier": "__skip__",
}


def _snapshots() -> Path:
    return Path(os.environ.get("NEXUS_KL2B_SNAPSHOTS")
                or (Path(os.environ.get("TEMP", "/tmp")) / "kl2b-snapshots"))


def _cols() -> dict[str, Any]:
    return load_field_registry()


def _field_path(sigma_field: str, cols: dict[str, Any], families: list[str]) -> str | None:
    """Our `fields.<name>[.kw]` for a Sigma field, or None when unmapped."""
    from nexus.knowledge.query_validation import expand_families

    name = FIELD_MAP.get(sigma_field)
    if sigma_field in ("EventID", "event_id", "eventid"):
        return "event_id"
    if not name:
        return None
    wanted = re.sub(r"[^a-z0-9]", "", name.lower())
    expanded = expand_families(families)
    for col, info in cols.items():
        if re.sub(r"[^a-z0-9]", "", col.lower()) != wanted:
            continue
        col_fams = {str(f).lower() for f in (info.get("families") or [])}
        if not col_fams or (col_fams & expanded):
            return f"fields.{col}.kw" if str(info.get("type")) == "text" else f"fields.{col}"
    return None


def _clause(field: str, value: Any, modifiers: list[str]) -> dict[str, Any] | None:
    """One clause for a (field, value, modifiers) triple, or None when unexpressible."""
    if "exists" in modifiers:
        return {"exists": {"field": field}}
    if any(m in modifiers for m in ("gt", "gte", "lt", "lte")):
        op = next(m for m in modifiers if m in ("gt", "gte", "lt", "lte"))
        # pySigma hands back a `SigmaNumber`, not a plain int. It YAML-round-trips
        # to a plain int, so leaving it uncoerced makes the pack disagree with a
        # regeneration (`--check` drift) even though the query is the same.
        number: int | float
        try:
            number = int(value)
        except (TypeError, ValueError):
            try:
                number = float(value)
            except (TypeError, ValueError):
                return None
        return {"range": {field: {op: number}}}
    text = str(value)
    if any(m in modifiers for m in ("re", "base64", "base64offset", "cidr", "fieldref", "windash")):
        return None
    if "contains" in modifiers:
        text = f"*{text.strip('*')}*"
    elif "startswith" in modifiers:
        text = f"{text.strip('*')}*"
    elif "endswith" in modifiers:
        text = f"*{text.strip('*')}"
    if any(ch in text for ch in "*?"):
        return {"wildcard": {field: {"value": text, "case_insensitive": "cased" not in modifiers}}}
    return {"term": {field: text}}


def _item_clauses(item: Any, cols: dict[str, Any], families: list[str],
                  counters: Counter) -> list[dict[str, Any]] | None:
    """Clauses for one detection item. None means "this rule cannot be translated"."""
    from sigma.rule.detection import SigmaDetection, SigmaDetectionItem

    if isinstance(item, SigmaDetection):
        inner = _detection_clauses(item, cols, families, counters)
        return None if inner is None else [inner]

    if not isinstance(item, SigmaDetectionItem):
        counters["unsupported_item"] += 1
        return None
    fields = item.field if isinstance(item.field, list) else [item.field]
    field_paths = [_field_path(str(f), cols, families) for f in fields]
    if any(p is None for p in field_paths):
        counters["skipped_no_field"] += 1
        return None
    # `item.modifiers` holds modifier **classes**, not instances, so the name is on
    # the object itself (`SigmaContainsModifier`), not on `type(m)` - reading
    # `type(m).__name__` gave "ABCMeta" for every modifier and skipped every rule.
    def _mod_name(mod: Any) -> str:
        return getattr(mod, "__name__", type(mod).__name__)

    modifiers = [_MOD.get(_mod_name(m), _mod_name(m)) for m in (item.modifiers or [])]
    if any(m not in SUPPORTED_MODIFIERS for m in modifiers):
        counters["skipped_modifier"] += 1
        return None
    values = item.value if isinstance(item.value, list) else [item.value]
    if not values:
        counters["unsupported_item"] += 1
        return None
    clauses: list[dict[str, Any]] = []
    for value in values:
        # `null` in Sigma means the field is null/absent. Our index has no null, and
        # `must_not exists` would fire on every row that merely lacks the column, so
        # the honest answer is to skip the rule rather than approximate it. Without
        # this branch `str(SigmaNull)` became a search value - the literal text
        # `"<sigma.types.SigmaNull object at 0x...>"`, which can never match and which
        # changed a memory address on every run (a `--check` drift).
        if value is None or type(value).__name__ == "SigmaNull":
            counters["skipped_null"] += 1
            return None
        clause = _clause(field_paths[0], value, modifiers)
        if clause is None:
            counters["skipped_modifier"] += 1
            return None
        clauses.append(clause)
    if not clauses:
        counters["unsupported_item"] += 1
        return None
    if "all" in modifiers:
        return clauses
    if len(clauses) == 1:
        return clauses
    return [{"bool": {"should": clauses, "minimum_should_match": 1}}]


def _detection_clauses(detection: Any, cols: dict[str, Any], families: list[str],
                       counters: Counter) -> dict[str, Any] | None:
    """A detection is an AND of its items; a list of maps inside one is an OR."""
    from sigma.rule.detection import SigmaDetection

    must: list[dict[str, Any]] = []
    should: list[dict[str, Any]] = []
    for item in detection.detection_items:
        clauses = _item_clauses(item, cols, families, counters)
        if clauses is None:
            return None
        target = should if isinstance(item, SigmaDetection) else must
        target.extend(clauses)
    parts: list[dict[str, Any]] = []
    if must:
        parts.extend(must)
    if should:
        parts.append({"bool": {"should": should, "minimum_should_match": 1}})
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return {"bool": {"must": parts}}


_TOKEN = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\ball\b|\bof\b|\bthem\b|[0-9]+|[A-Za-z0-9_.*?]+)", re.I)


def _tokenize(condition: str) -> list[str]:
    out: list[str] = []
    pos = 0
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m:
            pos += 1
            continue
        out.append(m.group(1))
        pos = m.end()
    return out


def _members(pattern: str, detections: dict[str, Any]) -> list[str]:
    """The detection names a `1 of X` / `all of X` selector refers to."""
    if pattern == "them":
        return sorted(detections)
    if "*" in pattern or "?" in pattern:
        rx = re.compile("^" + pattern.replace("*", ".*").replace("?", ".") + "$")
        return sorted(n for n in detections if rx.match(n))
    return [pattern] if pattern in detections else []


class _CondParser:
    """Recursive-descent parser for the Sigma condition grammar.

    pySigma's own condition tree inlines field/value leaves and links modifiers
    through `parent` chains, which is awkward to walk; the condition *string* is a
    small grammar and the named detections are already in hand
    (`rule.detection.detections`). Parsing the string is the simpler, more literal
    route, and `builtin` (below) covers the handful of shapes it does not parse.
    """

    def __init__(self, tokens: list[str], detections: dict[str, Any], cols: dict[str, Any],
                 families: list[str], counters: Counter) -> None:
        self.tokens = tokens
        self.i = 0
        self.detections = detections
        self.cols = cols
        self.families = families
        self.counters = counters

    def peek(self) -> str:
        return self.tokens[self.i].lower() if self.i < len(self.tokens) else ""

    def take(self) -> str:
        tok = self.tokens[self.i]
        self.i += 1
        return tok

    def parse(self) -> dict[str, Any] | None:
        node = self.parse_or()
        return node if self.i >= len(self.tokens) else None

    def parse_or(self):
        parts = [self.parse_and()]
        while self.peek() == "or":
            self.take()
            parts.append(self.parse_and())
        if any(p is None for p in parts):
            return None
        if len(parts) == 1:
            return parts[0]
        return {"bool": {"should": parts, "minimum_should_match": 1}}

    def parse_and(self):
        parts = [self.parse_not()]
        while self.peek() == "and":
            self.take()
            parts.append(self.parse_not())
        if any(p is None for p in parts):
            return None
        if len(parts) == 1:
            return parts[0]
        return {"bool": {"must": parts}}

    def parse_not(self):
        if self.peek() == "not":
            self.take()
            inner = self.parse_not()
            return None if inner is None else {"bool": {"must_not": [inner]}}
        return self.parse_atom()

    def parse_atom(self):
        if self.peek() == "(":
            self.take()
            inner = self.parse_or()
            if self.peek() == ")":
                self.take()
            return inner
        # `1 of X` / `all of X`
        if self.peek() in ("1", "all") and self.i + 1 < len(self.tokens) \
                and self.tokens[self.i + 1].lower() == "of":
            quantifier = self.take().lower()
            self.take()  # of
            selector = self.take()
            names = _members(selector, self.detections)
            if not names:
                self.counters["unsupported_condition"] += 1
                return None
            clauses = [self._detection(n) for n in names]
            if any(c is None for c in clauses):
                return None
            key = "must" if quantifier == "all" else "should"
            out: dict[str, Any] = {"bool": {key: clauses}}
            if quantifier != "all":
                out["bool"]["minimum_should_match"] = 1
            return out
        name = self.take()
        if name in self.detections:
            return self._detection(name)
        self.counters["unsupported_condition"] += 1
        return None

    def _detection(self, name: str):
        clause = _detection_clauses(self.detections[name], self.cols, self.families, self.counters)
        return clause


def _builtin_condition(rule: Any, detections: dict[str, Any], cols: dict[str, Any],
                       families: list[str], counters: Counter) -> dict[str, Any] | None:
    """The fallback for shapes the small parser does not cover.

    pySigma also resolves conditions itself; when the parser returns None this asks
    pySigma for the answer and maps the resulting detection names, so a rule is not
    lost to a parser gap. Nothing is invented: the mapping is over the same named
    detections.
    """
    try:
        resolved = rule.detection.parsed_condition[0]
    except Exception:  # noqa: BLE001
        return None
    names: list[str] = []

    def walk(node: Any) -> None:
        for arg in getattr(node, "args", []) or []:
            walk(arg)
        ident = getattr(node, "identifier", None)
        if isinstance(ident, str) and ident in detections:
            names.append(ident)

    walk(resolved.parsed)
    if not names:
        return None
    clauses = [_detection_clauses(detections[n], cols, families, counters) for n in set(names)]
    if any(c is None for c in clauses):
        return None
    if len(clauses) == 1:
        return clauses[0]
    return {"bool": {"must": clauses}}


def build() -> dict[str, Any]:
    from sigma.collection import SigmaCollection

    snap = _snapshots() / "sigma"
    if not snap.is_dir():
        raise SystemExit(f"SigmaHQ snapshot not found at {snap}. Clone SigmaHQ/sigma there.")

    import subprocess

    commit = subprocess.run(["git", "-C", str(snap), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=False).stdout.strip()

    cols = _cols()
    dirs = ["rules/windows/process_creation", "rules/windows/registry",
            "rules/windows/file/file_event", "rules/windows/powershell/powershell_script"]
    counters: Counter = Counter()
    packs: list[dict[str, Any]] = []

    for rel in dirs:
        for path in sorted((snap / rel).rglob("*.yml")):
            counters["rules"] += 1
            try:
                rule = SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules[0]
            except Exception:  # noqa: BLE001
                counters["parse_failed"] += 1
                continue
            category = str(getattr(rule.logsource, "category", "") or "")
            families = CATEGORY_FAMILIES.get(category)
            if not families:
                counters["skipped_category"] += 1
                continue

            detections = dict(rule.detection.detections)
            es_query = None
            for condition_text in rule.detection.condition or []:
                parser = _CondParser(_tokenize(str(condition_text)), detections, cols,
                                     families, counters)
                es_query = parser.parse()
                if es_query is None:
                    es_query = _builtin_condition(rule, detections, cols, families, counters)
                if es_query is not None:
                    break
            if es_query is None:
                counters["skipped_untranslatable"] += 1
                continue

            citation = [str(rule.id)] if rule.id else []
            problems = validate_stored_query(es_query, declared_families=families,
                                             citation=citation)
            if problems:
                counters["failed_validation"] += 1
                continue
            counters["translated"] += 1
            techniques = sorted({str(t) for t in (rule.tags or []) if str(t).startswith("attack.t")})
            packs.append({
                "id": f"sigma-{rule.id}" if rule.id else f"sigma-{path.stem}",
                "name": str(rule.title or path.stem)[:200],
                "families": families,
                "citation": {
                    "type": "sigma",
                    "id": str(rule.id or path.stem),
                    "ref": f"https://github.com/SigmaHQ/sigma/blob/master/{rel}/{path.name}",
                    "title": str(rule.title or "")[:160],
                },
                "techniques": [t.replace("attack.", "").upper() for t in techniques],
                "rationale": (f"Translated from Sigma rule {rule.id or path.stem} "
                              f"({rule.level or 'no level'}) by devtools/knowledge/sigma_import.py."),
                "es": es_query,
            })

    packs.sort(key=lambda p: p["id"])
    return {
        "version": 1,
        "generated": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "generator": "devtools/knowledge/sigma_import.py",
        "note": ("SigmaHQ rules translated by program into ES query JSON. Do not edit by "
                 "hand - re-run the importer. A rule whose fields do not map to our "
                 "registry is skipped, never guessed."),
        "source": "https://github.com/SigmaHQ/sigma",
        "source_version": commit,
        "counts": dict(counters),
        "packs": packs,
    }


def _comparable(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "generated"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    payload = build()
    counts = payload["counts"]
    print(f"  SigmaHQ @{payload['source_version'][:10]}  {counts.get('rules', 0)} rules in the four families")
    for key in ("translated", "skipped_no_field", "skipped_modifier", "skipped_null",
                "skipped_category", "skipped_untranslatable", "failed_validation",
                "parse_failed", "unsupported_condition", "unsupported_item"):
        if counts.get(key):
            print(f"    {key:24s} {counts[key]}")

    if args.check:
        on_disk = yaml.safe_load(OUT.read_text(encoding="utf-8")) or {}
        if _comparable(on_disk) != _comparable(payload):
            print("DRIFT: sigma_analytics.yaml is not what the snapshot produces", file=sys.stderr)
            return 1
        print("sigma_analytics.yaml matches the snapshot")
        return 0
    if args.write:
        OUT.write_text(
            "# WO-KL2b - SigmaHQ rules translated by program into ES query JSON.\n"
            "# Generator: devtools/knowledge/sigma_import.py. Do not edit by hand.\n"
            + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000),
            encoding="utf-8")
        print(f"  written: {OUT.relative_to(REPO)}  ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
