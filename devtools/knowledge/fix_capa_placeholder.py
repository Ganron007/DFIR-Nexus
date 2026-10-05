"""WO-KR2b/R0' defect 6: remove the literal `<rule>` placeholder from capa_capabilities.

The step is hand-authored (`es_authored_reason`) because its query really does span
three different columns in one `should`, which the converter cannot express. That is
legitimate - but the authored fields carried the registry PLACEHOLDER
`rules.<rule>.meta.*`, which is not a column the index emits, so the query can never
match. The reviewer named it exactly:

  "the agent's own `capa_capabilities` - `exists` on
   `fields.rules.<rule>.meta.attack`, with the **literal placeholder `<rule>`**"

Measured: the capa family indexes its raw JSON as a single text row (6,378 identical
rows, zero `fields`, no rule name anywhere in them), so nothing under `rules.*` exists.
The family's one real typed column is `fields.meta.version`.

Fix: assert the family's real column and search the capability names in the row text,
which is where the JSON's content actually lands. The placeholder is recorded in
`es_dropped` so the gap is visible instead of silently untestable.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CAPA_ES = {
    "bool": {
        "should": [
            # the capability names, ATT&CK ids and MBC parts are inside the capa
            # JSON, which the index holds as the row's text.
            {"wildcard": {"text.wc": {"value": "*attack*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*mbc*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*rules*", "case_insensitive": True}}},
            # the family's one real typed column
            {"wildcard": {"fields.meta.version.kw": {"value": "*capa*",
                                                    "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

DROP = [
    {"term": "capability",
     "reason": "the free query's own name for the capa rule names; they are searched "
               "in `text.wc` (the capa JSON is the row's text), not as a column, "
               "because no `rules.*` column is live"},
    {"term": "exists fields.rules.<rule>.meta.attack",
     "reason": "registry placeholder, not a live column. The capa family indexes its "
               "raw JSON as one text row, so no `rules.*` key ever exists in the "
               "index. The content is searched in `text.wc` instead, which is a "
               "weaker match than a column assertion - recorded here rather than "
               "shipped as an unfillable clause."},
    {"term": "exists fields.rules.<rule>.meta.mbc",
     "reason": "same placeholder"},
    {"term": "exists fields.rules.<rule>.meta.name",
     "reason": "same placeholder"},
]


def main() -> int:
    path = (Path(__file__).resolve().parents[2] / "src" / "nexus" / "data" / "knowledge"
            / "skills" / "malware_analysis_triage.yaml")
    header = [l for l in path.read_text(encoding="utf-8").splitlines()
              if l.startswith("#")]
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    hit = 0
    for s in data.get("steps") or []:
        if isinstance(s, dict) and s.get("name") == "capa_capabilities":
            s["es"] = CAPA_ES
            s["es_dropped"] = DROP
            s["es_authored_reason"] = (
                "Hand-authored: the query asks about the capability name AND its "
                "ATT&CK mapping AND its MBC mapping in one should, over several "
                "columns, which the converter's one-clause-per-alternative builder "
                "cannot express. R0' fix: the fields it names are the registry "
                "PLACEHOLDER `rules.<rule>.meta.*`, not live columns, so the step "
                "now combines the capa family's real typed column "
                "(`fields.meta.version`) with the text that actually carries the "
                "capability names.")
            hit += 1
    if not hit:
        print("  !! capa_capabilities not found")
        return 2
    body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    path.write_text(("\n".join(header) + "\n" + body) if header else body,
                    encoding="utf-8")
    print(f"  capa_capabilities rewritten ({hit})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
