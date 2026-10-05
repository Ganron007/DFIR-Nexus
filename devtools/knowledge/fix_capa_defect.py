"""WO-KR2b defect 6: `rules.<rule>` is a registry placeholder, not a live column.

The registry declares `rules.<rule>.meta.name` for family `capa`, but ES sees no such
key: the capa family currently indexes the raw JSON as a single line (one row = the
whole file, 6,378 copies of an identical blob, zero `fields`), so nothing under
`rules.*` ever exists. A stored query that asserts `exists` on a placeholder can never
match, which is the R0' defect verbatim: "the literal placeholder `<rule>`".

Fix: query what the index ACTUALLY yields for capa rows, and record the placeholder as
`es_dropped` with the reason, so the gap is visible instead of silently untestable.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

CAPA_ES = {
    "bool": {
        "should": [
            # the capa JSON embeds the whole run verbatim, so its capability names,
            # ATT&CK ids and MBC parts are all inside `text`. This is the only thing
            # the index actually holds for a capa row today.
            {"wildcard": {"text.wc": {"value": "*attack*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*mbc*", "case_insensitive": True}}},
            {"wildcard": {"text.wc": {"value": "*rules*", "case_insensitive": True}}},
            # meta.version is a real typed column on the capa family
            {"wildcard": {"fields.meta.version.kw": {"value": "*capa*", "case_insensitive": True}}},
        ],
        "minimum_should_match": 1,
    }
}

DROP = [
    {"term": "exists fields.rules.<rule>.meta.attack.kw",
     "reason": "registry placeholder, not a live column. The capa family indexes "
               "the raw JSON as one text row, so no `rules.*` key ever exists in "
               "the index. The content is searched in `text.wc` instead, and a "
               "successful text hit is weaker than a column assertion - the step "
               "now requires a field AND a text match."},
]

AUTHORED = ("Hand-authored: the R0' query asserted `exists` on the placeholder "
            "`fields.rules.<rule>.meta.attack`, which can never match. The step now "
            "combines the family's one real typed column (`fields.meta.version`) with "
            "the text that actually carries the capability names.")


def main() -> int:
    path = Path("src/nexus/data/knowledge/skills/malware_analysis_triage.yaml")
    header = [l for l in path.read_text(encoding="utf-8").splitlines()
              if l.startswith("#")]
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    hit = 0
    for s in data.get("steps") or []:
        if isinstance(s, dict) and s.get("name") == "capa_capabilities":
            s["es"] = CAPA_ES
            s["es_dropped"] = DROP
            s["es_authored_reason"] = AUTHORED
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
