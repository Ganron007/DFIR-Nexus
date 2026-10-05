"""Mark the capa step as hand-authored, and record why its alternatives are safe.

The full suite caught this: the capa step's free `query` listed three alternatives
that its `es` did not express, and the converter - which rebuilds every step from the
query - could not reproduce a `should` over three DIFFERENT columns. Both are KR2b
contract points, so the step either conforms or says why.

This records:
- `es_authored_reason`: the converter cannot express this query, so the hand-written
  one is kept and validated (the same mechanism the four inexpressible analytics use).
- `es_dropped`: the alternative `capability` is not a clause of its own because
  `exists` on the capability-name column already covers it - a recorded reason, not a
  silent loss.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
SKILL = REPO / "src" / "nexus" / "data" / "knowledge" / "skills" / "malware_analysis_triage.yaml"

REASON = (
    "Hand-authored: the query asks about the capability name AND its ATT&CK mapping AND "
    "its MBC mapping in one should, over three different columns. The converter builds a "
    "single clause per alternative against one pivot column, which would be weaker."
)
DROPPED = [{
    "term": "capability",
    "reason": ("covered by the `exists` clause on fields.rules.<rule>.meta.name.kw - the "
               "capability name column itself"),
}]


def main() -> int:
    raw = SKILL.read_text(encoding="utf-8")
    header = []
    for line in raw.splitlines():
        if line.startswith("#"):
            header.append(line)
        elif line.strip():
            break
    data = yaml.safe_load(raw) or {}
    hit = False
    for step in data.get("steps") or []:
        if isinstance(step, dict) and step.get("name") == "capa_capabilities":
            step["es_authored_reason"] = REASON
            step["es_dropped"] = DROPPED
            # Keep the display query in step with the clauses it drives.
            step["query"] = "capability OR attack OR mbc"
            hit = True
    if not hit:
        print("  capa_capabilities not found", file=sys.stderr)
        return 2
    body = yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)
    SKILL.write_text("\n".join(header) + "\n" + body if header else body, encoding="utf-8")
    print("  capa_capabilities marked hand-authored with a recorded drop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
