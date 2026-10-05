"""WO-KR2b change 2: procedure steps are not queries.

Four sampled steps had their procedure text turned into keyword searches:

  hash_on_acquire     "Hash the image ... SHA-256 preferred"      -> *sha256*/*md5*/*hash*
  triage_first        "Triage image (KAPE targets) ..."           -> *kape*/*triage*
  encryption_check    "check for drive encryption"                -> *bitlocker*
  backward_analysis   "Work BACKWARD from impact ..."             -> *rdp*/*phish*

Each fires on any row that mentions the word and counts as coverage, which is the R0'
defect: "4 are procedure steps turned into searches. They fire on noise and count as
coverage."

Fix: `kind: procedure`, no `es:`, `es_dropped` records every keyword that was a
procedure rather than a search, and a `procedure_reason` records why.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

PROCEDURES = {
    "hash_on_acquire": {
        "file": "evidence_acquisition_handling.yaml",
        "dropped": [
            {"term": "*sha256*", "reason": "procedure verb, not evidence: hashing is what "
                                           "the examiner does, not what is searched for"},
            {"term": "*md5*", "reason": "procedure verb, not evidence"},
            {"term": "*hash*", "reason": "procedure verb, not evidence"},
        ],
    },
    "triage_first": {
        "file": "evidence_acquisition_handling.yaml",
        "dropped": [
            {"term": "*kape*", "reason": "names a tool the examiner runs, not a field "
                                         "value to search for"},
            {"term": "*triage*", "reason": "procedure verb, not evidence"},
        ],
    },
    "encryption_check": {
        "file": "evidence_acquisition_handling.yaml",
        "dropped": [
            {"term": "*bitlocker*", "reason": "a pre-acquisition decision, not a search "
                                              "over indexed evidence"},
            {"term": "*encryption*", "reason": "procedure verb, not evidence"},
            {"term": "*encrypted*", "reason": "procedure verb, not evidence"},
        ],
    },
    "backward_analysis": {
        "file": "impact_ransomware.yaml",
        "dropped": [
            {"term": "*rdp*", "reason": "an entry vector named in the procedure, not a "
                                        "column value"},
            {"term": "*phish*", "reason": "an entry vector named in the procedure"},
            {"term": "event_id 4624", "reason": "a real clue, but this step is the order "
                                                "of investigation, not a search for it"},
        ],
    },
}


def main() -> int:
    done = []
    for step, spec in PROCEDURES.items():
        path = Path("src/nexus/data/knowledge/skills") / spec["file"]
        if not path.is_file():
            # find it wherever it lives
            cands = [p for p in (Path("src/nexus/data/knowledge/skills")).glob("*.yaml")
                     if any(s.get("name") == step for s in
                            (yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("steps") or [])]
            if not cands:
                print(f"  !! {step} not found")
                continue
            path = cands[0]
        header = [l for l in path.read_text(encoding="utf-8").splitlines()
                  if l.startswith("#")]
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for s in data.get("steps") or []:
            if isinstance(s, dict) and s.get("name") == step:
                old_es = s.pop("es", None)
                s["kind"] = "procedure"
                s["es_dropped"] = spec["dropped"]
                s["procedure_reason"] = (
                    "R0' defect: this step's look_for is an investigation ORDER "
                    "(do X, then Y), not evidence to search. It is shown to agents "
                    "as a procedure and never executed, so it cannot fire on noise "
                    "and cannot count as coverage."
                )
                done.append(f"{path.stem}:{step}" + (" (es removed)" if old_es else ""))
                break
        body = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        path.write_text(("\n".join(header) + "\n" + body) if header else body,
                        encoding="utf-8")
    for d in done:
        print("  ", d)
    print(f"\n  {len(done)} procedure step(s) reclassified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
