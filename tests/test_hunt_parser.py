"""Unit tests for nexus.langgraph.hunt_parser.

Exercises every parse path so we know stage_findings's placeholder
fallback fires only when it should.

Run as a script: `python tests/test_hunt_parser.py`.
"""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from nexus.langgraph.hunt_parser import normalize_candidate, parse_hunt_candidates

passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {label}" + (f" — {detail}" if detail else ""))
    else:
        failed += 1
        print(f"  FAIL: {label}" + (f" — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# Fallback path — these MUST return [] so stage_findings can salvage N4 hits
# ---------------------------------------------------------------------------

# 1. Empty input
check("empty messages -> []", parse_hunt_candidates([]) == [])

# 2. None input is tolerated
check("None messages -> []", parse_hunt_candidates(None or []) == [])

# 3. Prose with no JSON anywhere
r = parse_hunt_candidates([
    {"role": "ai", "content": "I scanned the MFT and found nothing of note."},
])
check("prose only -> []", r == [], f"got {len(r)} candidates")

# 4. Malformed JSON (truncated brace)
r = parse_hunt_candidates([
    {"role": "ai", "content": '{"title": "bad", "observation": "missing close brace"'},
])
check("malformed top-level JSON -> []", r == [], f"got {len(r)} candidates")

# 5. Markdown fence with malformed JSON inside
r = parse_hunt_candidates([
    {"role": "ai", "content": "```json\n{not valid json at all}\n```"},
])
check("malformed fenced JSON -> []", r == [], f"got {len(r)} candidates")

# 6. Empty markdown fence
r = parse_hunt_candidates([
    {"role": "ai", "content": "Here is the output:\n```json\n\n```"},
])
check("empty fenced block -> []", r == [], f"got {len(r)} candidates")

# 7. Whole-content JSON missing observation (strict path requires both keys)
r = parse_hunt_candidates([
    {"role": "ai", "content": '{"title": "Title only, no observation"}'},
])
check("raw JSON missing observation -> []", r == [], f"got {len(r)} candidates")

# 8. JSON array of non-dicts inside a fence
r = parse_hunt_candidates([
    {"role": "ai", "content": "```json\n[1, 2, 3, \"strings\"]\n```"},
])
check("fenced array of primitives -> []", r == [], f"got {len(r)} candidates")

# 9. JSON object with no title field
r = parse_hunt_candidates([
    {"role": "ai", "content": '{"observation": "no title here", "confidence": "HIGH"}'},
])
check("missing title -> []", r == [], f"got {len(r)} candidates")

# 10. Content is None (LangChain sometimes does this for tool calls)
r = parse_hunt_candidates([{"role": "ai", "content": None}])
check("None content -> []", r == [], f"got {len(r)} candidates")

# 11. Non-string content (list of content blocks, e.g. Anthropic tool-call shape)
r = parse_hunt_candidates([
    {"role": "ai", "content": [{"type": "text", "text": "no json here"}]},
])
check("list content with no JSON -> []", r == [], f"got {len(r)} candidates")


# ---------------------------------------------------------------------------
# Happy paths — these MUST produce candidates so the placeholder is skipped
# ---------------------------------------------------------------------------

# 12. Whole-content JSON, title + observation present
r = parse_hunt_candidates([
    {"role": "ai", "content": '{"title": "EVIL.EXE in AppData", "observation": "MFT shows it"}'},
])
check("raw JSON happy path", len(r) == 1 and r[0]["title"] == "EVIL.EXE in AppData", f"got {len(r)}")

# 13. Single fenced JSON object (fenced path only needs title)
r = parse_hunt_candidates([
    {"role": "ai", "content": 'See finding:\n```json\n{"title": "Suspicious autorun"}\n```'},
])
check("fenced single object", len(r) == 1 and r[0]["title"] == "Suspicious autorun")

# 14. Fenced array — multiple findings in one message
r = parse_hunt_candidates([
    {"role": "ai", "content": (
        "Here are the candidates:\n```json\n"
        '[{"title": "F1"}, {"title": "F2"}, {"title": "F3"}]\n```'
    )},
])
check("fenced array -> N candidates", len(r) == 3, f"got {len(r)}")

# 15. Fenced array with mixed valid + invalid items
r = parse_hunt_candidates([
    {"role": "ai", "content": (
        "```json\n"
        '[{"title": "good"}, {"observation": "no title"}, {"title": "good2"}, 42]\n```'
    )},
])
check("array with mixed validity -> only valid", len(r) == 2, f"got {len(r)} (expected 2)")

# 16. Multiple messages, candidates accumulate across them
r = parse_hunt_candidates([
    {"role": "ai", "content": '```json\n{"title": "msg1"}\n```'},
    {"role": "ai", "content": '```json\n{"title": "msg2"}\n```'},
])
check("candidates across messages", len(r) == 2, f"got {len(r)}")

# 17. Only the LAST scan_last messages are scanned (default 20)
older = [{"role": "ai", "content": '```json\n{"title": "old"}\n```'}] * 5
recent = [{"role": "ai", "content": '```json\n{"title": "recent"}\n```'}] * 20
r = parse_hunt_candidates(older + recent)
check("only last 20 scanned (default)", len(r) == 20 and all(c["title"] == "recent" for c in r),
      f"got {len(r)} candidates, titles={set(c['title'] for c in r)}")
r = parse_hunt_candidates(older + recent, scan_last=5)
check("scan_last=5 honored", len(r) == 5 and all(c["title"] == "recent" for c in r),
      f"got {len(r)}")

# 18. LangChain-style message object (has .content attribute, not dict)
msg = SimpleNamespace(content='```json\n{"title": "from object"}\n```')
r = parse_hunt_candidates([msg])
check("LangChain object messages", len(r) == 1 and r[0]["title"] == "from object")

# 19. Plain string message
r = parse_hunt_candidates(['```json\n{"title": "plain string"}\n```'])
check("plain string message", len(r) == 1 and r[0]["title"] == "plain string")


# ---------------------------------------------------------------------------
# normalize_candidate — clamping and field aliases
# ---------------------------------------------------------------------------

# 20. Title is clamped to 200 chars
n = normalize_candidate({"title": "x" * 500, "observation": "y"})
check("title clamped to 200", len(n["title"]) == 200, f"got len={len(n['title'])}")

# 21. Observation clamped to 8000 chars
n = normalize_candidate({"title": "t", "observation": "y" * 12000})
check("observation clamped to 8000", len(n["observation"]) == 8000, f"got len={len(n['observation'])}")

# 22. `description` aliases `observation` when observation missing
n = normalize_candidate({"title": "t", "description": "fallback obs"})
check("description -> observation alias", n["observation"] == "fallback obs")

# 23. `mitre_ids` aliases `attack_ids`
n = normalize_candidate({"title": "t", "mitre_ids": ["T1003"]})
check("mitre_ids -> attack_ids alias", n["attack_ids"] == ["T1003"])

# 24. `timestamp` aliases `event_timestamp`
n = normalize_candidate({"title": "t", "timestamp": "2026-01-15T14:32:00Z"})
check("timestamp -> event_timestamp alias", n["event_timestamp"] == "2026-01-15T14:32:00Z")

# 25. Confidence is upper-cased
n = normalize_candidate({"title": "t", "confidence": "medium"})
check("confidence upper-cased", n["confidence"] == "MEDIUM")

# 26. Confidence defaults to MEDIUM when absent
n = normalize_candidate({"title": "t"})
check("confidence defaults to MEDIUM", n["confidence"] == "MEDIUM")

# 27. iocs/attack_ids default to empty list, not None
n = normalize_candidate({"title": "t"})
check("iocs default []", n["iocs"] == [])
check("attack_ids default []", n["attack_ids"] == [])


# ---------------------------------------------------------------------------
# Anti-injection: nested fences and unicode shouldn't crash
# ---------------------------------------------------------------------------

# 28. Adversarial: huge content, no fence
big_prose = "x" * 100_000
r = parse_hunt_candidates([{"role": "ai", "content": big_prose}])
check("huge non-JSON content -> []", r == [])

# 29. Adversarial: unicode in title doesn't crash normalisation
r = parse_hunt_candidates([
    {"role": "ai", "content": '```json\n{"title": "файл.exe в AppData"}\n```'},
])
check("unicode title parses", len(r) == 1 and "файл" in r[0]["title"])

# 30. Fence-like text without a closing fence is ignored
r = parse_hunt_candidates([
    {"role": "ai", "content": '```json\n{"title": "no close fence"'},
])
check("unclosed fence -> []", r == [], f"got {len(r)} candidates")

# 31. Unfenced JSON array buried in prose
r = parse_hunt_candidates([{
    "role": "ai",
    "content": (
        "Here are the findings:\n"
        '[{"title": "sdelete wipe", "observation": "pecmd hit sdelete.exe"}]\n'
    ),
}])
check("buried JSON array -> 1 candidate", len(r) == 1 and "sdelete" in r[0]["title"],
      f"got {len(r)}")


print()
print(f"=== {passed} PASSED, {failed} FAILED (out of {passed + failed}) ===")
sys.exit(0 if failed == 0 else 1)
