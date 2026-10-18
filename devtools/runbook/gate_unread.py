"""Print a case's evidence gate: its state and every item not processed, with the reason (Part 10, P2).

    python devtools/runbook/gate_unread.py CASE-X          (a case id under the configured cases root)
    python devtools/runbook/gate_unread.py <case folder>
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))


def case_dir(arg: str) -> Path:
    path = Path(arg)
    if path.is_dir():
        return path
    from nexus.config import settings  # noqa: PLC0415

    return Path(settings.cases_root) / arg


def report(folder: Path) -> list[str]:
    gate_file = folder / "analysis" / "lane_gate.json"
    if not gate_file.is_file():
        return [f"{folder.name}: no lane_gate.json (the lane has not run)"]
    gate = json.loads(gate_file.read_text(encoding="utf-8"))
    lines = [f"{folder.name}: gate {gate.get('status')}, processed {gate.get('processed_count')}, "
             f"blocked {gate.get('blocked_count')}, waiting {gate.get('waiting_count')}"]
    for row in gate.get("unprocessed") or []:
        purpose = str(row.get("purpose") or "")
        where = purpose.split("_samples\\", 1)[-1] if "_samples\\" in purpose else purpose
        lines.append(f"  {str(row.get('tool') or '')[:24]:24} {where[:110]:110} | {str(row.get('reason') or '')[:100]}")
    return lines


def main(arg: str) -> int:
    lines = report(case_dir(arg))
    print("\n".join(lines))
    return 1 if lines[0].endswith("has not run)") else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1]))
