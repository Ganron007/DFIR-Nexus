"""R7-R16 format sweep driver (debug plan 3b).

For each unanchored format: create `dbg-sweep-<fmt>`, register its corpus dir,
run the real tools lane through the portal, then record lane OK/SKIP/FAIL,
the evidence gate, indexed docs and the row-reconciliation summary.

Usage:  python scripts/debug_sweep.py [fmt ...]      (default: all ten)
Writes Docs/internal/sweep-results.json (read-only on the case store apart
from the run itself).
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:4508"
ROOT = REPO / "Evidence-files" / "ES-Mapping" / "evidence"
FORMATS = ["prefetch", "lnk", "jumplists", "thumbcache", "recycle",
           "srum", "rdp", "setupapi", "samples", "activitiescache"]
EXAMINER = "gate_bot"
LANE_TIMEOUT_S = 2400


def _req(method: str, path: str, payload: dict | None = None, headers: dict | None = None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode() or "{}")


def _case_dir(case_id: str) -> Path:
    return REPO / "cases" / case_id


def run_format(fmt: str) -> dict:
    src = ROOT / fmt
    out: dict = {"format": fmt, "source": str(src)}
    r = _req("POST", "/portal/api/case/create",
             {"name": f"dbg-sweep-{fmt}", "examiner": EXAMINER})
    case_id = r.get("case_id") or r.get("id")
    out["case_id"] = case_id
    if not case_id:
        out["error"] = f"create failed: {r}"
        return out

    reg = _req("POST", "/portal/api/evidence", {"path": str(src), "case_id": case_id})
    out["registered"] = bool(reg.get("sha256") or reg.get("status"))
    _req("POST", "/portal/api/case/mode", {"mode": "1", "case_id": case_id})

    headers = {"X-Nexus-Case": case_id}
    run = _req("POST", "/portal/api/pipeline/run", {"mode": "tools", "case_id": case_id})
    run_id = run.get("run_id")
    out["run_id"] = run_id
    deadline = time.time() + LANE_TIMEOUT_S
    status = ""
    while time.time() < deadline:
        st = _req("GET", f"/portal/api/pipeline/status?run_id={run_id}", headers=headers)
        status = str(st.get("status") or "")
        if status in ("complete", "error"):
            break
        time.sleep(5)
    out["status"] = status

    cdir = _case_dir(case_id)
    journals = sorted((cdir / "analysis" / "pipeline_runs").glob("*.progress.jsonl"))
    tallies = {"OK": 0, "SKIP": 0, "FAIL": 0}
    reasons = []
    if journals:
        for line in journals[-1].read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            s = str(row.get("status") or "").upper()
            if s in tallies and row.get("stage") == "tool":
                tallies[s] += 1
                if s == "FAIL":
                    reasons.append(str(row.get("reason") or row.get("detail") or "")[:100])
    out["lane"] = tallies
    out["fail_reasons"] = reasons[:4]

    gate_file = cdir / "analysis" / "lane_gate.json"
    out["gate"] = "blocked"
    if gate_file.is_file():
        try:
            gate = json.loads(gate_file.read_text(encoding="utf-8"))
            out["gate"] = str(gate.get("status") or "clear")
            out["gate_rows"] = int(gate.get("blocked_count") or 0)
        except (OSError, ValueError):
            out["gate"] = "unknown"

    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:9200/nexus-case-{case_id.lower()}/_count", timeout=15
        ) as resp:
            out["index_docs"] = json.loads(resp.read().decode()).get("count")
    except Exception as exc:  # noqa: BLE001
        out["index_docs"] = f"error: {str(exc)[:60]}"

    sys.path.insert(0, str(REPO / "src"))
    try:
        from nexus.analysis.reconciliation import reconcile_case

        rec = reconcile_case(cdir)
        t = rec.get("totals") or {}
        out["recon"] = {"files": t.get("files"), "match": t.get("match"),
                        "mismatch": t.get("mismatch"),
                        "fragmented": t.get("fragmented")}
        out["recon_files"] = [
            {k: f.get(k) for k in ("file", "source_records", "docs", "deduped",
                                   "delta", "status")}
            for f in (rec.get("files") or ())
            if f.get("status") in ("mismatch", "fragmented", "missing", "unreconcilable")
        ]
    except Exception as exc:  # noqa: BLE001
        out["recon"] = f"error: {str(exc)[:80]}"
    return out


def main(argv: list[str]) -> int:
    wanted = [a for a in argv if a in FORMATS] or FORMATS
    results = []
    for fmt in wanted:
        print(f"=== {fmt} ===", flush=True)
        row = run_format(fmt)
        results.append(row)
        print(json.dumps(row, indent=1, default=str), flush=True)
    out = REPO / "Docs" / "internal" / "sweep-results.json"
    out.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"\n{len(results)} format(s) -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
