"""R17-R19 segregation probe: every mode-owned route vs each stored mode.

Drives the dashboard's real route table against three minimal cases (one per
stored mode): a case stored in mode X must answer **409** on every route owned
by another mode; same-mode GET reads are recorded as controls (not blocked).

Usage:  python scripts/seg_probe_409.py CASE-BED89CCB CASE-1AF5FC2D CASE-FFE10C94
Writes Docs/internal/seg-probe.json.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BASE = "http://127.0.0.1:4508"
PARAM_RE = re.compile(r"\{[^}]+\}")


def enumerate_routes() -> list[tuple[str, str]]:
    """(path, method) for every mode-owned dashboard route."""
    sys.path.insert(0, str(REPO / "src"))
    from nexus.dashboard.app import create_dashboard

    out: list[tuple[str, str]] = []
    for route in create_dashboard():
        path = str(getattr(route, "path", ""))
        if "/portal/api/mode" not in path:
            continue
        methods = [
            m for m in sorted(getattr(route, "methods", None) or [])
            if m in ("GET", "POST", "PUT", "DELETE", "PATCH")
        ]
        if not methods:
            continue
        out.append((path, methods[0]))
    return out


def _mode_of(path: str) -> str:
    if "/mode1/" in path:
        return "1"
    if "/mode2/" in path:
        return "2"
    if "/mode3/" in path:
        return "3"
    return ""


def _request(method: str, path: str, case_id: str) -> tuple[int, str]:
    url = BASE + PARAM_RE.sub("probe-00000000", path)
    data = None if method == "GET" else b"{}"
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "X-Nexus-Case": case_id},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read(200).decode(errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(200).decode(errors="replace")
    except Exception as exc:  # noqa: BLE001
        return -1, str(exc)[:120]


def main(argv: list[str]) -> int:
    cases = sys.argv[1:]
    if not cases:
        print("usage: python scripts/seg_probe_409.py CASE-... [CASE-...]")
        return 2
    routes = enumerate_routes()
    by_mode = {m: [(p, meth) for p, meth in routes if _mode_of(p) == m] for m in ("1", "2", "3")}
    print(f"routes: mode1={len(by_mode['1'])} mode2={len(by_mode['2'])} mode3={len(by_mode['3'])}")

    # Stored mode per case from CASE.yaml (investigation_mode).
    import yaml

    results = []
    total = cross_ok = 0
    for case_id in cases:
        meta = yaml.safe_load((REPO / "cases" / case_id / "CASE.yaml").read_text(encoding="utf-8")) or {}
        stored = str(meta.get("investigation_mode") or "")
        row = {"case_id": case_id, "stored_mode": stored, "cross": [], "controls": []}
        for mode, entries in by_mode.items():
            if mode == stored:
                continue
            for path, method in entries:
                status, body = _request(method, path, case_id)
                total += 1
                ok = status == 409
                cross_ok += 1 if ok else 0
                row["cross"].append({
                    "path": path, "method": method, "expect": "409",
                    "status": status, "ok": ok, "body": body[:80],
                })
        for path, method in by_mode.get(stored, []):
            if method != "GET":
                continue  # never start a same-mode run from a probe
            status, body = _request(method, path, case_id)
            row["controls"].append({"path": path, "method": "GET", "status": status})
        failed = [c for c in row["cross"] if not c["ok"]]
        print(f"{case_id} stored=Mode {stored}: cross={len(row['cross'])} "
              f"409={len(row['cross']) - len(failed)} failed={len(failed)} "
              f"controls={len(row['controls'])}")
        for c in failed:
            print(f"    FAIL {c['method']} {c['path']} -> {c['status']} {c['body'][:60]}")
        results.append(row)

    out = REPO / "Docs" / "internal" / "seg-probe.json"
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\nTOTAL cross-mode probes: {cross_ok}/{total} answered 409 -> {out}")
    return 0 if cross_ok == total else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
