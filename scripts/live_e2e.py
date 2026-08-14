"""Pass-1 live E2E against Evidence-files. Writes Evidence-files/RESULTS.md."""
from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EV = ROOT / "Evidence-files"
OUT = EV / "_e2e-out"
RESULTS = EV / "RESULTS.md"
sys.path.insert(0, str(ROOT / "src"))


def pick(rel: str) -> Path | None:
    p = EV / rel
    return p if p.is_file() else None


def first(glob: str) -> Path | None:
    hits = [p for p in EV.glob(glob) if p.is_file()]
    if not hits:
        return None
    return sorted(hits, key=lambda p: p.stat().st_size)[0]


def ingest_one(path: Path) -> dict:
    from nexus.ingest.detect import ingest_auto
    r = ingest_auto(path)
    r["rel"] = str(path.relative_to(EV))
    return r


def run_tool(name: str, args: list[str], timeout: int = 180) -> dict:
    from nexus.tools.windows import _find_binary
    exe = _find_binary(name)
    if not exe:
        return {"tool": name, "ok": False, "error": "not resolved"}
    cmd = [exe, *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=str(OUT))
        return {
            "tool": name,
            "ok": proc.returncode == 0,
            "exe": exe,
            "rc": proc.returncode,
            "stdout": (proc.stdout or "")[:800],
            "stderr": (proc.stderr or "")[:400],
        }
    except Exception as exc:
        return {"tool": name, "ok": False, "exe": exe, "error": str(exc)}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    started = datetime.now(UTC).isoformat()

    ingest_targets: list[Path] = []
    for rel in (
        "04-network/suricata/eve.json",
        "04-network/zeek/conn.log",
        "05-siem/elastic.ndjson",
        "05-siem/cadre-elk/elastic-security-4624.ndjson",
        "05-siem/wazuh.json",
        "03-linux/auth.log",
        "03-linux/audit.log",
        "06-cloud/cloudtrail-sample.json",
        "06-cloud/azure-activity-sample.json",
        "06-cloud/m365-ual-sample.json",
        "07-ti/vt-sample.json",
        "07-ti/otx-pulse.json",
        "07-ti/misp-event.json",
        "07-ti/abuseipdb-sample.json",
        "08-ir-platforms/thehive-case.json",
        "08-ir-platforms/iris-case.json",
        "08-ir-platforms/sandbox-report.json",
    ):
        p = pick(rel)
        if p:
            ingest_targets.append(p)
    for g in (
        "01-windows/evtx/**/*.evtx",
        "01-windows/prefetch/**/*.pf",
        "01-windows/lnk/**/*.lnk",
        "01-windows/amcache/**/*.hve",
        "01-windows/registry/**/*",
    ):
        p = first(g)
        if p and p.is_file():
            ingest_targets.append(p)

    ingest_rows = []
    for t in ingest_targets:
        print(f"INGEST {t.relative_to(EV)}")
        ingest_rows.append(ingest_one(t))

    evtx = first("01-windows/evtx/**/*.evtx")
    pf = first("01-windows/prefetch/**/*.pf")
    lnk = first("01-windows/lnk/**/*.lnk")
    hve = first("01-windows/amcache/**/*.hve")

    tool_rows = []
    if pf:
        print(f"TOOL PECmd {pf.name}")
        tool_rows.append(run_tool("PECmd", ["-f", str(pf), "--csv", str(OUT / "pecmd")]))
    if evtx:
        print(f"TOOL EvtxECmd {evtx.name}")
        (OUT / "evtx").mkdir(exist_ok=True)
        tool_rows.append(run_tool("EvtxECmd", ["-f", str(evtx), "--csv", str(OUT / "evtx")]))
    if lnk:
        print(f"TOOL LECmd {lnk.name}")
        (OUT / "lnk").mkdir(exist_ok=True)
        tool_rows.append(run_tool("LECmd", ["-f", str(lnk), "--csv", str(OUT / "lnk")]))
    if hve:
        print(f"TOOL AmcacheParser {hve.name}")
        (OUT / "amcache").mkdir(exist_ok=True)
        tool_rows.append(run_tool("AmcacheParser", ["-f", str(hve), "--csv", str(OUT / "amcache")]))

    case_row: dict = {}
    try:
        from nexus.cli.case_cmd import _get_sqlite_mgr, _set_active_case
        mgr = _get_sqlite_mgr()
        case = mgr.create_case(name="E2E-2026-08-11", description="Agent pass-1 live E2E")
        _set_active_case(case.id)
        ev_path = evtx or ingest_targets[0]
        # register via CLI module internals is messy; hash + store if API exists
        case_row = {"ok": True, "case_id": case.id, "name": case.name, "evidence_note": str(ev_path)}
        print(f"CASE {case.id}")
    except Exception as exc:
        case_row = {"ok": False, "error": str(exc)}
        print(f"CASE FAIL {exc}")

    ok_in = sum(1 for r in ingest_rows if r.get("success"))
    fail_in = [r for r in ingest_rows if not r.get("success")]
    ok_tool = sum(1 for r in tool_rows if r.get("ok"))

    lines = [
        "# RESULTS — agent pass-1 E2E (2026-08-11)",
        "",
        f"Started (UTC): `{started}`",
        f"Finished (UTC): `{datetime.now(UTC).isoformat()}`",
        "",
        "This is **pass 1** (agent). Operator manual passes are 2+. Does **not** satisfy COMPLETE-TO-SHIP 12/12.",
        "",
        "## Summary",
        "",
        f"- ingest files: {ok_in}/{len(ingest_rows)} success",
        f"- windows tools: {ok_tool}/{len(tool_rows)} rc=0",
        f"- case init: {'ok ' + case_row.get('case_id','') if case_row.get('ok') else 'FAIL ' + str(case_row.get('error'))}",
        "",
        "## Ingest",
        "",
        "| ok | artifacts | source | path | error |",
        "|----|-----------|--------|------|-------|",
    ]
    for r in ingest_rows:
        err = (r.get("error") or "; ".join(r.get("errors") or []))[:120]
        lines.append(
            f"| {'yes' if r.get('success') else 'no'} | {r.get('artifacts', 0)} | {r.get('source','')} | `{r.get('rel')}` | {err} |"
        )
    lines += ["", "## Windows tools", "", "| ok | tool | rc | note |", "|----|------|----|------|"]
    for r in tool_rows:
        note = r.get("error") or (r.get("stderr") or r.get("stdout") or "")[:160].replace("\n", " ")
        lines.append(f"| {'yes' if r.get('ok') else 'no'} | {r.get('tool')} | {r.get('rc','')} | {note} |")
    lines += [
        "",
        "## Case",
        "",
        "```json",
        json.dumps(case_row, indent=2),
        "```",
        "",
        "## Not covered this pass",
        "",
        "- SIFT install + `nexus serve :4508` + `setup client --sift`",
        "- MCP HTTP `/mcp` + portal approve",
        "- TI live lookups / Sigma MCP / VR hunts",
        "- `nexus data download-*`",
        "- Full 43-importer fixture matrix + 12-pass ledger",
        "",
    ]
    RESULTS.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {RESULTS}")
    print(f"ingest {ok_in}/{len(ingest_rows)} tools {ok_tool}/{len(tool_rows)}")
    return 0 if fail_in == [] and ok_tool == len(tool_rows) and case_row.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
