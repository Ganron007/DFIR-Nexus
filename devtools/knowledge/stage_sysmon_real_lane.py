"""WO-KR2c 0d: stage the Sysmon log and run the REAL EvtxECmd lane on the SIFT host.

The WO: "Sysmon: <path under _k1-datasets/benign>, run through the real EvtxECmd
lane." Not a python parser, not an agent's recollection - the tool that produced the
existing `outputs/evtxecmd` CSV.

The SIFT host has EvtxECmd at /usr/local/bin (that is the lane the operator's corpus
was built with, per the argv recorded in es_mappings/evtxecmd.yaml). So: copy the log
there, run it, pull the CSV back, and report what it actually parses - the event IDs
present and the generic columns it fills, which is the thing KR2c needs.

Nothing here scores anything; it is staging for the population check.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
KEY = Path("C:/Users/Ganro/.ssh/cadre-sift-key")
HOST = "sansforensics@192.168.77.135"
REMOTE_DIR = "/tmp/kr2c-sysmon"

#: The log the WO names.
SYS = (REPO / "Evidence-files" / "_k1-datasets" / "benign" / "win10-client"
       / "Logs_Client" / "Microsoft-Windows-Sysmon%4Operational.evtx")
OUT_DIR = REPO / "Evidence-files" / "ES-Mapping" / "outputs" / "evtxecmd-sysmon"
REPORT = REPO / "Evidence-files" / "ES-Mapping" / "es_mappings" / "_sysmon_population.json"

SSH = ["ssh", "-i", str(KEY), "-o", "ConnectTimeout=15", "-o", "BatchMode=yes", HOST]


def _ssh(*args: str, timeout: int = 600) -> tuple[int, str]:
    proc = subprocess.run([*SSH, " ".join(args)], capture_output=True, text=True,
                          timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _scp(local: Path, remote: str, timeout: int = 900) -> tuple[int, str]:
    proc = subprocess.run(["scp", "-i", str(KEY), "-o", "ConnectTimeout=15",
                           "-o", "BatchMode=yes", str(local), f"{HOST}:{remote}"],
                          capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _pull(remote: str, local: Path, timeout: int = 900) -> tuple[int, str]:
    proc = subprocess.run(["scp", "-i", str(KEY), "-o", "ConnectTimeout=15",
                           "-o", "BatchMode=yes", f"{HOST}:{remote}", str(local)],
                          capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def main() -> int:
    if not SYS.is_file():
        print(f"  Sysmon log absent at {SYS} - record the absence, do not substitute")
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    rc, out = _ssh(f"mkdir -p {REMOTE_DIR}/in {REMOTE_DIR}/out")
    if rc != 0:
        print("  SIFT host unreachable:", out[-300:])
        return 3
    rc, out = _scp(SYS, f"{REMOTE_DIR}/in/sysmon.evtx")
    if rc != 0:
        print("  scp failed:", out[-300:])
        return 3
    print(f"  staged {SYS.name} to the SIFT host")

    rc, out = _ssh(f"cd {REMOTE_DIR} && EvtxECmd -d {REMOTE_DIR}/in "
                   f"--csv {REMOTE_DIR}/out 2>&1 | tail -20")
    print("  EvtxECmd:", out[-600:])

    rc, listing = _ssh(f"ls -l {REMOTE_DIR}/out")
    print("  remote out:", listing[-400:])
    rc, _ = _pull(f"{REMOTE_DIR}/out/*.csv", OUT_DIR)
    local = sorted(OUT_DIR.glob("*.csv"))
    print(f"  pulled {len(local)} csv file(s)")

    report = {"sysmon_log": SYS.name, "remote_out": listing[-500:],
              "csv_files": [p.name for p in local], "rows": 0,
              "event_ids": {}, "generic_columns_filled": {}}
    if local:
        import collections
        import csv

        for path in local:
            with open(path, encoding="utf-8-sig", errors="replace") as fh:
                rows = list(csv.reader(fh))
            hdr = [h.strip().lower() for h in rows[0]]
            i_ev = hdr.index("eventid") if "eventid" in hdr else None
            report["rows"] += max(0, len(rows) - 1)
            if i_ev is None:
                continue
            ev = collections.Counter(r[i_ev] for r in rows[1:]
                                     if len(r) > i_ev and r[i_ev])
            report["event_ids"] = dict(sorted(ev.items(), key=lambda kv: -kv[1]))
            generic = [h for h in hdr if h.startswith(("payloaddata", "executable",
                                                       "username", "remotehost"))]
            filled = {}
            for h in generic:
                i = hdr.index(h)
                filled[h] = sum(1 for r in rows[1:] if len(r) > i and (r[i] or "").strip())
            report["generic_columns_filled"] = filled

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(f"  rows: {report['rows']}  event ids: {report['event_ids']}")
    print(f"  generic columns filled: {report['generic_columns_filled']}")
    print(f"  written: {REPORT.relative_to(REPO)}")

    rc, _ = _ssh(f"rm -rf {REMOTE_DIR}")
    print("  remote cleaned up")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
