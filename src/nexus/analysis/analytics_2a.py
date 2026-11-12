"""T2-3 to T2-9 — 2A Advanced Forensic Analytics.

Provides deterministic, evidence-grounded analytics across:
- T2-3: Typo-tolerant fuzzy search, column stacking, frequency distribution & rare-value flagging.
- T2-4: Process-tree reconstruction (parent/child relationships across hosts).
- T2-5: Process-ancestry expectations and chain scoring.
- T2-6: Identity-centric lateral analytics (account-hopping and multi-host logons).
- T2-7: Impact / ransomware analytics (burst renames, high entropy extensions, ransom notes).
- T2-8: Anti-forensics analytics (timestomp drift detection between $SI and $FN, log-clearing gaps).
- T2-9: NTFS depth analytics (Mark-of-the-Web ADS extraction, resident data analysis).
"""

from __future__ import annotations

import collections
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Suspicious parent-child process pairs (Parent -> list of suspicious children)
_ABNORMAL_SPAWNS: dict[str, list[str]] = {
    "w3wp.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "certutil.exe", "whoami.exe"],
    "httpd.exe": ["cmd.exe", "powershell.exe", "sh", "bash", "python.exe"],
    "nginx.exe": ["cmd.exe", "powershell.exe", "sh", "bash"],
    "sqlservr.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "bitsadmin.exe"],
    "wmiprvse.exe": ["powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"],
    "spoolsv.exe": ["cmd.exe", "powershell.exe"],
}

# Protected Windows processes and their required parent
_EXPECTED_PARENTS: dict[str, str] = {
    "services.exe": "wininit.exe",
    "lsass.exe": "wininit.exe",
    "svchost.exe": "services.exe",
    "smss.exe": "system",
}

_RANSOM_NOTE_RE = re.compile(
    r"(?i)\b(read[_\s-]?me|how[_\s-]?to[_\s-]?decrypt|decrypt[_\s-]?instructions|restore[_\s-]?files)\.(txt|html|hta)\b"
)
_ENCRYPTED_EXT_RE = re.compile(
    r"(?i)\.(locked|crypto|enc|encrypted|crypted|lockbit|blackcat|alphv|rhysida|akira)$"
)


# ============================================================================
# T2-3: Search & Distribution Analytics (Stacking, Rarity, Fuzzy Matching)
# ============================================================================


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)

    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0[:] = v1[:]

    return v1[len(s2)]


def fuzzy_search(needle: str, candidates: list[str], max_distance: int = 2) -> list[dict[str, Any]]:
    """Find candidates within edit distance of needle (detects typo-squatting and obfuscation)."""
    needle_lower = needle.lower().strip()
    matches: list[dict[str, Any]] = []

    for c in candidates:
        c_lower = c.lower().strip()
        dist = levenshtein_distance(needle_lower, c_lower)
        if 0 < dist <= max_distance:
            matches.append({
                "candidate": c,
                "target": needle,
                "distance": dist,
                "is_typosquat": True,
            })

    return sorted(matches, key=lambda x: x["distance"])


def column_frequency_stack(
    values: list[Any],
    rare_threshold_pct: float = 5.0,
) -> dict[str, Any]:
    """Compute frequency distribution and flag rare outliers (stacking analysis)."""
    if not values:
        return {"total_count": 0, "unique_count": 0, "frequencies": [], "rare_values": []}

    counts = collections.Counter(str(v).strip() for v in values if v not in (None, ""))
    total = sum(counts.values())
    freqs: list[dict[str, Any]] = []
    rare: list[dict[str, Any]] = []

    for val, count in counts.most_common():
        pct = (count / total) * 100.0 if total > 0 else 0.0
        entry = {"value": val, "count": count, "percent": round(pct, 2), "is_rare": pct <= rare_threshold_pct}
        freqs.append(entry)
        if entry["is_rare"]:
            rare.append(entry)

    return {
        "total_count": total,
        "unique_count": len(counts),
        "frequencies": freqs,
        "rare_values": rare,
    }


# ============================================================================
# T2-4 & T2-5: Process Tree Reconstruction & Ancestry Scoring
# ============================================================================


def reconstruct_process_tree(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Reconstruct parent-child process execution trees across events."""
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    for ev in events:
        pid = str(ev.get("pid") or ev.get("process_id") or "").strip()
        ppid = str(ev.get("ppid") or ev.get("parent_process_id") or "").strip()
        name = str(ev.get("process_name") or ev.get("image") or ev.get("name") or "unknown").strip()
        parent_name = str(ev.get("parent_process_name") or ev.get("parent_image") or "").strip()
        host = str(ev.get("host") or "").strip()
        ts = str(ev.get("timestamp") or "")

        node_id = f"{host}:{pid}:{name}" if pid else f"{host}:{name}:{ts}"
        if node_id not in nodes:
            nodes[node_id] = {
                "id": node_id,
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "parent_name": parent_name,
                "host": host,
                "timestamp": ts,
                "children": [],
            }

        if ppid and parent_name:
            parent_id = f"{host}:{ppid}:{parent_name}"
            edges.append({
                "source": parent_id,
                "target": node_id,
                "parent_name": parent_name,
                "child_name": name,
            })

    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def score_process_ancestry(parent_image: str, child_image: str) -> dict[str, Any]:
    """Score process parent-child legitimacy and flag anomalous ancestry."""
    p = Path(parent_image).name.lower()
    c = Path(child_image).name.lower()

    # Rule 1: Check expected system parents
    if c in _EXPECTED_PARENTS:
        expected = _EXPECTED_PARENTS[c]
        if p != expected:
            return {
                "suspicious": True,
                "score": 95,
                "rule": "illegal_system_parent",
                "reason": f"Protected system binary '{c}' spawned by '{p}' instead of '{expected}'",
            }

    # Rule 2: Check web/database servers spawning shells/interpreters
    if p in _ABNORMAL_SPAWNS and c in _ABNORMAL_SPAWNS[p]:
        return {
            "suspicious": True,
            "score": 90,
            "rule": "server_shell_spawn",
            "reason": f"Server process '{p}' spawned shell/interpreter '{c}' (potential web shell or RCE)",
        }

    return {"suspicious": False, "score": 10, "rule": "normal_ancestry", "reason": "Expected or unmonitored pairing"}


# ============================================================================
# T2-6: Identity-Centric Lateral Analytics (Account-Hopping)
# ============================================================================


def detect_account_hopping(
    logon_events: list[dict[str, Any]],
    window_seconds: int = 3600,
    min_hosts: int = 2,
) -> list[dict[str, Any]]:
    """Detect accounts authenticating across multiple distinct hosts within a time window."""
    by_user: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)

    for ev in logon_events:
        user = str(ev.get("user") or ev.get("username") or "").strip().lower()
        host = str(ev.get("host") or ev.get("computer") or ev.get("target_host") or "").strip().lower()
        ts_str = str(ev.get("timestamp") or "")

        if not user or not host or user.endswith("$") or "anonymous" in user:
            continue

        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except ValueError:
            continue

        by_user[user].append({"host": host, "timestamp": ts, "raw": ev})

    hops: list[dict[str, Any]] = []

    for user, events in by_user.items():
        events.sort(key=lambda x: x["timestamp"])
        for i in range(len(events)):
            start_ev = events[i]
            window_hosts = {start_ev["host"]}
            involved = [start_ev]

            for j in range(i + 1, len(events)):
                next_ev = events[j]
                if (next_ev["timestamp"] - start_ev["timestamp"]).total_seconds() > window_seconds:
                    break
                window_hosts.add(next_ev["host"])
                involved.append(next_ev)

            if len(window_hosts) >= min_hosts:
                hops.append({
                    "user": user,
                    "host_count": len(window_hosts),
                    "hosts": sorted(window_hosts),
                    "start_time": start_ev["timestamp"].isoformat(),
                    "event_count": len(involved),
                    "is_account_hopping": True,
                })
                break

    return hops


# ============================================================================
# T2-7: Impact / Ransomware Analytics
# ============================================================================


def detect_ransomware_patterns(
    file_events: list[dict[str, Any]],
    burst_window_seconds: int = 60,
    burst_threshold: int = 20,
) -> dict[str, Any]:
    """Detect ransomware characteristics: mass renames, ransom notes, and encrypted extensions."""
    ransom_notes: list[dict[str, Any]] = []
    encrypted_files: list[dict[str, Any]] = []
    renames: list[dict[str, Any]] = []

    for ev in file_events:
        path_str = str(ev.get("path") or ev.get("file_path") or ev.get("name") or "")
        action = str(ev.get("action") or ev.get("event") or "").lower()

        if _RANSOM_NOTE_RE.search(path_str):
            ransom_notes.append({"path": path_str, "event": ev})

        if _ENCRYPTED_EXT_RE.search(path_str):
            encrypted_files.append({"path": path_str, "event": ev})

        if "rename" in action or "modify" in action:
            renames.append(ev)

    # Check for burst activity
    has_burst = len(renames) >= burst_threshold or len(encrypted_files) >= burst_threshold

    confidence = "none"
    if ransom_notes and (encrypted_files or has_burst):
        confidence = "critical"
    elif ransom_notes or encrypted_files:
        confidence = "high"
    elif has_burst:
        confidence = "medium"

    return {
        "confidence": confidence,
        "is_ransomware_detected": confidence in ("critical", "high"),
        "ransom_note_count": len(ransom_notes),
        "encrypted_file_count": len(encrypted_files),
        "rename_burst_detected": has_burst,
        "sample_ransom_notes": [n["path"] for n in ransom_notes[:5]],
        "sample_encrypted": [e["path"] for e in encrypted_files[:5]],
    }


# ============================================================================
# T2-8: Anti-Forensics Analytics (Timestomp Drift & Log Clearing)
# ============================================================================


def detect_timestomp_drift(
    si_mtime: str | datetime,
    fn_mtime: str | datetime,
    drift_threshold_seconds: int = 60,
) -> dict[str, Any]:
    """Detect timestomping by comparing NTFS $STANDARD_INFORMATION and $FILE_NAME timestamps.

    In Windows NTFS, $SI can be modified by user-mode APIs (SetFileTime), but $FN
    is updated only by the kernel. If $SI is significantly older than $FN, or $SI
    has zero nanoseconds/subsecond precision, timestomping is indicated.
    """
    def _to_dt(val: str | datetime) -> datetime | None:
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=UTC)
        try:
            return datetime.fromisoformat(str(val).replace("Z", "+00:00"))
        except ValueError:
            return None

    dt_si = _to_dt(si_mtime)
    dt_fn = _to_dt(fn_mtime)

    if not dt_si or not dt_fn:
        return {"timestomped": False, "reason": "Unparseable timestamps"}

    diff_seconds = (dt_fn - dt_si).total_seconds()
    zero_subseconds = dt_si.microsecond == 0 and dt_fn.microsecond != 0

    is_drift = diff_seconds > drift_threshold_seconds
    is_timestomped = is_drift or zero_subseconds

    reasons: list[str] = []
    if is_drift:
        reasons.append(f"$SI is older than $FN by {int(diff_seconds)}s (kernel $FN was not backdated)")
    if zero_subseconds:
        reasons.append("$SI subsecond precision is exactly zero (typical of basic timestomping utilities)")

    return {
        "timestomped": is_timestomped,
        "si_timestamp": dt_si.isoformat(),
        "fn_timestamp": dt_fn.isoformat(),
        "drift_seconds": diff_seconds,
        "zero_subseconds": zero_subseconds,
        "reasons": reasons,
    }


# ============================================================================
# T2-9: NTFS Recovery Depth Analytics (Mark-of-the-Web / ADS Extraction)
# ============================================================================


def extract_motw_urls(zone_identifier_content: str) -> dict[str, str]:
    """Extract Mark-of-the-Web (Zone.Identifier) alternate data stream metadata.

    Extracts ZoneId (3=Internet, 4=Restricted), ReferrerUrl, and HostUrl.
    """
    out: dict[str, str] = {
        "zone_id": "",
        "zone_name": "Unknown",
        "referrer_url": "",
        "host_url": "",
    }

    if not zone_identifier_content:
        return out

    zone_names = {
        "0": "My Computer",
        "1": "Local Intranet",
        "2": "Trusted Sites",
        "3": "Internet",
        "4": "Restricted Sites",
    }

    for line in zone_identifier_content.splitlines():
        line = line.strip()
        if not line or line.startswith("["):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            k_lower = key.strip().lower()
            v = val.strip()
            if k_lower == "zoneid":
                out["zone_id"] = v
                out["zone_name"] = zone_names.get(v, f"Zone {v}")
            elif k_lower in ("referrerurl", "referrer_url"):
                out["referrer_url"] = v
            elif k_lower in ("hosturl", "host_url"):
                out["host_url"] = v

    return out
