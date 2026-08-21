"""YAML artifact → filesystem discovery (SSoT for tools/coverage lanes).

Knowledge files under ``src/nexus/data/knowledge/artifacts/windows/*.yaml``
declare ``locations`` and ``related_tools``. The planner globs those
locations against a Windows image root and reports present / absent.
Argv construction stays in ``tool_lane.py`` (tool-specific flags).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SKIP_USERS = {"Default", "Default User", "Public", "All Users", "desktop.ini"}
_USER_PLACEHOLDERS = re.compile(
    r"\{username\}|\{user\}|<username>|<user>|\{SID\}|\{sid\}|\{guid\}|\{profile\}",
    re.IGNORECASE,
)
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_HIVE_PREFIXES = (
    "NTUSER.DAT\\",
    "NTUSER.DAT/",
    "USRCLASS.DAT\\",
    "USRCLASS.DAT/",
    "SYSTEM\\",
    "SOFTWARE\\",
    "HKLM\\",
    "HKCU\\",
)


@dataclass
class ArtifactHit:
    """One YAML artifact vs this evidence root."""

    name: str
    slug: str
    related_tools: list[str]
    present: bool
    hits: list[Path] = field(default_factory=list)
    locations: list[str] = field(default_factory=list)
    reason: str = ""


def user_profile_dirs(root: Path) -> list[Path]:
    """Every real user profile under ``Users`` (not Default/Public)."""
    users = root / "Users"
    if not users.is_dir():
        return []
    out: list[Path] = []
    try:
        for p in sorted(users.iterdir()):
            if p.is_dir() and p.name not in _SKIP_USERS:
                out.append(p)
    except OSError:
        return []
    return out


def _to_relative_glob(path_str: str) -> str | None:
    """Turn a YAML location into a glob relative to the Windows image root.

    Returns None when the location is not a filesystem path we can glob
    (registry-only prose, 'any file', GPO text, etc.).
    """
    raw = (path_str or "").strip().strip('"')
    if not raw:
        return None
    lower = raw.lower()
    if lower.startswith("$mft"):
        return "$MFT"
    if lower.startswith("$logfile"):
        return "$LogFile"
    if lower.startswith("$recycle.bin") or "\\$recycle.bin" in lower or "/$recycle.bin" in lower:
        return "$Recycle.Bin"
    if "usnjrnl" in lower or "$extend" in lower:
        return "$Extend/$UsnJrnl:$J"
    if raw.startswith("$"):
        return None
    if any(
        k in lower
        for k in (
            "any file",
            "embedded in",
            "configured via",
            "part of the executable",
            "attribute of every",
            "root of each ntfs",
        )
    ):
        return None
    if raw.upper().startswith(_HIVE_PREFIXES) or raw.upper().startswith("SYSTEM\\"):
        return None
    if raw.upper().startswith("HKLM") or raw.upper().startswith("HKCU"):
        return None
    if _DRIVE.match(raw):
        raw = raw[2:].lstrip("\\/")
    raw = raw.replace("\\", "/")
    raw = _USER_PLACEHOLDERS.sub("*", raw)
    raw = re.sub(r"%[0-9A-Fa-f]{2}", "*", raw)  # URL-encoded evtx names stay literal; %4 → *
    # Evtx YAML uses %4 for '/' in log names — restore
    raw = raw.replace("*Operational.evtx", "*Operational.evtx")
    if not raw or raw.startswith("{"):
        return None
    return raw


def _hive_hits(root: Path, path_str: str, users: list[Path]) -> list[Path]:
    """Registry YAML paths → hive files that actually exist."""
    raw = (path_str or "").strip()
    upper = raw.upper()
    hits: list[Path] = []
    if upper.startswith("NTUSER.DAT"):
        for user in users:
            nt = user / "NTUSER.DAT"
            if nt.is_file():
                hits.append(nt)
        return hits
    if upper.startswith("USRCLASS.DAT"):
        for user in users:
            uc = user / "AppData/Local/Microsoft/Windows/UsrClass.dat"
            if uc.is_file():
                hits.append(uc)
        return hits
    if upper.startswith("SYSTEM\\") or upper.startswith("HKLM\\SYSTEM"):
        hive = root / "Windows/System32/config/SYSTEM"
        return [hive] if hive.is_file() else []
    if upper.startswith("SOFTWARE\\") or upper.startswith("HKLM\\SOFTWARE"):
        hive = root / "Windows/System32/config/SOFTWARE"
        return [hive] if hive.is_file() else []
    return []


def glob_location(root: Path, path_str: str, users: list[Path] | None = None) -> list[Path]:
    """Resolve one YAML location against ``root``. Empty = not present."""
    users = users if users is not None else user_profile_dirs(root)
    hive = _hive_hits(root, path_str, users)
    if hive:
        return hive
    rel = _to_relative_glob(path_str)
    if not rel:
        return []
    # Recycle / MFT specials
    if rel == "$MFT":
        p = root / "$MFT"
        return [p] if p.is_file() else []
    if rel == "$LogFile":
        p = root / "$LogFile"
        return [p] if p.is_file() else []
    if rel == "$Recycle.Bin":
        p = root / "$Recycle.Bin"
        return [p] if p.is_dir() else []
    # USN $J is an ADS on live NTFS; KAPE/triage packs extract it as a file.
    if "usnjrnl" in rel.lower() or rel.rstrip("/").endswith("$J"):
        for cand in (
            root / "$Extend" / "$UsnJrnl:$J",
            root / "$Extend" / "$J",
            root / "$J",
        ):
            if cand.is_file():
                return [cand]
        ext = root / "$Extend"
        if ext.is_dir():
            try:
                for p in ext.iterdir():
                    if p.is_file() and "usn" in p.name.lower():
                        return [p]
            except OSError:
                pass
        return []
    try:
        found = [p for p in root.glob(rel) if p.exists()]
    except (OSError, ValueError):
        found = []
    if found:
        return found[:80]
    # Directory present but glob empty (e.g. Prefetch\\*.pf with no .pf yet)
    if "*" in rel or "?" in rel:
        parent_rel = rel.rsplit("/", 1)[0] if "/" in rel else ""
        if parent_rel:
            try:
                parents = [p for p in root.glob(parent_rel) if p.is_dir()]
            except (OSError, ValueError):
                parents = []
            if parents:
                return parents[:80]
            pdir = root / parent_rel
            if "*" not in parent_rel and "?" not in parent_rel and pdir.is_dir():
                return [pdir]
    return []


def _slug(art: dict[str, Any]) -> str:
    name = str(art.get("name") or "")
    return name.lower().replace(" ", "_").replace("-", "_")


def discover_windows_artifacts(root: Path) -> list[ArtifactHit]:
    """Evaluate every Windows artifact YAML against this image root."""
    from nexus.knowledge.loader import list_artifacts

    users = user_profile_dirs(root)
    out: list[ArtifactHit] = []
    for art in list_artifacts(platform="windows"):
        if not isinstance(art, dict):
            continue
        name = str(art.get("name") or "unknown")
        tools = [str(t) for t in (art.get("related_tools") or []) if t]
        locs = []
        for loc in art.get("locations") or []:
            if isinstance(loc, dict) and loc.get("path"):
                locs.append(str(loc["path"]))
            elif isinstance(loc, str):
                locs.append(loc)
        hits: list[Path] = []
        globbable = False
        for loc in locs:
            globbable = True
            hits.extend(glob_location(root, loc, users))
        # Implicit filesystem for shellbags (YAML is registry-only)
        if _slug(art) == "shellbags":
            globbable = True
            for user in users:
                uc = user / "AppData/Local/Microsoft/Windows/UsrClass.dat"
                if uc.is_file():
                    hits.append(uc)
        # Dedup hits
        uniq: list[Path] = []
        seen: set[str] = set()
        for h in hits:
            key = str(h)
            if key not in seen:
                seen.add(key)
                uniq.append(h)
        present = bool(uniq)
        reason = ""
        if not locs and not present:
            reason = "YAML has no globbable locations"
        elif globbable and not present:
            reason = "artifact not present on this evidence"
        elif not globbable and not present:
            reason = "location is not a filesystem path (registry/prose)"
            # hive_hits already ran; if still empty, absent
        out.append(ArtifactHit(
            name=name,
            slug=_slug(art),
            related_tools=tools,
            present=present,
            hits=uniq,
            locations=locs,
            reason=reason if not present else f"{len(uniq)} hit(s)",
        ))
    return out


def invokable_tool_key(name: str) -> str:
    """Normalize YAML related_tools names to planner keys."""
    n = name.strip().lower().replace(" ", "")
    aliases = {
        "pecmd": "pecmd",
        "evtxecmd": "evtxecmd",
        "hayabusa": "hayabusa",
        "lecmd": "lecmd",
        "jlecmd": "jlecmd",
        "amcacheparser": "amcacheparser",
        "appcompatcacheparser": "appcompatcacheparser",
        "srumecmd": "srumecmd",
        "mftecmd": "mftecmd",
        "sqlecmd": "sqlecmd",
        "sbecmd": "sbecmd",
        "wxtcmd": "wxtcmd",
        "rbcmd": "rbcmd",
        "recmd": "recmd",
        "regripper": "recmd",
        "hindsight": "sqlecmd",
        "browsinghistoryview": "sqlecmd",
        "dbbrowserforsqlite": "sqlecmd",
        "autoruns": "recmd",
        "autorunsc": "recmd",
        "suzaku": "suzaku",
        "chainsaw": "chainsaw",
        "volatility3": "vol",
        "vol3": "vol",
        "vol": "vol",
        "fls": "fls",
        "mactime": "mactime",
        "kape": "kape",
        "sigcheck": "sigcheck",
        "maldump": "maldump",
        "strings": "strings",
        "yara": "yara",
        "icat": "icat",
        "vshadowinfo": "vshadowinfo",
        "vshadowmount": "vshadowmount",
        "journalctl": "journalctl",
        "last": "last",
        "bmc-tools": "bmc-tools",
        "bmctools": "bmc-tools",
        "thumbcache_viewer": "thumbcache_viewer",
        "thumbcacheviewer": "thumbcache_viewer",
        "thumbcache_viewer_cmd": "thumbcache_viewer",
        "bitsparser": "bitsparser",
        "kstrike": "kstrike",
        "logfileparser": "logfileparser",
        "logfileparser64": "logfileparser",
        "esedbexport": "esedbexport",
        "tshark": "tshark",
        "exiftool": "exiftool",
        "vssadmin": "vssadmin",
    }
    return aliases.get(n, n)


def completeness_table(
    hits: list[ArtifactHit],
    scheduled_tools: set[str],
    ledger: list[dict[str, Any]] | None = None,
) -> list[dict[str, str]]:
    """Examiner rows: absent / parsed / fail / still queued / staged / no parser."""
    rows = []
    scheduled_l = {invokable_tool_key(t) for t in scheduled_tools}
    ran: dict[str, str] = {}
    rank = {"OK": 3, "FAIL": 2, "SKIP": 1, "PENDING": 0}
    for row in ledger or []:
        key = invokable_tool_key(str(row.get("tool") or ""))
        st = str(row.get("status") or "").upper()
        if not key or st not in rank:
            continue
        if rank[st] >= rank.get(ran.get(key, ""), 0):
            ran[key] = st
    for h in hits:
        keys = {invokable_tool_key(t) for t in h.related_tools}
        covered = bool(keys & scheduled_l)
        ran_hit = [ran[k] for k in keys if k in ran]
        if not h.present:
            status = "ABSENT"
        elif any(s == "OK" for s in ran_hit):
            status = "PARSED"
        elif any(s == "FAIL" for s in ran_hit):
            status = "FAIL"
        elif covered:
            status = "SCHEDULED"
        elif not keys:
            # Plain-text copy (SetupAPI, transcripts, PSReadLine) — no parser.
            status = "STAGED"
        else:
            status = "PRESENT_NO_PARSER"
        rows.append({
            "artifact": h.name,
            "status": status,
            "tools": ", ".join(h.related_tools) or "-",
            "hits": str(len(h.hits)),
            "reason": h.reason,
        })
    return rows


def apply_ledger_to_completeness(
    rows: list[dict[str, str]],
    ledger: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Upgrade SCHEDULED rows to PARSED/FAIL from a finished ledger (no remount)."""
    rank = {"OK": 3, "FAIL": 2, "SKIP": 1, "PENDING": 0}
    ran: dict[str, str] = {}
    for row in ledger or []:
        key = invokable_tool_key(str(row.get("tool") or ""))
        st = str(row.get("status") or "").upper()
        if not key or st not in rank:
            continue
        if rank[st] >= rank.get(ran.get(key, ""), 0):
            ran[key] = st
    out = []
    for row in rows:
        item = dict(row)
        if str(item.get("status") or "") in {"ABSENT", "STAGED", "PRESENT_NO_PARSER"}:
            out.append(item)
            continue
        tools = [t.strip() for t in str(item.get("tools") or "").split(",") if t.strip()]
        keys = {invokable_tool_key(t) for t in tools}
        ran_hit = [ran[k] for k in keys if k in ran]
        if any(s == "OK" for s in ran_hit):
            item["status"] = "PARSED"
        elif any(s == "FAIL" for s in ran_hit):
            item["status"] = "FAIL"
        out.append(item)
    return out
