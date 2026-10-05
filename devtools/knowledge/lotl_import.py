"""WO-KL2b (design time): import the LOTL lists in full from pinned snapshots.

Rule 9 of the §3Z forbidden list: **ingest, don't type.** Every item of external
knowledge must come from a *pinned snapshot* of its source - a git commit SHA (or a
release tag) plus the SHA-256 of the file used - transformed by a script here. A
model never types a hash, an id or a list entry into a knowledge file.

What this replaces: `triage/db.py` carried **hand-typed** seeds for the very lists
this module imports - 13 BYOVD drivers (with SHA-256s), 9 hijackable DLLs, 17 RMM
tools, 14 LOTS domains, 16 LOOBins. The real projects publish hundreds to
thousands of machine-readable entries, so a `check_driver` that knew 13 answered
"unknown" for almost every abusable driver, and the typed hashes were unverified.

Sources and the pin for each:

| Source | Repo / URL | Data file used |
|---|---|---|
| LOLDrivers | github.com/magicsword-io/LOLDrivers | `loldrivers.io/content/api/drivers.json` |
| HijackLibs | github.com/wietze/HijackLibs | `yml/**/*.yml` |
| LOLRMM | github.com/magicsword-io/LOLRMM | `website/public/api/rmm_tools.json` |
| LOOBins | github.com/infosecB/LOOBins | `LOOBins/*.yml` |
| LOLBAS | github.com/LOLBAS-Project/LOLBAS | `yml/**/*.yml` |
| GTFOBins | github.com/GTFOBins/GTFOBins.github.io | `_gtfobins/*` |
| LOTS | https://lots-project.com | the page's `main-table` (a web source: pinned by date + SHA-256) |

The snapshots are **inputs**, not product data: they live outside the repo (a path
given by `NEXUS_KL2B_SNAPSHOTS`) because LOLDrivers is ~560 MB of driver binaries.
This module writes the **derived** lists to
`src/nexus/data/knowledge/lists/lotl.yaml`, which is committed; each list carries
`source`, `source_version` (the commit SHA / retrieval date) and its `source_key`.

The output is deterministic (every list sorted), so `--check` proves the file on
disk is what the snapshots produce.

Usage::

    python devtools/knowledge/lotl_import.py            # write the lists
    python devtools/knowledge/lotl_import.py --check    # fail on drift
"""
from __future__ import annotations

import argparse
import hashlib
import html as html_lib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "src" / "nexus" / "data" / "knowledge" / "lists" / "lotl.yaml"

DEFAULT_SNAPSHOTS = Path(os.environ.get("NEXUS_KL2B_SNAPSHOTS") or (Path(os.environ.get("TEMP", "/tmp")) / "kl2b-snapshots"))


def _snapshots() -> Path:
    return Path(os.environ.get("NEXUS_KL2B_SNAPSHOTS") or DEFAULT_SNAPSHOTS)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _commit(repo: Path) -> str:
    out = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=False)
    return out.stdout.strip()


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
    except Exception:  # noqa: BLE001 - a malformed upstream file is skipped, not fatal
        return {}


def _stable(items: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    return sorted(items, key=lambda r: tuple(str(r.get(k) or "") for k in keys))


def _join(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(v) for v in value if str(v).strip())
    return str(value or "")


# ── the importers ──────────────────────────────────────────────────────

def import_loldrivers(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every driver in the project's machine-readable list, with all its hashes."""
    data_file = snap / "LOLDrivers" / "loldrivers.io" / "content" / "api" / "drivers.json"
    drivers = json.loads(data_file.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for entry in drivers:
        category = str(entry.get("Category") or "")
        mitre = str(entry.get("MitreID") or "")
        for sample in entry.get("KnownVulnerableSamples") or []:
            auth = sample.get("Authentihash") or {}
            if not isinstance(auth, dict):
                auth = {}
            rows.append({
                "filename_lower": str(sample.get("Filename") or "").lower(),
                "sha256": str(sample.get("SHA256") or "") or None,
                "sha1": str(sample.get("SHA1") or "") or None,
                "md5": str(sample.get("MD5") or "") or None,
                "authentihash_sha256": str(auth.get("SHA256") or "") or None,
                "authentihash_sha1": str(auth.get("SHA1") or "") or None,
                "authentihash_md5": str(auth.get("MD5") or "") or None,
                "vendor": str(sample.get("Company") or "") or None,
                "product": str(sample.get("Product") or "") or None,
                # LOLDrivers has no CVE column; CVEs appear in the entry's Resources,
                # often as an NVD URL, so scan the text rather than requiring a bare id.
                "cve": _first_cve(entry.get("Resources")),
                "vulnerability_type": category or None,
                "description": " / ".join(x for x in (
                    str(entry.get("Id") or ""), str(sample.get("Description") or ""), mitre) if x) or None,
                "source_key": str(entry.get("Id") or ""),
            })
    rows = [r for r in rows if r["filename_lower"] or r["sha256"]]
    prov = {"url": "https://github.com/magicsword-io/LOLDrivers",
            "commit": _commit(snap / "LOLDrivers"),
            "file": "loldrivers.io/content/api/drivers.json",
            "sha256": _sha256(data_file), "entries": len(drivers), "rows": len(rows)}
    return prov, _stable(rows, "filename_lower", "sha256")


def import_hijacklibs(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every YAML entry: one row per (dll, vulnerable executable)."""
    root = snap / "HijackLibs" / "yml"
    files = sorted(root.rglob("*.y*ml"))
    rows: list[dict[str, Any]] = []
    for path in files:
        doc = _load_yaml(path)
        name = str(doc.get("Name") or "").strip()
        if not name:
            continue
        vendor = str(doc.get("Vendor") or "").strip() or None
        expected = [str(x) for x in (doc.get("ExpectedLocations") or []) if str(x).strip()]
        exes = doc.get("VulnerableExecutables") or []
        if not isinstance(exes, list):
            exes = []
        for exe in exes:
            if not isinstance(exe, dict):
                continue
            rows.append({
                "dll_name_lower": name.lower(),
                "hijack_type": str(exe.get("Type") or "").strip() or None,
                "vulnerable_exe": str(exe.get("Path") or "").strip() or None,
                "vulnerable_exe_path": str(exe.get("Path") or "").strip() or None,
                "expected_paths": json.dumps(expected),
                "vendor": vendor,
                "source_key": path.relative_to(root).as_posix(),
            })
        if not exes:
            rows.append({
                "dll_name_lower": name.lower(), "hijack_type": None,
                "vulnerable_exe": None, "vulnerable_exe_path": None,
                "expected_paths": json.dumps(expected), "vendor": vendor,
                "source_key": path.relative_to(root).as_posix(),
            })
    prov = {"url": "https://github.com/wietze/HijackLibs", "commit": _commit(snap / "HijackLibs"),
            "file": "yml/**/*.yml", "files": len(files), "rows": len(rows)}
    return prov, _stable(rows, "dll_name_lower", "vulnerable_exe")


def import_lolrmm(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every RMM tool, as a suspicious executable name."""
    data_file = snap / "LOLRMM" / "website" / "public" / "api" / "rmm_tools.json"
    tools = json.loads(data_file.read_text(encoding="utf-8"))
    rows: dict[str, dict[str, Any]] = {}
    for tool in tools:
        name = str(tool.get("Name") or "").strip()
        if not name:
            continue
        details = tool.get("Details") or {}
        meta = details.get("PEMetadata") if isinstance(details, dict) else {}
        if isinstance(meta, dict) and not isinstance(meta, list):
            filename = str(meta.get("Filename") or "").strip()
        else:
            filename = ""
            meta = (meta or [{}])[0] if isinstance(meta, list) else {}
            if isinstance(meta, dict):
                filename = str(meta.get("Filename") or "").strip()
        stem = re.sub(r"[^a-z0-9]+", "", name.lower())
        for pattern in {filename.lower(), f"{stem}.exe"}:
            if not pattern:
                continue
            rows.setdefault(pattern, {
                "filename_pattern": pattern,
                "is_regex": 0,
                "tool_name": name,
                "category": "lotrmm",
                "mitre_techniques": "T1219",
                "risk_level": "high",
                "notes": str(tool.get("Category") or "") or None,
                "source_key": name,
            })
    prov = {"url": "https://github.com/magicsword-io/LOLRMM", "commit": _commit(snap / "LOLRMM"),
            "file": "website/public/api/rmm_tools.json", "sha256": _sha256(data_file),
            "entries": len(tools), "rows": len(rows)}
    return prov, _stable(list(rows.values()), "filename_pattern")


def _first_cve(resources: Any) -> str | None:
    """The first CVE id in an entry's resources, bare or inside an NVD URL."""
    for item in resources or []:
        m = re.search(r"CVE-\d{4}-\d{4,}", str(item), re.IGNORECASE)
        if m:
            return m.group(0).upper()
    return None


_TAG_TECHNIQUE = {
    "c&c": "T1102", "c2": "T1102", "command and control": "T1102",
    "exfiltration": "T1567", "exfil": "T1567", "phishing": "T1566",
    "payload": "T1105", "download": "T1105", "staging": "T1105",
    "malware": "T1204", "proxy": "T1090", "tunneling": "T1572",
    "storage": "T1567", "remote access": "T1219", "file sharing": "T1567",
}


def import_lots(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every row of the site's main table: a trusted site abused for C2/exfil.

    The tag cell is free text (`Phishing C&C Download`), so it is split into tags,
    sorted, and each tag mapped to an ATT&CK technique where one is known - a raw
    multi-line tag string in `category` is not a usable field.
    """
    page = snap / "lots" / "lots.html"
    html_text = page.read_text(encoding="utf-8", errors="replace")
    rows: list[dict[str, Any]] = []
    for block in re.findall(r'<tr class="extension-row[^"]*">(.*?)</tr>', html_text, re.S):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", block, re.S)
        if len(cells) < 2:
            continue
        text = [re.sub(r"\s+", " ", html_lib.unescape(re.sub(r"<[^>]+>", " ", c))).strip()
                for c in cells]
        domain = text[0].lower().strip()
        if not domain or " " in domain:
            continue
        tags = sorted({t.strip().lower() for t in re.split(r"[\s,]+", text[1]) if t.strip()})
        provider = text[2] if len(text) > 2 else ""
        techniques = sorted({_TAG_TECHNIQUE[t] for t in tags if t in _TAG_TECHNIQUE})
        rows.append({
            "domain_lower": domain,
            "category": " | ".join(tags) or None,
            "description": f"service provider: {provider}" if provider else None,
            "mitre_technique": ", ".join(techniques) or None,
            "source_url": "https://lots-project.com",
            "source_key": domain,
        })
    prov = {"url": "https://lots-project.com", "source_version": "web",
            "sha256": _sha256(page), "retrieved": "2026-10-05", "rows": len(rows)}
    return prov, _stable(rows, "domain_lower")


def import_loobins(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every macOS LOTL binary."""
    root = snap / "LOOBins" / "LOOBins"
    files = sorted(root.glob("*.yml"))
    rows: list[dict[str, Any]] = []
    for path in files:
        doc = _load_yaml(path)
        name = str(doc.get("name") or "").strip()
        if not name:
            continue
        tactics: set[str] = set()
        for use in doc.get("example_use_cases") or []:
            if isinstance(use, dict):
                tactics.update(str(t) for t in (use.get("tactics") or []) if str(t).strip())
        rows.append({
            "binary_name_lower": name.lower(),
            "description": (str(doc.get("short_description") or "").strip()
                            or str(doc.get("full_description") or "").strip()[:400] or None),
            "paths": json.dumps([str(p) for p in (doc.get("paths") or []) if str(p).strip()]),
            "functions": json.dumps(sorted(tactics)),
            "mitre_techniques": None,
            "detection": None,
            "source_url": "https://loobins.io",
            "source_key": path.stem,
        })
    prov = {"url": "https://github.com/infosecB/LOOBins", "commit": _commit(snap / "LOOBins"),
            "file": "LOOBins/*.yml", "files": len(files), "rows": len(rows)}
    return prov, _stable(rows, "binary_name_lower")


def import_lolbas(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every Windows LOTL binary, with its abuse commands and MITRE ids."""
    root = snap / "LOLBAS" / "yml"
    files = sorted(root.rglob("*.yml"))
    rows: list[dict[str, Any]] = []
    for path in files:
        doc = _load_yaml(path)
        name = str(doc.get("Name") or "").strip()
        if not name:
            continue
        funcs: set[str] = set()
        mitre: set[str] = set()
        for cmd in doc.get("Commands") or []:
            if isinstance(cmd, dict):
                if str(cmd.get("Category") or "").strip():
                    funcs.add(str(cmd["Category"]).strip())
                if str(cmd.get("MitreID") or "").strip():
                    mitre.add(str(cmd["MitreID"]).strip())
        detection = [str(d.get("IOC")) for d in (doc.get("Detection") or [])
                     if isinstance(d, dict) and d.get("IOC")]
        rows.append({
            "filename_lower": name.lower(),
            "name": name,
            "description": str(doc.get("Description") or "").strip() or None,
            "functions": json.dumps(sorted(funcs)),
            "expected_paths": json.dumps([str(p.get("Path")) for p in (doc.get("Full_Path") or [])
                                          if isinstance(p, dict) and p.get("Path")]),
            "mitre_techniques": ", ".join(sorted(mitre)) or None,
            "detection": " | ".join(detection[:4]) or None,
            "source_url": "https://lolbas-project.github.io",
            "platform": "windows",
            "source_key": path.relative_to(root).as_posix(),
        })
    prov = {"url": "https://github.com/LOLBAS-Project/LOLBAS", "commit": _commit(snap / "LOLBAS"),
            "file": "yml/**/*.yml", "files": len(files), "rows": len(rows)}
    return prov, _stable(rows, "filename_lower")


def import_gtfobins(snap: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Every Linux LOTL binary (the YAML front matter of each `_gtfobins` entry)."""
    root = snap / "GTFOBins" / "_gtfobins"
    files = sorted(p for p in root.iterdir() if p.is_file()) if root.is_dir() else []
    rows: list[dict[str, Any]] = []
    for path in files:
        doc = _load_yaml(path) or {}
        name = str(doc.get("name") or path.name).strip()
        funcs = sorted(str(f) for f in (doc.get("functions") or {})) \
            if isinstance(doc.get("functions"), dict) else []
        rows.append({
            "filename_lower": name.lower(),
            "name": name,
            "description": None,
            "functions": json.dumps(funcs),
            "expected_paths": json.dumps([f"/usr/bin/{name}", f"/usr/local/bin/{name}"]),
            "mitre_techniques": None,
            "detection": None,
            "source_url": "https://gtfobins.github.io",
            "platform": "linux",
            "source_key": path.name,
        })
    prov = {"url": "https://github.com/GTFOBins/GTFOBins.github.io",
            "commit": _commit(snap / "GTFOBins"), "file": "_gtfobins/*",
            "files": len(files), "rows": len(rows)}
    return prov, _stable(rows, "filename_lower")


IMPORTERS = {
    "loldrivers": import_loldrivers,
    "hijacklibs": import_hijacklibs,
    "lolrmm": import_lolrmm,
    "lots": import_lots,
    "loobins": import_loobins,
    "lolbas": import_lolbas,
    "gtfobins": import_gtfobins,
}


def build(*, only: list[str] | None = None) -> dict[str, Any]:
    snap = _snapshots()
    if not snap.is_dir():
        raise SystemExit(
            f"snapshots not found at {snap}. Clone the pinned sources there and set "
            f"NEXUS_KL2B_SNAPSHOTS. See the module docstring for the exact repos."
        )
    payload: dict[str, Any] = {
        "version": 1,
        "generated": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "generator": "devtools/knowledge/lotl_import.py",
        "note": ("Generated from pinned snapshots of the upstream projects. Do not edit by "
                 "hand - re-run the importer. Every list carries its source, version and key."),
        "sources": {},
        "lists": {},
    }
    for name, fn in IMPORTERS.items():
        if only and name not in only:
            continue
        prov, rows = fn(snap)
        payload["sources"][name] = prov
        payload["lists"][name] = rows
    return payload


def _comparable(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in payload.items() if k != "generated"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="exit 1 if the file on disk is not what the snapshots produce")
    parser.add_argument("--only", default="", help="comma list of sources to import")
    args = parser.parse_args(argv)

    only = [s.strip() for s in args.only.split(",") if s.strip()] or None
    payload = build(only=only)

    for name, prov in payload["sources"].items():
        rows = payload["lists"].get(name) or []
        print(f"  {name:12s} {len(rows):6d} rows   {prov.get('commit') or prov.get('sha256', '')[:16]}")

    if args.check:
        on_disk = _load_yaml(OUT)
        if _comparable(on_disk) != _comparable(payload):
            print("DRIFT: the lists on disk are not what the snapshots produce", file=sys.stderr)
            return 1
        print("lists match the snapshots")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(
        "# WO-KL2b - the LOTL lists, imported from pinned snapshots.\n"
        "# Generator: devtools/knowledge/lotl_import.py. Do not edit by hand.\n"
        + yaml.safe_dump(payload, sort_keys=False, allow_unicode=True, width=1000),
        encoding="utf-8",
    )
    print(f"written: {OUT.relative_to(REPO)}  ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
