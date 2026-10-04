"""WO-K2 — the examiner toolkit, as read-only loop tools.

The checks themselves already exist inside `triage/server.py`, but they were
nested in `register_tools()` and therefore unreachable except as MCP tools: the
agent loop could not call them. This module holds the **one implementation** of
each check's decision logic, taking the database objects as parameters, and
`triage/server.py` delegates to it. That is what makes "add these as read-only
loop tools" true without forking the logic — a second copy would drift, and a
drifted baseline check is worse than none.

Every result carries `interpretation_constraint`: **UNKNOWN means not in the
database, not suspicious** (FD-004). A caller that escalates an UNKNOWN without
corroboration is doing so against an explicit contract, and `analysis.leads`
already refuses to.
"""
from __future__ import annotations

from typing import Any

from nexus.triage.analysis import (
    calculate_file_verdict,
    calculate_hash_verdict,
    calculate_process_verdict,
    calculate_service_verdict,
    check_process_name_spoofing,
    check_suspicious_path,
    detect_hash_algorithm,
    extract_directory,
    extract_filename,
    is_system_path,
    normalize_hash,
    normalize_path,
    parse_service_binary_path,
)

#: Result keys a caller may rely on across every check.
UNKNOWN_CONSTRAINT = "UNKNOWN means not-in-database, NOT suspicious"


def check_file(
    known_good: Any,
    context: Any = None,
    *,
    path: str,
    path_hash: str = "",
) -> dict[str, Any]:
    """A file path against the Windows baseline (the body of `check_file`)."""
    if not known_good:
        return {
            "path": path,
            "verdict": "UNKNOWN",
            "message": "Triage database not found.",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    filename = extract_filename(path)
    dir_normalized = extract_directory(path)
    normalized = normalize_path(path)
    is_sys_path = is_system_path(path)

    path_in_baseline = known_good.path_exists(path)
    filename_in_baseline = known_good.filename_exists(filename)
    directory_known = known_good.is_directory_known_for_file(filename, dir_normalized)

    filename_findings: list[dict[str, Any]] = []
    if context:
        suspicious = context.check_suspicious_filename(filename)
        if suspicious:
            filename_findings.append({
                "type": "known_tool",
                "severity": "high",
                "tool_name": suspicious.get("tool_name", filename),
                "category": suspicious.get("category", "unknown"),
            })

    filename_findings.extend(check_suspicious_path(path))

    protected = context.get_protected_process_names() if context else []
    filename_findings.extend(check_process_name_spoofing(filename, protected))

    lolbin_info = context.check_lolbin(filename) if context else None
    is_protected = (
        context.check_protected_process(filename) is not None if context else False
    )

    verdict = calculate_file_verdict(
        path_in_baseline=path_in_baseline,
        filename_in_baseline=filename_in_baseline,
        is_sys_path=is_sys_path,
        filename_findings=filename_findings,
        lolbin_info=lolbin_info,
        is_protected_process=is_protected,
        directory_known_for_file=directory_known,
        dir_normalized=dir_normalized,
        filename=filename,
    )

    result: dict[str, Any] = {
        "path": path,
        "normalized_path": normalized,
        "filename": filename,
        "verdict": str(verdict.verdict),
        "reasons": verdict.reasons,
        "confidence": verdict.confidence,
        "path_in_baseline": path_in_baseline,
        "filename_in_baseline": filename_in_baseline,
        "is_system_path": is_sys_path,
        "caveats": [
            "Baseline covers default Windows installations only",
            "Third-party software will not appear in baseline",
        ],
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }
    if lolbin_info:
        result["lolbin"] = {
            "name": lolbin_info.get("name", ""),
            "description": lolbin_info.get("description", ""),
            "functions": lolbin_info.get("functions", []),
        }
    if path_hash:
        algorithm = detect_hash_algorithm(path_hash)
        if algorithm:
            matches = known_good.lookup_hash(normalize_hash(path_hash))
            result["hash_in_baseline"] = bool(matches)
            if matches:
                result["hash_matches"] = matches
    if filename_findings:
        result["filename_issues"] = filename_findings
    return result


def check_process_tree(
    context: Any,
    *,
    process_name: str,
    parent_name: str,
    path: str = "",
    user: str = "",
) -> dict[str, Any]:
    """A parent-child relationship against the baseline (body of `check_process_tree`)."""
    if not context:
        return {
            "process_name": process_name,
            "verdict": "UNKNOWN",
            "message": "Context database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    findings: list[dict[str, Any]] = []
    expected = context.get_expected_process(process_name)
    process_known = expected is not None

    if not path:
        protected = context.get_protected_process_names()
        findings.extend(check_process_name_spoofing(process_name, protected))

    parent_expected = context.get_expected_process(parent_name) if context else None
    if parent_expected and parent_expected.get("never_spawns_children", 0):
        findings.append({
            "type": "never_spawns_children",
            "severity": "critical",
            "description": (
                f"{parent_name} should never spawn children — spawned {process_name} (possible process injection)"
            ),
        })

    path_valid: bool | None = None
    if path and expected:
        valid_paths = expected.get("valid_paths")
        if valid_paths:
            norm = normalize_path(path)
            path_valid = any(norm.startswith(normalize_path(vp)) or norm == normalize_path(vp) for vp in valid_paths)

    user_valid: bool | None = None
    if user and expected:
        valid_users = expected.get("valid_users")
        if valid_users:
            bare = user.lower()
            # Baseline entries are fully qualified ("NT AUTHORITY\SYSTEM");
            # callers often pass bare names ("SYSTEM"). Accept an exact match or
            # a bare name matching the suffix after the domain.
            user_valid = any(
                bare == v.lower() or ("\\" not in bare and v.lower().endswith("\\" + bare))
                for v in valid_users
            )

    parent_valid = True
    if expected:
        valid_parents = expected.get("valid_parents", []) or []
        suspicious_parents = expected.get("suspicious_parents", []) or []
        if valid_parents:
            parent_valid = parent_name.lower() in (p.lower() for p in valid_parents)
        elif suspicious_parents:
            parent_valid = parent_name.lower() not in (
                sp.lower() for sp in suspicious_parents
            )
        if expected.get("parent_exits", 0) and parent_name.lower() not in (
            p.lower() for p in valid_parents
        ):
            findings.append({
                "type": "unexpected_parent_exit",
                "severity": "high",
                "description": (
                    f"Unexpected parent ({parent_name}) causing {process_name} exit"
                ),
            })

    verdict = calculate_process_verdict(
        process_known=process_known,
        parent_valid=parent_valid,
        path_valid=path_valid,
        user_valid=user_valid,
        findings=findings,
    )
    return {
        "process_name": process_name,
        "parent_name": parent_name,
        "verdict": str(verdict.verdict),
        "reasons": verdict.reasons,
        "confidence": verdict.confidence,
        "process_known": process_known,
        "parent_valid": parent_valid,
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }


def check_service(
    known_good: Any,
    context: Any = None,
    *,
    service_name: str,
    binary_path: str = "",
) -> dict[str, Any]:
    """A Windows service against the baseline (body of `check_service`)."""
    if not known_good:
        return {
            "service_name": service_name,
            "verdict": "UNKNOWN",
            "message": "Baseline database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    services = known_good.lookup_service(service_name)
    service_in_baseline = len(services) > 0

    binary_findings: list[dict[str, Any]] = []
    binary_path_matches: bool | None = None
    if binary_path and service_in_baseline:
        norm = parse_service_binary_path(binary_path)
        for service in services:
            pattern = service.get("binary_path_pattern", "")
            if pattern and parse_service_binary_path(pattern) == norm:
                binary_path_matches = True
                break
        if binary_path_matches is None:
            binary_path_matches = False

    if binary_path and not binary_path_matches and context:
        filename = extract_filename(binary_path)
        if context.check_lolbin(filename):
            binary_findings.append({
                "type": "lolbin_service",
                "severity": "high",
                "description": f"Service binary is a LOLBin: {filename}",
            })

    verdict = calculate_service_verdict(
        service_in_baseline=service_in_baseline,
        binary_path_matches=binary_path_matches,
        binary_findings=binary_findings,
    )
    return {
        "service_name": service_name,
        "verdict": str(verdict.verdict),
        "reasons": verdict.reasons,
        "confidence": verdict.confidence,
        "baseline_os_versions": (
            [s.get("os_versions", "[]") for s in services] if services else []
        ),
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }


def check_hash(known_good: Any, context: Any = None, *, hash_value: str) -> dict[str, Any]:
    """A file hash against the baseline and known vulnerable drivers (body of `check_hash`)."""
    if not known_good and not context:
        return {
            "hash": hash_value,
            "verdict": "UNKNOWN",
            "message": "Baseline and context databases not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    algorithm = detect_hash_algorithm(hash_value)
    if not algorithm:
        return {
            "hash": hash_value,
            "verdict": "UNKNOWN",
            "message": "Unrecognized hash format",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    normalized = normalize_hash(hash_value)
    matches = known_good.lookup_hash(normalized) if known_good else []
    driver_info = None
    if context:
        driver_info = context.check_vulnerable_driver(normalized, algorithm)
    if matches:
        verdict = calculate_hash_verdict(matches=matches)
    elif driver_info:
        verdict = calculate_hash_verdict(is_vulnerable_driver=True, driver_info=driver_info)
    else:
        verdict = calculate_hash_verdict()
    return {
        "hash": hash_value,
        "normalized_hash": normalized,
        "algorithm": algorithm,
        "verdict": str(verdict.verdict),
        "reasons": verdict.reasons,
        "confidence": verdict.confidence,
        "matches": matches or [],
        "driver_info": driver_info,
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }


def check_autorun(
    known_good: Any,
    context: Any = None,
    *,
    key_path: str,
    value_name: str = "",
) -> dict[str, Any]:
    """A registry autorun entry against the baseline (body of `check_autorun`)."""
    if not known_good:
        return {
            "key_path": key_path,
            "verdict": "UNKNOWN",
            "message": "Baseline database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    autoruns = known_good.lookup_autorun(key_path, value_name or None)
    if autoruns:
        return {
            "key_path": key_path,
            "value_name": value_name,
            "verdict": "EXPECTED",
            "reasons": ["Autorun matches Windows baseline"],
            "confidence": "high",
            "baseline_entries": len(autoruns),
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    findings: list[dict[str, Any]] = []
    if value_name and context:
        filename = extract_filename(value_name)
        suspicious = context.check_suspicious_filename(filename)
        if suspicious:
            findings.append({
                "type": "known_tool",
                "severity": "high",
                "tool_name": suspicious.get("tool_name", filename),
            })
        if context.check_lolbin(filename):
            findings.append({
                "type": "lolbin",
                "severity": "medium",
                "description": f"LOLBin in autorun: {filename}",
            })

    result: dict[str, Any] = {
        "key_path": key_path,
        "value_name": value_name,
        "verdict": "UNKNOWN",
        "reasons": ["Autorun not in baseline (neutral)"],
        "confidence": "low",
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }
    if findings:
        result["findings"] = findings
    return result


def check_registry(
    registry_db: Any,
    *,
    key_path: str,
    value_name: str = "",
    hive: str = "",
    os_version: str = "",
) -> dict[str, Any]:
    """A registry key or value against the registry baseline.

    The registry baseline is optional (~12 GB), so `registry_db` may be None;
    that is reported as UNKNOWN with the reason, never as "not suspicious".
    """
    if not registry_db:
        return {
            "key_path": key_path,
            "value_name": value_name,
            "hive": hive,
            "verdict": "UNKNOWN",
            "reasons": ["Registry baseline not available (optional, ~12 GB)"],
            "confidence": "low",
            "lookup_performed": False,
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    matches = (
        registry_db.lookup_value(key_path, value_name, hive or None, os_version or None)
        if value_name
        else registry_db.lookup_key(key_path, hive or None, os_version or None)
    )
    if not matches:
        return {
            "key_path": key_path,
            "value_name": value_name,
            "hive": hive,
            "verdict": "UNKNOWN",
            "reasons": [
                "Registry entry not in baseline (neutral - may be legitimate software)"
            ],
            "confidence": "low",
            "in_baseline": False,
            "lookup_performed": True,
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }

    os_versions: set[str] = set()
    values_found: list[dict[str, Any]] = []
    for match in matches:
        os_versions.update(match.get("os_versions", []) or [])
        if match.get("value_name"):
            values_found.append({
                "name": match.get("value_name"),
                "type": match.get("value_type"),
                "hive": match.get("hive"),
            })

    result: dict[str, Any] = {
        "key_path": key_path,
        "value_name": value_name,
        "hive": hive,
        "verdict": "EXPECTED",
        "reasons": ["Registry entry found in Windows baseline"],
        "confidence": "high",
        "in_baseline": True,
        "lookup_performed": True,
        "match_count": len(matches),
        "os_versions": sorted(os_versions)[:10],
        "os_version_count": len(os_versions),
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }
    if values_found:
        result["values"] = values_found[:10]
        result["value_count"] = len(values_found)
    return result


def analyze_filename_triage(
    context: Any = None,
    *,
    filename: str,
) -> dict[str, Any]:
    """Filename deception analysis (body of `analyze_filename_triage`)."""
    from nexus.triage.analysis import analyze_filename

    result = analyze_filename(filename)
    findings = list(result["findings"])

    protected = context.get_protected_process_names() if context else []
    findings.extend(check_process_name_spoofing(filename, protected))

    if context:
        suspicious = context.check_suspicious_filename(filename)
        if suspicious:
            findings.append({
                "type": "known_tool",
                "severity": "high",
                "tool_name": suspicious.get("tool_name", filename),
                "category": suspicious.get("category", ""),
                "description": f"Known tool: {suspicious.get('tool_name', filename)}",
            })

    return {
        "filename": filename,
        "entropy": result["entropy"],
        "findings": findings,
        "is_suspicious": len(findings) > 0,
        "suspicious_count": len(findings),
        "interpretation_constraint": (
            "a filename is a naming signal only - corroborate before escalating"
        ),
    }


def check_lolbin(context: Any, *, filename: str) -> dict[str, Any]:
    """Whether a binary is a known LOLBin and how it is abused."""
    if not context:
        return {
            "filename": filename,
            "verdict": "UNKNOWN",
            "message": "Context database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    lolbin = context.check_lolbin(filename)
    if not lolbin:
        return {
            "filename": filename,
            "found": False,
            "interpretation_constraint": (
                "not a known LOLBin - absence of a match is not innocence"
            ),
        }
    return {
        "filename": filename,
        "found": True,
        "verdict": "EXPECTED_LOLBIN",
        "name": lolbin.get("name", ""),
        "description": lolbin.get("description", ""),
        "functions": lolbin.get("functions", []),
        "expected_paths": lolbin.get("expected_paths", []),
        "mitre_techniques": lolbin.get("mitre_techniques", []),
        "detection": lolbin.get("detection", ""),
        "interpretation_constraint": (
            "legitimate but abusable - a LOLBin is not by itself malicious"
        ),
    }


def check_hijackable_dll(context: Any, *, dll_name: str) -> dict[str, Any]:
    """Whether a DLL is known to be vulnerable to search-order hijacking."""
    if not context:
        return {
            "dll_name": dll_name,
            "entries": [],
            "message": "Context database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    entries = context.check_hijackable_dll(dll_name)
    return {
        "dll_name": dll_name,
        "entries": entries,
        "hijackable": len(entries) > 0,
        "interpretation_constraint": (
            "a hijackable DLL is an opportunity, not an observation"
        ),
    }


def deobfuscate_command(*, command: str) -> dict[str, Any]:
    """Decode an obfuscated command (WO-K2; `tools/analysis.py:185`).

    Delegates to the same implementation the MCP tool uses, so the loop and the
    MCP surface cannot drift.
    """
    from nexus.ingest.deobfuscate import deobfuscate_command as _deobfuscate

    result = _deobfuscate(command)
    out = dict(result) if isinstance(result, dict) else {"decoded": str(result)}
    out["interpretation_constraint"] = (
        "a decoded command is a claim about intent - read the decoded text"
    )
    return out


def check_driver(
    context: Any,
    *,
    driver_name: str = "",
    hash_value: str = "",
    hash: str = "",
) -> dict[str, Any]:
    """Check a driver name or hash against known vulnerable BYOVD drivers (LOLDrivers)."""
    target_hash = hash_value or hash
    if not context:
        return {
            "driver_name": driver_name,
            "hash": target_hash,
            "found": False,
            "verdict": "UNKNOWN",
            "message": "Context database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    entry = None
    if target_hash:
        algo = detect_hash_algorithm(target_hash)
        if algo:
            entry = context.check_vulnerable_driver(normalize_hash(target_hash), algo)
    if not entry and driver_name:
        entry = context.check_driver_by_name(driver_name)
    if entry:
        cve = entry.get("cve") or ""
        product = entry.get("product") or entry.get("filename_lower") or "Vulnerable driver"
        return {
            "driver_name": driver_name or entry.get("filename_lower", ""),
            "hash": target_hash,
            "found": True,
            "verdict": "SUSPICIOUS_VULNERABLE_DRIVER",
            "cve": cve,
            "product": product,
            "vendor": entry.get("vendor", ""),
            "vulnerability_type": entry.get("vulnerability_type", ""),
            "description": entry.get("description", ""),
            "interpretation_constraint": (
                "known vulnerable BYOVD driver - presence suggests privilege escalation or defense evasion"
            ),
        }
    return {
        "driver_name": driver_name,
        "hash": target_hash,
        "found": False,
        "verdict": "UNKNOWN",
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }


def check_lots_domain(context: Any, *, domain: str) -> dict[str, Any]:
    """Check whether a domain is a known living-off-trusted-sites (LOTS) domain."""
    if not context:
        return {
            "domain": domain,
            "found": False,
            "verdict": "UNKNOWN",
            "message": "Context database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    entry = context.check_lots_domain(domain)
    if entry:
        return {
            "domain": domain,
            "found": True,
            "verdict": "SUSPICIOUS_LOTS_DOMAIN",
            "category": entry.get("category", ""),
            "description": entry.get("description", ""),
            "mitre_technique": entry.get("mitre_technique", ""),
            "source_url": entry.get("source_url", ""),
            "interpretation_constraint": (
                "living off trusted sites - legitimate domain abused for C2 or exfiltration"
            ),
        }
    return {
        "domain": domain,
        "found": False,
        "verdict": "UNKNOWN",
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }


def check_loobin(context: Any, *, binary_name: str) -> dict[str, Any]:
    """Check whether a binary is a macOS living-off-the-land binary (LOOBin)."""
    if not context:
        return {
            "binary_name": binary_name,
            "found": False,
            "verdict": "UNKNOWN",
            "message": "Context database not available",
            "interpretation_constraint": UNKNOWN_CONSTRAINT,
        }
    entry = context.check_loobin(binary_name)
    if entry:
        return {
            "binary_name": binary_name,
            "found": True,
            "verdict": "EXPECTED_LOOBIN",
            "description": entry.get("description", ""),
            "paths": entry.get("paths", []),
            "functions": entry.get("functions", []),
            "mitre_techniques": entry.get("mitre_techniques", []),
            "detection": entry.get("detection", ""),
            "source_url": entry.get("source_url", ""),
            "interpretation_constraint": (
                "legitimate macOS binary abusable for living-off-the-land techniques"
            ),
        }
    return {
        "binary_name": binary_name,
        "found": False,
        "verdict": "UNKNOWN",
        "interpretation_constraint": UNKNOWN_CONSTRAINT,
    }


#: Tools this module implements. Kept here so the backbone allowlist and the
#: loop's argument table cannot disagree with the code.
EXAMINER_CHECK_TOOLS: tuple[str, ...] = (
    "check_file",
    "check_process_tree",
    "check_service",
    "check_hash",
    "check_autorun",
    "check_registry",
    "analyze_filename_triage",
    "check_lolbin",
    "check_hijackable_dll",
    "deobfuscate_command",
    "check_driver",
    "check_lots_domain",
    "check_loobin",
)


def is_examiner_check(name: str) -> bool:
    """Whether *name* is one of this module's checks."""
    return str(name or "").strip() in EXAMINER_CHECK_TOOLS

