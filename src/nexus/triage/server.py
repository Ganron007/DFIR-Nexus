"""Triage server — 13 tools for offline Windows baseline validation.

Integrates with KnownGoodDB (file/service/task/autorun baselines) and
ContextDB (LOLBins, vulnerable drivers, process rules, named pipes).
"""

import logging
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.config import settings

from .analysis import (
    analyze_filename,
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
from .db import ContextDB, KnownGoodDB, RegistryDB
from .download import download_databases

logger = logging.getLogger(__name__)


def _get_db_path() -> Path:
    return settings.data_root / "triage"


def _open_dbs(read_only: bool = True):
    db_dir = _get_db_path()
    known_good = None
    context = None
    if (db_dir / "known_good.db").exists():
        known_good = KnownGoodDB(db_dir / "known_good.db", read_only=read_only)
        known_good.connect()
    if (db_dir / "context.db").exists():
        context = ContextDB(db_dir / "context.db", read_only=read_only)
        context.connect()
    return known_good, context


def _open_registry_db(read_only: bool = True) -> RegistryDB | None:
    reg_path = _get_db_path() / "known_good_registry.db"
    if not reg_path.exists():
        return None
    db = RegistryDB(reg_path, read_only=read_only)
    if not db.is_available():
        db.close()
        return None
    return db


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def check_file(path: str, hash: str = "", os_version: str = "") -> dict:
        """Check a file path against the Windows baseline database.

        Returns verdict: EXPECTED, EXPECTED_LOLBIN (legitimate but abusable),
        SUSPICIOUS, or UNKNOWN (not in database — neutral).

        Args:
            path: Windows file path (e.g. C:\\Windows\\System32\\cmd.exe)
            hash: Optional file hash (MD5/SHA1/SHA256)
            os_version: Optional OS filter (e.g. 'Windows 10')
        """
        from nexus.audit import resolve_examiner
        known_good, context = _open_dbs()
        if not known_good:
            return {"path": path, "verdict": "UNKNOWN",
                    "examiner": resolve_examiner(),
                    "message": "Triage database not found. Run triage_download() to install."}

        audit_id = audit.log(tool="check_file", params={"path": path}, result_summary={"status": "checked"})

        normalized = normalize_path(path)
        filename = extract_filename(path)
        dir_normalized = extract_directory(path)
        is_sys_path = is_system_path(path)

        path_in_baseline = known_good.path_exists(path)
        filename_in_baseline = known_good.filename_exists(filename)
        directory_known = known_good.is_directory_known_for_file(filename, dir_normalized)

        filename_findings = []
        if context:
            suspicious = context.check_suspicious_filename(filename)
            if suspicious:
                filename_findings.append({
                    "type": "known_tool", "severity": "high",
                    "tool_name": suspicious.get("tool_name", filename),
                    "category": suspicious.get("category", "unknown"),
                })

        path_findings = check_suspicious_path(path)
        filename_findings.extend(path_findings)

        protected = context.get_protected_process_names() if context else []
        spoofing = check_process_name_spoofing(filename, protected)
        filename_findings.extend(spoofing)

        lolbin_info = context.check_lolbin(filename) if context else None
        is_protected = context.check_protected_process(filename) is not None if context else False

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

        from nexus.audit import resolve_examiner
        result = {
            "path": path,
            "normalized_path": normalized,
            "filename": filename,
            "verdict": str(verdict.verdict),
            "reasons": verdict.reasons,
            "confidence": verdict.confidence,
            "path_in_baseline": path_in_baseline,
            "filename_in_baseline": filename_in_baseline,
            "is_system_path": is_sys_path,
            "audit_id": audit_id,
            "examiner": resolve_examiner(),
            "caveats": [
                "Baseline covers default Windows installations only",
                "Third-party software will not appear in baseline",
            ],
            "interpretation_constraint": "UNKNOWN means not-in-database, NOT suspicious",
        }

        if lolbin_info:
            result["lolbin"] = {
                "name": lolbin_info.get("name", ""),
                "description": lolbin_info.get("description", ""),
                "functions": lolbin_info.get("functions", []),
            }

        if hash:
            algo = detect_hash_algorithm(hash)
            if algo:
                hash_norm = normalize_hash(hash)
                hash_results = known_good.lookup_hash(hash_norm)
                if hash_results:
                    result["hash_in_baseline"] = True
                    result["hash_matches"] = hash_results
                else:
                    result["hash_in_baseline"] = False

        if filename_findings:
            result["filename_issues"] = filename_findings

        return result

    @server.tool()
    def check_process_tree(process_name: str, parent_name: str, path: str = "", user: str = "") -> dict:
        """Validate a process parent-child relationship against the Windows baseline.

        Args:
            process_name: Process name (e.g. 'svchost.exe')
            parent_name: Parent process name
            path: Optional executable path
            user: Optional user context
        """
        known_good, context = _open_dbs()
        if not context:
            return {"process_name": process_name, "verdict": "UNKNOWN",
                    "message": "Context database not available"}

        audit.log(tool="check_process_tree", params={"process_name": process_name, "parent_name": parent_name},
                  result_summary={"status": "checked"})

        findings = []
        exp = context.get_expected_process(process_name)
        process_known = exp is not None

        if not path:
            protected = context.get_protected_process_names()
            spoofing = check_process_name_spoofing(process_name, protected)
            findings.extend(spoofing)

        if exp:
            never_spawns = exp.get("never_spawns_children", 0)
            if never_spawns:
                findings.append({
                    "type": "never_spawns_children", "severity": "critical",
                    "description": f"{process_name} should never spawn children — possible process injection",
                })

        path_valid = None
        if path and exp:
            valid_paths = exp.get("valid_paths")
            if valid_paths:
                norm = normalize_path(path)
                path_valid = any(norm.startswith(vp.lower()) for vp in valid_paths)

        user_valid = None
        if user and exp:
            valid_users = exp.get("valid_users")
            if valid_users:
                u = user.lower()
                # Baseline entries are fully qualified ("NT AUTHORITY\SYSTEM");
                # callers often pass bare names ("SYSTEM"). Accept an exact
                # match or a bare name matching the suffix after the domain.
                user_valid = any(
                    u == v.lower() or ("\\" not in u and v.lower().endswith("\\" + u))
                    for v in valid_users
                )

        parent_valid = True
        if exp:
            valid_parents = exp.get("valid_parents", [])
            suspicious_parents = exp.get("suspicious_parents", [])
            if valid_parents:
                parent_valid = parent_name.lower() in (p.lower() for p in valid_parents)
            elif suspicious_parents:
                parent_valid = parent_name.lower() not in (sp.lower() for sp in suspicious_parents)

            auto_flag = exp.get("parent_exits", 0)
            if auto_flag and parent_name.lower() not in (p.lower() for p in (valid_parents or [])):
                findings.append({
                    "type": "unexpected_parent_exit", "severity": "high",
                    "description": f"Unexpected parent ({parent_name}) causing {process_name} exit",
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
        }

    @server.tool()
    def check_service(service_name: str, binary_path: str = "", os_version: str = "") -> dict:
        """Check a Windows service against the baseline.

        Args:
            service_name: Service name (e.g. 'BITS', 'Spooler')
            binary_path: Service binary path
            os_version: Target OS version (e.g. 'W11_22H2')
        """
        known_good, context = _open_dbs()
        if not known_good:
            return {"service_name": service_name, "verdict": "UNKNOWN",
                    "message": "Baseline database not available"}

        audit.log(tool="check_service", params={"service_name": service_name},
                  result_summary={"status": "checked"})

        services = known_good.lookup_service(service_name)
        service_in_baseline = len(services) > 0

        binary_findings = []
        binary_path_matches = None
        if binary_path and service_in_baseline:
            norm = parse_service_binary_path(binary_path)
            for svc in services:
                bl = svc.get("binary_path_pattern", "")
                if bl and parse_service_binary_path(bl) == norm:
                    binary_path_matches = True
                    break
            if binary_path_matches is None:
                binary_path_matches = False

        if binary_path and not binary_path_matches:
            filename = extract_filename(binary_path)
            if context:
                lolbin = context.check_lolbin(filename)
                if lolbin:
                    binary_findings.append({
                        "type": "lolbin_service", "severity": "high",
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
            "baseline_os_versions": [s.get("os_versions", "[]") for s in services] if services else [],
        }

    @server.tool()
    def check_scheduled_task(task_path: str, os_version: str = "") -> dict:
        """Check a scheduled task against the Windows baseline.

        Args:
            task_path: Task path (e.g. '\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan')
            os_version: Target OS version
        """
        known_good, _ = _open_dbs()
        if not known_good:
            return {"task_path": task_path, "verdict": "UNKNOWN",
                    "message": "Baseline database not available"}

        audit.log(tool="check_scheduled_task", params={"task_path": task_path},
                  result_summary={"status": "checked"})

        tasks = known_good.lookup_task(task_path)
        if tasks:
            return {
                "task_path": task_path,
                "verdict": "EXPECTED",
                "reasons": ["Task matches Windows baseline"],
                "confidence": "high",
                "baseline_os_versions": [t.get("os_versions", "[]") for t in tasks],
            }
        return {
            "task_path": task_path,
            "verdict": "UNKNOWN",
            "reasons": ["Task not in baseline (neutral)"],
            "confidence": "low",
        }

    @server.tool()
    def check_autorun(key_path: str, value_name: str = "", os_version: str = "") -> dict:
        """Check a registry autorun/persistence entry against the baseline.

        Args:
            key_path: Registry key path (e.g. 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
            value_name: Registry value name
            os_version: Target OS version
        """
        known_good, context = _open_dbs()
        if not known_good:
            return {"key_path": key_path, "verdict": "UNKNOWN",
                    "message": "Baseline database not available"}

        audit.log(tool="check_autorun", params={"key_path": key_path},
                  result_summary={"status": "checked"})

        autoruns = known_good.lookup_autorun(key_path, value_name or None)
        if autoruns:
            return {
                "key_path": key_path,
                "value_name": value_name,
                "verdict": "EXPECTED",
                "reasons": ["Autorun matches Windows baseline"],
                "confidence": "high",
                "baseline_entries": len(autoruns),
            }

        filename_findings = []
        if value_name:
            filename = extract_filename(value_name)
            if context:
                suspicious = context.check_suspicious_filename(filename)
                if suspicious:
                    filename_findings.append({
                        "type": "known_tool", "severity": "high",
                        "tool_name": suspicious.get("tool_name", filename),
                    })
                lolbin = context.check_lolbin(filename)
                if lolbin:
                    filename_findings.append({
                        "type": "lolbin", "severity": "medium",
                        "description": f"LOLBin in autorun: {filename}",
                    })

        result = {
            "key_path": key_path,
            "value_name": value_name,
            "verdict": "UNKNOWN",
            "reasons": ["Autorun not in baseline (neutral)"],
            "confidence": "low",
        }
        if filename_findings:
            result["findings"] = filename_findings
        return result

    @server.tool()
    def check_registry(key_path: str, value_name: str = "", hive: str = "", os_version: str = "") -> dict:
        """Check a registry key or value against the full registry baseline.

        Requires known_good_registry.db (optional, 12GB). For autorun checks,
        use check_autorun instead — faster and doesn't need the large DB.

        Args:
            key_path: Registry key path
            value_name: Optional specific value name
            hive: Registry hive (SYSTEM, SOFTWARE, NTUSER, DEFAULT)
            os_version: Filter by OS version
        """
        db_dir = _get_db_path()
        reg_db = db_dir / "known_good_registry.db"
        if not reg_db.exists():
            return {"key_path": key_path, "verdict": "UNKNOWN",
                    "message": "Registry baseline not available (optional, ~12GB). Install separately."}

        audit.log(tool="check_registry", params={"key_path": key_path},
                  result_summary={"status": "checked"})

        registry_db = _open_registry_db()
        if not registry_db:
            return {
                "key_path": key_path,
                "value_name": value_name,
                "hive": hive,
                "verdict": "UNKNOWN",
                "reasons": ["Registry baseline exists but is not initialized with baseline_registry"],
                "confidence": "low",
                "lookup_performed": False,
            }

        matches = (
            registry_db.lookup_value(key_path, value_name, hive or None, os_version or None)
            if value_name else
            registry_db.lookup_key(key_path, hive or None, os_version or None)
        )
        if matches:
            all_os_versions = set()
            values_found = []
            for match in matches:
                all_os_versions.update(match.get("os_versions", []))
                if match.get("value_name"):
                    values_found.append({
                        "name": match.get("value_name"),
                        "type": match.get("value_type"),
                        "hive": match.get("hive"),
                    })
            result = {
                "key_path": key_path,
                "value_name": value_name,
                "hive": hive,
                "verdict": "EXPECTED",
                "reasons": ["Registry entry found in Windows baseline"],
                "confidence": "high",
                "in_baseline": True,
                "lookup_performed": True,
                "match_count": len(matches),
                "os_versions": sorted(all_os_versions)[:10],
                "os_version_count": len(all_os_versions),
            }
            if values_found:
                result["values"] = values_found[:10]
                result["value_count"] = len(values_found)
            return result

        return {
            "key_path": key_path,
            "value_name": value_name,
            "hive": hive,
            "verdict": "UNKNOWN",
            "reasons": ["Registry entry not in baseline (neutral - may be legitimate software)"],
            "confidence": "low",
            "in_baseline": False,
            "lookup_performed": True,
        }

    @server.tool()
    def check_hash(hash_value: str) -> dict:
        """Check a file hash against the LOLDrivers vulnerable driver database.

        Returns SUSPICIOUS (known vulnerable driver) or UNKNOWN.
        For broader threat intel, use OpenCTI lookup_indicator instead.

        Args:
            hash_value: File hash (MD5/SHA1/SHA256)
        """
        _, context = _open_dbs()
        if not context:
            return {"hash": hash_value, "verdict": "UNKNOWN",
                    "message": "Context database not available"}

        audit.log(tool="check_hash", params={"hash": hash_value[:16]},
                  result_summary={"status": "checked"})

        algo = detect_hash_algorithm(hash_value)
        if not algo:
            return {"hash": hash_value, "error": "Could not detect hash algorithm"}

        norm = normalize_hash(hash_value)
        driver = context.check_vulnerable_driver(norm, algo)

        verdict = calculate_hash_verdict(is_vulnerable_driver=driver is not None, driver_info=driver)

        result = {
            "hash": hash_value,
            "algorithm": algo,
            "verdict": str(verdict.verdict),
            "reasons": verdict.reasons,
            "confidence": verdict.confidence,
        }
        if driver:
            result["driver"] = {
                "product": driver.get("product", ""),
                "vendor": driver.get("vendor", ""),
                "cve": driver.get("cve", ""),
                "vulnerability_type": driver.get("vulnerability_type", ""),
                "match_type": driver.get("match_type", "file_hash"),
            }
        return result

    @server.tool()
    def analyze_filename_triage(filename: str) -> dict:
        """Analyze a filename for deception techniques: Unicode evasion,
        typosquatting, double extensions, and known attacker tools.

        Args:
            filename: Filename to analyze
        """
        _, context = _open_dbs()
        audit.log(tool="analyze_filename_triage", params={"filename": filename},
                  result_summary={"status": "analyzed"})

        result = analyze_filename(filename)
        all_findings = list(result["findings"])

        protected = context.get_protected_process_names() if context else []
        spoofing = check_process_name_spoofing(filename, protected)
        all_findings.extend(spoofing)

        if context:
            suspicious = context.check_suspicious_filename(filename)
            if suspicious:
                all_findings.append({
                    "type": "known_tool", "severity": "high",
                    "tool_name": suspicious.get("tool_name", filename),
                    "category": suspicious.get("category", ""),
                    "description": f"Known tool: {suspicious.get('tool_name', filename)}",
                })

        return {
            "filename": filename,
            "entropy": result["entropy"],
            "findings": all_findings,
            "is_suspicious": len(all_findings) > 0,
            "suspicious_count": len(all_findings),
        }

    @server.tool()
    def check_lolbin(filename: str) -> dict:
        """Check if a binary is a known LOLBin with abuse techniques.

        Args:
            filename: Filename to check (e.g. 'certutil.exe')
        """
        _, context = _open_dbs()
        if not context:
            return {"filename": filename, "verdict": "UNKNOWN",
                    "message": "Context database not available"}

        audit.log(tool="check_lolbin", params={"filename": filename},
                  result_summary={"status": "checked"})

        lolbin = context.check_lolbin(filename)
        if lolbin:
            return {
                "filename": filename,
                "found": True,
                "name": lolbin.get("name", ""),
                "description": lolbin.get("description", ""),
                "functions": lolbin.get("functions", []),
                "expected_paths": lolbin.get("expected_paths", []),
                "mitre_techniques": lolbin.get("mitre_techniques", []),
                "detection": lolbin.get("detection", ""),
            }
        return {"filename": filename, "found": False}

    @server.tool()
    def check_hijackable_dll(dll_name: str) -> dict:
        """Check if a DLL is known to be vulnerable to DLL search-order hijacking.

        Args:
            dll_name: DLL filename (e.g. 'version.dll')
        """
        _, context = _open_dbs()
        if not context:
            return {"dll_name": dll_name, "entries": [],
                    "message": "Context database not available"}

        audit.log(tool="check_hijackable_dll", params={"dll_name": dll_name},
                  result_summary={"status": "checked"})

        entries = context.check_hijackable_dll(dll_name)
        return {"dll_name": dll_name, "entries": entries, "hijackable": len(entries) > 0}

    @server.tool()
    def check_pipe(pipe_name: str) -> dict:
        """Check a named pipe against known Windows pipes and C2 framework pipes.

        Args:
            pipe_name: Named pipe name
        """
        _, context = _open_dbs()
        if not context:
            return {"pipe_name": pipe_name, "verdict": "UNKNOWN",
                    "message": "Context database not available"}

        audit.log(tool="check_pipe", params={"pipe_name": pipe_name},
                  result_summary={"status": "checked"})

        windows = context.check_windows_pipe(pipe_name)
        if windows:
            return {
                "pipe_name": pipe_name,
                "verdict": "EXPECTED",
                "reasons": [f"Known Windows pipe: {windows.get('protocol', '')}"],
                "confidence": "high",
                "description": windows.get("description", ""),
            }

        suspicious = context.check_suspicious_pipe(pipe_name)
        if suspicious:
            return {
                "pipe_name": pipe_name,
                "verdict": "SUSPICIOUS",
                "reasons": [f"Matches known {suspicious.get('tool_name', 'C2')} pipe pattern"],
                "confidence": "high",
                "tool": suspicious.get("tool_name", ""),
                "malware_family": suspicious.get("malware_family", ""),
            }

        return {
            "pipe_name": pipe_name,
            "verdict": "UNKNOWN",
            "reasons": ["Pipe not in known Windows or C2 databases (neutral)"],
            "confidence": "low",
        }

    @server.tool()
    def get_db_stats() -> dict:
        """Get statistics for all loaded baseline databases."""
        known_good, context = _open_dbs()
        stats = {}
        if known_good:
            stats["known_good"] = known_good.get_stats()
        if context:
            stats["context"] = context.get_stats()
        registry = _open_registry_db()
        if registry:
            stats["registry"] = registry.get_stats()
        stats["database_path"] = str(_get_db_path())
        return stats

    @server.tool()
    def get_health() -> dict:
        """Get server health: uptime, database connectivity, cache hit rates."""
        known_good, context = _open_dbs()
        return {
            "status": "healthy",
            "known_good_db": known_good is not None,
            "context_db": context is not None,
            "registry_db": _open_registry_db() is not None,
            "database_path": str(_get_db_path()),
        }

    @server.tool()
    def triage_status() -> dict:
        """Check triage database status."""
        db_dir = _get_db_path()
        known = db_dir / "known_good.db"
        context = db_dir / "context.db"
        registry = db_dir / "known_good_registry.db"
        if not known.exists() and not context.exists():
            return {
                "status": "not_installed",
                "message": "Triage databases not found. Run triage_download() to install.",
            }
        size_mb = sum(f.stat().st_size for f in [known, context, registry] if f.exists()) / (1024 * 1024)
        return {
            "status": "present",
            "known_good_db": known.exists(),
            "context_db": context.exists(),
            "registry_db": registry.exists(),
            "total_size_mb": round(size_mb, 1),
        }

    @server.tool()
    def triage_download(tag: str = "latest") -> dict:
        """Download baseline validation databases from GitHub releases.

        Downloads known_good.db (~5GB) and context.db (~10MB).
        known_good.db contains 2.6M+ records from clean Windows installations.

        Args:
            tag: Release tag (default: 'latest')
        """
        audit.log(tool="triage_download", params={"tag": tag},
                  result_summary={"status": "downloading"})

        db_dir = _get_db_path()
        success = download_databases(str(db_dir))
        if success:
            return {"status": "success", "database_path": str(db_dir)}
        return {"status": "failed", "message": "Download failed. Check network and retry."}
