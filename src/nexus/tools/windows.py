"""Windows forensic tool execution — catalog-gated, platform-gated.

Catalog-driven execution of Windows forensic tools across 7
categories, with result caching and structured output parsing.
"""

import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.config import settings

logger = logging.getLogger(__name__)
_IS_WINDOWS = sys.platform == "win32"

_WIN_CATALOG = {
    "amcacheparser": {"name": "AmcacheParser", "category": "zimmerman",
                      "description": "Parse Amcache.hve for application execution history"},
    "appcompatcacheparser": {"name": "AppCompatCacheParser", "category": "zimmerman",
                              "description": "Parse Shimcache for application compatibility"},
    "evtxecmd": {"name": "EvtxECmd", "category": "zimmerman",
                 "description": "Parse Windows Event Logs (EVTX)"},
    "jlecmd": {"name": "JLECmd", "category": "zimmerman",
               "description": "Parse Windows Jump Lists"},
    "lecmd": {"name": "LECmd", "category": "zimmerman",
              "description": "Parse Windows LNK files"},
    "mftecmd": {"name": "MFTECmd", "category": "zimmerman",
                "description": "Parse NTFS MFT files"},
    "pecmd": {"name": "PECmd", "category": "zimmerman",
              "description": "Parse Windows Prefetch files"},
    "rbcmd": {"name": "RBCmd", "category": "zimmerman",
              "description": "Parse Windows Recycle Bin artifacts"},
    "recmd": {"name": "RECmd", "category": "zimmerman",
              "description": "Parse Windows Registry hives"},
    "sbecmd": {"name": "SBECmd", "category": "zimmerman",
               "description": "Parse ShellBags"},
    "sqlecmd": {"name": "SQLECmd", "category": "zimmerman",
                "description": "Parse SQLite databases"},
    "srumecmd": {"name": "SrumECmd", "category": "zimmerman",
                 "description": "Parse SRUM data"},
    "wxtcmd": {"name": "WxTCmd", "category": "zimmerman",
               "description": "Parse Windows Timeline"},
    "bstrings": {"name": "bstrings", "category": "zimmerman",
                  "description": "Extract strings with binary awareness"},
    "autorunsc": {"name": "autorunsc", "category": "sysinternals",
                   "description": "List autostart entry points"},
    "sigcheck": {"name": "sigcheck", "category": "sysinternals",
                  "description": "Verify file signatures"},
    "strings": {"name": "strings64", "category": "sysinternals",
                 "description": "Extract ASCII/Unicode strings"},
    "handle": {"name": "handle64", "category": "sysinternals",
               "description": "Display open file handles"},
    "procdump": {"name": "procdump64", "category": "sysinternals",
                  "description": "Capture process memory dumps"},
    "winpmem": {"name": "winpmem", "category": "memory",
                "description": "Capture physical memory acquisition"},
    "dumpit": {"name": "dumpit", "category": "memory",
               "description": "Dump physical memory (DumpIt)"},
    "moneta": {"name": "moneta64", "category": "memory",
               "description": "Detect process memory anomalies"},
    "hollows_hunter": {"name": "hollows_hunter", "category": "memory",
                        "description": "Scan for hollowed/injected processes"},
    "hayabusa": {"name": "Hayabusa", "category": "timeline",
                  "description": "EVTX timeline analysis with Sigma rules"},
    "suzaku": {"name": "suzaku", "category": "timeline",
               "description": "Yamato Suzaku — fast EVTX / JSONL timeline + Sigma hunt"},
    "chainsaw": {"name": "chainsaw", "category": "timeline",
                  "description": "EVTX hunting with Sigma rules"},
    "mactime": {"name": "mactime.pl", "category": "timeline",
                 "description": "Create timeline from bodyfile (SLEUTHKIT)"},
    "kape": {"name": "KAPE", "category": "collection",
             "description": "Kroll Artifact Parser and Extractor"},
    "capa": {"name": "capa", "category": "analysis",
             "description": "Detect capabilities in executable files"},
    "yara": {"name": "yara64", "category": "analysis",
             "description": "Pattern matching for malware identification"},
    "densityscout": {"name": "densityscout", "category": "analysis",
                      "description": "Measure entropy/compression to find packed/encrypted data"},
    "get_injectedthreadex": {"name": "Get-InjectedThreadEx", "category": "scripts",
                              "description": "Detect injected threads (Get-InjectedThreadEx.exe / .ps1)"},
    "thumbcache_viewer": {"name": "thumbcache_viewer_cmd", "category": "analysis",
                           "description": "Extract Explorer thumbcache_*.db thumbnails (CLI)"},
    "bmc-tools": {"name": "bmc-tools.py", "category": "analysis",
                  "description": "Reconstruct RDP bitmap cache tiles (ANSSI bmc-tools)"},
    "bitsparser": {"name": "BitsParser.py", "category": "analysis",
                   "description": "Parse BITS qmgr.db / qmgr*.dat job queues from an image"},
    "kstrike": {"name": "KStrike.py", "category": "analysis",
                "description": "Parse Windows Server User Access Logging (UAL) ESE databases"},
    "logfileparser": {"name": "LogFileParser64", "category": "analysis",
                      "description": "Parse NTFS $LogFile transaction journal"},
}

_CACHE_TTL = 86400
_CACHE_MAX = 256
_result_cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()


def _cache_get(key: str) -> dict | None:
    if key not in _result_cache:
        return None
    ts, result = _result_cache[key]
    if time.monotonic() - ts > _CACHE_TTL:
        del _result_cache[key]
        return None
    _result_cache.move_to_end(key)
    return result


def _cache_put(key: str, result: dict) -> None:
    if len(_result_cache) >= _CACHE_MAX:
        _result_cache.popitem(last=False)
    _result_cache[key] = (time.monotonic(), result)


def _catalog_key(token: str) -> str | None:
    """Map EvtxECmd.exe / hayabusa-4.0.0-win-x64 → catalog key."""
    stem = Path(token).stem.lower()
    stem_norm = stem.replace("-", "_")
    if stem in _WIN_CATALOG:
        return stem
    if stem_norm in _WIN_CATALOG:
        return stem_norm
    for key in _WIN_CATALOG:
        if stem == key or stem_norm == key or stem.startswith(f"{key}-") or stem.startswith(f"{key}_"):
            return key
        pretty = _WIN_CATALOG[key]["name"].lower()
        pretty_stem = Path(pretty).stem
        if stem == pretty or stem == pretty_stem or stem.startswith(f"{pretty}-") or stem.startswith(f"{pretty_stem}-"):
            return key
    return None


def _name_matches(filename: str, wanted: str) -> bool:
    f = filename.lower()
    w = Path(wanted).name.lower()
    wstem = Path(w).stem.lower()
    if f == w or f == f"{wstem}.exe" or f == f"{wstem}.ps1" or f == f"{wstem}.pl" or f == f"{wstem}.py":
        return True
    # hayabusa-4.0.0-win-x64.exe / suzaku-2.0.0-win-x64.exe
    if f.startswith(f"{wstem}-") and f.endswith(".exe"):
        return True
    if f.startswith(f"{wstem}_") and f.endswith(".exe"):
        return True
    return False


def _prefer_binary(paths: list[Path]) -> Path | None:
    if not paths:
        return None
    rank = {".exe": 0, ".cmd": 1, ".bat": 1, ".ps1": 3, ".pl": 4, ".py": 4}

    def _key(p: Path) -> tuple[int, str]:
        return (rank.get(p.suffix.lower(), 2 if not p.suffix else 5), str(p).lower())

    return sorted(paths, key=_key)[0]


def _find_binary(name: str) -> str | None:
    """Resolve a catalog binary from NEXUS_TOOL_PATHS, then repo Tools/windows.

    Does not search PATH. Walks a few levels so Zimmerman net9/EvtxeCmd/EvtxECmd.exe
    and versioned Hayabusa/Suzaku names resolve. Skips rule/sigma trees.
    """
    if not name:
        return None
    candidates = [name]
    stem = Path(name).stem
    key = _catalog_key(name)
    if os.name == "nt" and not name.lower().endswith(".exe"):
        candidates.append(f"{name}.exe")
    if key:
        pretty = _WIN_CATALOG[key]["name"]
        candidates.extend([pretty, f"{pretty}.exe", key, f"{key}.exe"])

    seen: set[str] = set()
    for cand in candidates:
        low = cand.lower()
        if low in seen:
            continue
        seen.add(low)

    extra_dirs = [Path(p) for p in settings.tool_paths if p]
    repo_win = Path(__file__).resolve().parents[3] / "Tools" / "windows"
    if repo_win.is_dir():
        extra_dirs.append(repo_win)

    skip_dirs = {"rules", "sigma", ".git", "html_report", "__pycache__"}
    hits: list[Path] = []
    for root in extra_dirs:
        if not root.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            rel = Path(dirpath).relative_to(root)
            if len(rel.parts) > 5:
                dirnames.clear()
                continue
            dirnames[:] = [d for d in dirnames if d.lower() not in skip_dirs]
            for fn in filenames:
                if any(_name_matches(fn, cand) for cand in seen):
                    hits.append(Path(dirpath) / fn)
    chosen = _prefer_binary(hits)
    return str(chosen) if chosen else None


def _parse_output(stdout: str | None, stderr: str | None) -> dict:
    stdout = "" if stdout is None else stdout
    stderr = "" if stderr is None else stderr
    result: dict[str, Any] = {"stdout": stdout, "stderr": stderr}
    if not stdout.strip():
        return result
    try:
        result["parsed_json"] = json.loads(stdout)
        result["format"] = "json"
        return result
    except (json.JSONDecodeError, ValueError):
        pass
    if "," in stdout[:500] and "\n" in stdout[:2000]:
        import csv
        import io
        try:
            reader = csv.DictReader(io.StringIO(stdout))
            rows = []
            for i, row in enumerate(reader):
                if i >= 100:
                    break
                rows.append(row)
            if rows:
                result["parsed_csv"] = rows
                result["format"] = "csv"
                return result
        except Exception:
            pass
    result["format"] = "text"
    return result


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _active_case_dir() -> Path | None:
    from nexus.case.outputs import resolve_active_case_dir

    return resolve_active_case_dir()


def register_tools(server: FastMCP, audit: AuditWriter):
    if not _IS_WINDOWS:
        logger.debug("Windows tools skipped: not on Windows")
        return
    @server.tool()
    def scan_tools() -> dict:
        """Scan for all cataloged Windows forensic tools. Reports availability and install guidance."""
        if not _IS_WINDOWS:
            return {"platform": sys.platform, "tools": [],
                    "message": "Windows tools unavailable on this platform"}

        tools = []
        available = 0
        for key, info in sorted(_WIN_CATALOG.items()):
            binary = info["name"]
            found = _find_binary(binary) is not None
            if found:
                available += 1
            tools.append({
                "key": key, "name": info["name"], "category": info["category"],
                "description": info["description"], "installed": found,
            })
        return {"platform": sys.platform, "total": len(tools), "available": available,
                "missing": len(tools) - available, "tools": tools,
                "categories": list(dict.fromkeys(t["category"] for t in tools))}

    @server.tool()
    def get_share_info() -> dict:
        """Get case/share paths for cross-machine Windows and SIFT analysis."""
        case_dir = _active_case_dir()
        result = {"share_root": settings.share_root or ""}
        if case_dir:
            result.update({
                "case_dir": str(case_dir),
                "evidence_dir": str(case_dir / "evidence"),
                "extractions_dir": str(case_dir / "extractions"),
                "audit_dir": str(case_dir / "audit"),
            })
        else:
            result["note"] = "No active case. Run case_init or case_activate first."
        return result

    @server.tool()
    def list_windows_tools(category: str = "") -> dict:
        """List forensic tools available on this Windows system, optionally by category.

        Args:
            category: Optional filter by category (zimmerman, sysinternals, memory, timeline, collection, analysis, scripts)
        """
        if not _IS_WINDOWS:
            return {"tools": [], "count": 0, "error": "Windows tools unavailable"}
        result = []
        for key, info in sorted(_WIN_CATALOG.items()):
            if category and info["category"] != category:
                continue
            binary = info["name"]
            found = _find_binary(binary) is not None
            result.append({
                "name": info["name"], "key": key, "category": info["category"],
                "description": info["description"], "installed": found,
            })
        return {"tools": result, "count": len(result)}

    @server.tool()
    def list_missing_windows_tools() -> list:
        """List Windows tools not installed, with installation guidance."""
        if not _IS_WINDOWS:
            return [{"error": "Windows tools unavailable"}]
        missing = []
        install_hints = {
            "amcacheparser": "choco install amcacheparser",
            "evtxecmd": "choco install ericzimmerman",
            "hayabusa": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub Yamato-Security/hayabusa latest)",
            "suzaku": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub Yamato-Security/suzaku latest)",
            "chainsaw": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub WithSecureLabs/chainsaw latest)",
            "kape": "Download current KAPE from Kroll (not redistributable). Unpack to Tools/windows/kape/",
            "capa": "pip install flare-capa",
            "yara": "choco install yara",
            "winpmem": "https://github.com/Velocidex/WinPmem/releases",
            "thumbcache_viewer": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub thumbcacheviewer/thumbcacheviewer)",
            "bmc-tools": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub ANSSI-FR/bmc-tools)",
            "bitsparser": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub mandiant/BitsParser)",
            "kstrike": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub BrandonLeBlanc/KStrike)",
            "logfileparser": "pwsh -File Tools/fetch-windows-tools.ps1  (GitHub jschicht/LogFileParser)",
        }
        for key, info in sorted(_WIN_CATALOG.items()):
            if _find_binary(info["name"]) is None:
                entry = {"name": info["name"], "category": info["category"],
                         "description": info["description"]}
                hint = install_hints.get(key)
                if hint:
                    entry["install"] = hint
                missing.append(entry)
        return missing

    @server.tool()
    def check_windows_tools(tool_names: list[str]) -> dict:
        """Check which Windows tools are installed and available.

        Args:
            tool_names: List of tool names to check
        """
        result = {}
        for name in tool_names:
            found = _find_binary(name) is not None
            entry = {"name": name, "installed": found}
            for _key, info in _WIN_CATALOG.items():
                if info["name"].lower() == name.lower():
                    entry["category"] = info["category"]
                    entry["description"] = info["description"]
                    break
            result[name] = entry
        return result

    @server.tool()
    def get_windows_tool_help(tool_name: str) -> dict:
        """Get usage information for a specific tool.

        Args:
            tool_name: Tool name (e.g. 'MFTECmd', 'Hayabusa')
        """
        tool_key = tool_name.lower().replace(".exe", "").replace(".pl", "")
        info = _WIN_CATALOG.get(tool_key)
        if not info:
            return {"tool": tool_name, "found": False,
                    "error": f"Tool '{tool_name}' not in catalog"}
        return {
            "tool": tool_name, "found": True,
            "name": info["name"], "category": info["category"],
            "description": info["description"],
            "installed": _find_binary(info["name"]) is not None,
        }

    @server.tool()
    def suggest_windows_tools(artifact_type: str, question: str = "") -> list:
        """Suggest Windows tools for analyzing a specific artifact type.

        Args:
            artifact_type: Type of artifact (evtx, registry, mft, prefetch, memory, timeline, malware, etc.)
            question: Optional context for better suggestions
        """
        suggestions = {
            "mft": ["MFTECmd"],
            "prefetch": ["PECmd"],
            "evtx": ["EvtxECmd", "Hayabusa", "suzaku", "chainsaw"],
            "registry": ["RECmd"],
            "shellbags": ["SBECmd"],
            "jumplist": ["JLECmd"],
            "lnk": ["LECmd"],
            "amcache": ["AmcacheParser"],
            "shimcache": ["AppCompatCacheParser"],
            "timeline": ["Hayabusa", "suzaku", "chainsaw", "mactime"],
            "malware": ["capa", "yara", "sigcheck"],
            "autoruns": ["autorunsc"],
            "strings": ["bstrings", "strings"],
            "memory": ["winpmem", "dumpit", "moneta", "hollows_hunter"],
            "collection": ["kape"],
            "recycle": ["RBCmd"],
            "srum": ["SrumECmd"],
            "thumbcache": ["thumbcache_viewer_cmd"],
            "bits": ["BitsParser.py"],
            "ual": ["KStrike.py"],
            "rdp": ["bmc-tools.py", "EvtxECmd", "Hayabusa"],
            "logfile": ["LogFileParser64", "MFTECmd"],
        }
        at = artifact_type.lower().strip()
        tool_names = suggestions.get(at, [])
        try:
            from nexus import knowledge as fk
            art = fk.get_artifact(at)
            if art and art.get("related_tools"):
                tool_names = list(dict.fromkeys(
                    list(art["related_tools"]) + tool_names
                ))
            else:
                for cand in fk.list_artifacts(platform="windows"):
                    name = (cand.get("name") or "").lower()
                    slug = name.replace(" ", "_")
                    if at in name or at == slug:
                        tool_names = list(dict.fromkeys(
                            list(cand.get("related_tools") or []) + tool_names
                        ))
                        break
        except Exception:
            pass
        return [
            {"name": tn, "installed": _find_binary(tn) is not None}
            for tn in tool_names
        ]

    @server.tool()
    def list_kape_targets(list_type: str = "targets") -> list:
        """List available KAPE targets or modules in structured categories.

        Args:
            list_type: 'targets' or 'modules' (default: targets)
        """
        if not _IS_WINDOWS:
            return [{"error": "Windows tools unavailable"}]
        kape_bin = _find_binary("kape.exe") or _find_binary("KAPE") or _find_binary("kape")
        if not kape_bin:
            return [{"error": "KAPE not found. Install via: choco install kape"}]
        kape_home = Path(kape_bin).parent
        kind = "Targets" if str(list_type).lower().startswith("target") else (
            "Modules" if str(list_type).lower().startswith("module") else "Targets"
        )
        candidates = [kape_home / kind, kape_home.parent / kind]
        list_dir = next((p for p in candidates if p.is_dir()), None)
        if list_dir is None:
            return [{"error": f"KAPE {kind} directory not found at {kape_home / kind}"}]
        result = []
        for f in sorted(list_dir.rglob("*.tkape")) + sorted(list_dir.rglob("*.mkape")):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")[:2000]
                categories = []
                for line in text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("category:"):
                        categories.append(line.split(":", 1)[1].strip())
                result.append({
                    "name": f.stem, "file": f.name,
                    "categories": categories, "path": str(f),
                })
            except Exception:
                result.append({"name": f.stem, "file": f.name, "categories": []})
        return result

    @server.tool()
    def run_windows_command(
        command: str | list[str],
        purpose: str = "",
        timeout: int = 600,
        save_output: bool = True,
        input_files: list[str] | None = None,
    ) -> dict:
        """Execute a catalog-approved forensic tool.

        Args:
            command: Command list or string (tool + args). Must start with a cataloged tool.
            purpose: Why this command is being run (for audit trail)
            timeout: Max execution time in seconds (default: 600)
            save_output: Persist stdout/stderr under active case extractions/
                (default True — designed contract; set False only for dry probes)
            input_files: Files this command reads; auto-detected as a fallback
        """
        if not _IS_WINDOWS:
            return {"success": False, "error": "Windows tools unavailable on this platform",
                    "platform": sys.platform}

        start = time.monotonic()
        if isinstance(command, str):
            command_text = command
            parts = shlex.split(command)
        else:
            parts = [str(p) for p in command]
            command_text = " ".join(parts)
        if not parts:
            return {"success": False, "error": "Empty command"}
        binary = parts[0]
        binary_key = _catalog_key(binary) or Path(binary).stem.lower()

        denied = {"cmd", "powershell", "pwsh", "wscript", "cscript",
                  "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin",
                  "msiexec", "bash", "wsl", "sh", "ncat", "nc"}
        if Path(binary).stem.lower() in denied:
            audit_id = audit.log(
                tool="run_windows_command_blocked",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": f"Binary denied: {binary}"},
            )
            return {"success": False, "error": f"Binary denied: {binary}", "audit_id": audit_id}

        if binary_key not in _WIN_CATALOG:
            audit_id = audit.log(
                tool="run_windows_command_blocked",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": f"Tool not in allowlist: {binary}"},
            )
            return {"success": False, "error": f"Tool not in allowlist: {binary}", "audit_id": audit_id}

        resolved = _find_binary(binary) or _find_binary(_WIN_CATALOG[binary_key]["name"])
        if resolved:
            parts[0] = resolved
        else:
            audit_id = audit.log(
                tool="run_windows_command",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": f"Tool not found: {binary}"},
            )
            return {
                "success": False,
                "error": f"Tool not found: {binary}. Put it under Tools/windows/ or set NEXUS_TOOL_PATHS.",
                "audit_id": audit_id,
            }

        resolved_path = Path(parts[0])
        extra_args = parts[1:]
        if resolved_path.suffix.lower() == ".ps1":
            ps = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
            parts = [str(ps), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                     "-File", str(resolved_path), *extra_args]
        elif resolved_path.suffix.lower() == ".pl":
            perl = shutil.which("perl") or shutil.which("perl.exe")
            if not perl:
                audit_id = audit.log(
                    tool="run_windows_command",
                    params={"command": command_text[:500], "purpose": purpose[:200]},
                    result_summary={"error": "perl required to run mactime.pl"},
                )
                return {
                    "success": False,
                    "error": "perl is required to run mactime.pl on Windows (not found on PATH).",
                    "audit_id": audit_id,
                }
            parts = [perl, str(resolved_path), *extra_args]
        elif resolved_path.suffix.lower() == ".py":
            py = (
                shutil.which("python")
                or shutil.which("python3")
                or shutil.which("py")
            )
            if not py:
                audit_id = audit.log(
                    tool="run_windows_command",
                    params={"command": command_text[:500], "purpose": purpose[:200]},
                    result_summary={"error": "python required to run catalog .py tools"},
                )
                return {
                    "success": False,
                    "error": "python is required to run BitsParser/KStrike/bmc-tools (not found on PATH).",
                    "audit_id": audit_id,
                }
            parts = [py, str(resolved_path), *extra_args]

        detected_inputs = list(input_files or [])
        if not detected_inputs:
            for token in parts[1:]:
                if token.startswith("-"):
                    continue
                candidate = token.strip("\"'")
                if candidate and Path(candidate).exists():
                    detected_inputs.append(candidate)

        input_hashes: dict[str, str] = {}
        for inp in detected_inputs:
            try:
                input_hashes[inp] = _hash_file(inp)
            except (OSError, FileNotFoundError):
                input_hashes[inp] = ""

        try:
            proc = subprocess.run(
                parts, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=timeout, shell=False
            )
        except FileNotFoundError:
            elapsed = (time.monotonic() - start) * 1000
            audit_id = audit.log(
                tool="run_windows_command",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": f"Tool not found: {binary}"},
                elapsed_ms=elapsed,
                input_files=list(input_hashes) or None,
                input_sha256s=list(input_hashes.values()) or None,
            )
            return {"success": False, "error": f"Tool not found: {binary}", "audit_id": audit_id}
        except PermissionError:
            elapsed = (time.monotonic() - start) * 1000
            audit_id = audit.log(
                tool="run_windows_command",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": f"Permission denied: {binary}"},
                elapsed_ms=elapsed,
                input_files=list(input_hashes) or None,
                input_sha256s=list(input_hashes.values()) or None,
            )
            return {"success": False, "error": f"Permission denied: {binary}", "audit_id": audit_id}
        except subprocess.TimeoutExpired:
            elapsed = (time.monotonic() - start) * 1000
            audit_id = audit.log(
                tool="run_windows_command",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": f"Command timed out after {timeout}s", "exit_code": -9},
                elapsed_ms=elapsed,
                input_files=list(input_hashes) or None,
                input_sha256s=list(input_hashes.values()) or None,
            )
            return {"success": False, "error": f"Command timed out after {timeout}s",
                    "exit_code": -9, "audit_id": audit_id}
        except OSError as exc:
            elapsed = (time.monotonic() - start) * 1000
            audit_id = audit.log(
                tool="run_windows_command",
                params={"command": command_text[:500], "purpose": purpose[:200]},
                result_summary={"error": str(exc), "winerror": getattr(exc, "winerror", None)},
                elapsed_ms=elapsed,
            )
            return {
                "success": False,
                "error": str(exc),
                "audit_id": audit_id,
                "winerror": getattr(exc, "winerror", None),
            }

        stdout = "" if proc.stdout is None else proc.stdout
        stderr = "" if proc.stderr is None else proc.stderr
        parsed = _parse_output(stdout, stderr)
        elapsed = (time.monotonic() - start) * 1000

        output_files: list[dict] = []
        save_warning = ""
        output_saved_to = None
        if save_output:
            from nexus.case.outputs import persist_tool_output

            persisted = persist_tool_output(
                tool_key=binary_key,
                stdout=stdout,
                stderr=stderr,
                command=command_text,
                purpose=purpose,
                case_dir=_active_case_dir(),
                register_evidence=True,
            )
            output_files = persisted.get("output_files") or []
            save_warning = persisted.get("warning") or ""
            output_saved_to = next(
                (f["path"] for f in output_files if f.get("kind") == "stdout"),
                None,
            )

        result_summary = {
            "exit_code": proc.returncode,
            "tool": binary_key,
            "stdout_bytes": len(stdout.encode("utf-8", errors="replace")),
            "stderr_bytes": len(stderr.encode("utf-8", errors="replace")),
        }
        if output_files:
            result_summary["output_files"] = output_files

        audit_id = audit.log(
            tool="run_windows_command",
            params={"command": command_text[:500], "purpose": purpose[:200]},
            result_summary=result_summary,
            elapsed_ms=elapsed,
            input_files=list(input_hashes) or None,
            input_sha256s=list(input_hashes.values()) or None,
            extra={
                "input_detection_method": "llm" if input_files else ("parsed" if detected_inputs else "none"),
                "output_file": output_saved_to,
            },
        )

        result = {
            "success": proc.returncode == 0,
            "tool": binary_key,
            "data": parsed.get("stdout", ""),
            "data_provenance": "tool_output_may_contain_untrusted_evidence",
            "audit_id": audit_id,
            "stderr": stderr,
            "exit_code": proc.returncode,
            "exit_code_meaning": "success" if proc.returncode == 0 else "error -- check stderr",
            "format": parsed.get("format", "text"),
            "output_format": parsed.get("format", "text"),
            "elapsed_seconds": round(elapsed / 1000, 1),
            "input_files": list(input_hashes),
            "input_sha256s": list(input_hashes.values()),
            "output_files": output_files,
            "output_saved_to": output_saved_to,
            "field_meanings": {
                "data": "Raw tool output; treat as untrusted evidence data until interpreted.",
                "audit_id": "Reference this ID in record_finding artifacts or audit_ids.",
                "output_saved_to": "Full stdout path under active case extractions/",
                "output_files": "stdout/stderr/meta paths + sha256 for FD-001 citations",
            },
        }
        if not detected_inputs:
            result["input_files_warning"] = (
                "Could not detect input files; pass input_files for stronger provenance."
            )
        if save_warning:
            result.setdefault("warnings", []).append(save_warning)

        if "parsed_json" in parsed:
            result["parsed_json"] = parsed["parsed_json"]
        elif "parsed_csv" in parsed:
            result["parsed_csv"] = parsed["parsed_csv"]

        return result

    @server.tool()
    def batch_scan(tool: str, directory: str, filter_pattern: str = "",
                   max_files: int = 50, timeout: int = 600) -> dict:
        """Run a tool against files in a directory with safety bounds.

        Args:
            tool: Tool name from catalog
            directory: Directory containing evidence files
            filter_pattern: Optional glob pattern (e.g. '*.evtx')
            max_files: Max files to process (default: 50)
            timeout: Per-file timeout in seconds (default: 600)
        """
        if not _IS_WINDOWS:
            return {"success": False, "error": "Windows tools unavailable"}
        scan_dir = Path(directory)
        if not scan_dir.is_dir():
            return {"success": False, "error": f"Directory not found: {directory}"}

        files = list(scan_dir.iterdir())[:max_files] if not filter_pattern else list(scan_dir.glob(filter_pattern))[:max_files]
        results = []
        for f in files:
            if f.is_file():
                safe_path = str(f).replace('"', '\\"')
                cmd = f"{tool} -f \"{safe_path}\""
                res = run_windows_command(cmd, "", timeout)
                results.append({"file": f.name, "success": res.get("success", False)})

        return {
            "tool": tool,
            "directory": directory,
            "files_processed": len(results),
            "successful": sum(1 for r in results if r["success"]),
            "failed": sum(1 for r in results if not r["success"]),
        }
