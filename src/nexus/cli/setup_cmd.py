"""LLM client configuration generator for DFIR-Nexus.

Generates config files for Claude Code, Claude Desktop, or other MCP clients
to connect to one or more DFIR-Nexus servers (SIFT, Windows, REMnux, etc.).

Usage:
    nexus setup client                    # Interactive wizard
    nexus setup client --sift localhost   # SIFT server URL
    nexus setup client --windows 10.0.0.5:4508  # Windows server URL
    nexus setup client --uninstall        # Remove config
"""

import contextlib
import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# External reference MCPs (optional, public, no auth)
# ---------------------------------------------------------------------------
_ZELTSER_MCP = {
    "name": "zeltser-ir-writing",
    "type": "streamable-http",
    "url": "https://website-mcp.zeltser.com/mcp",
}

_MSLEARN_MCP = {
    "name": "microsoft-learn",
    "type": "streamable-http",
    "url": "https://learn.microsoft.com/api/mcp",
}

# ---------------------------------------------------------------------------
# Config dirs
# ---------------------------------------------------------------------------
_NEXUS_DIR = Path.home() / ".nexus"
_MCP_NAMES = {"dfir-nexus", "zeltser-ir-writing", "microsoft-learn"}


def cmd_setup_client(args) -> None:
    """Generate LLM client configuration for DFIR-Nexus endpoints."""
    if getattr(args, "uninstall", False):
        _cmd_uninstall()
        return

    auto = getattr(args, "yes", False)

    # Resolve server URLs (any can be empty)
    sift_url = _resolve_sift(args, auto)
    windows_url = _resolve_windows(args, auto)
    remnux_url = _resolve_remnux(args, auto)
    client = _resolve_client(args, auto)
    include_zeltser, include_mslearn = _resolve_internet_mcps(args, auto)

    # Build endpoint list
    servers: dict[str, dict] = {}

    if sift_url:
        servers["dfir-nexus-sift"] = _make_entry(sift_url)
    if windows_url:
        servers["dfir-nexus-windows"] = _make_entry(windows_url)
    if remnux_url:
        servers["dfir-nexus-remnux"] = _make_entry(remnux_url)

    # If no remote servers, add local dev entry
    if not servers:
        servers["dfir-nexus"] = {
            "type": "stdio",
            "command": sys.executable,
            "args": ["-m", "nexus"],
        }

    if include_zeltser:
        servers[_ZELTSER_MCP["name"]] = {"type": _ZELTSER_MCP["type"], "url": _ZELTSER_MCP["url"]}
    if include_mslearn:
        servers[_MSLEARN_MCP["name"]] = {"type": _MSLEARN_MCP["type"], "url": _MSLEARN_MCP["url"]}

    if not servers:
        print("No endpoints configured — nothing to write.", file=sys.stderr)
        return

    # Generate config for selected client
    _generate_config(client, servers)


def _make_entry(url: str) -> dict:
    return {
        "type": "streamable-http",
        "url": url.rstrip("/"),
    }


# =========================================================================
# Interactive wizard helpers
# =========================================================================

def _prompt(message: str, default: str = "") -> str:
    try:
        if default:
            answer = input(f"{message} [{default}]: ").strip()
            return answer or default
        return input(f"{message}: ").strip()
    except EOFError:
        return default


def _prompt_yn(message: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    try:
        answer = input(f"{message} [{hint}]: ").strip().lower()
    except EOFError:
        return default
    if not answer:
        return default
    return answer.startswith("y")


def _resolve_client(args, auto: bool) -> str:
    val = getattr(args, "client", None)
    if val:
        return val
    if auto:
        return "claude-code"
    print("\n=== DFIR-Nexus Client Configuration ===")
    print("Which LLM client will connect to your DFIR-Nexus servers?\n")
    print("  1. Claude Code      CLI agent (writes .mcp.json + settings.json)")
    print("  2. Claude Desktop   Desktop app (writes claude_desktop_config.json)")
    print("  3. Other            Prints raw JSON for any MCP client")
    choice = _prompt("\nChoose", "1")
    return {"1": "claude-code", "2": "claude-desktop", "3": "other"}.get(choice, "other")


def _resolve_sift(args, auto: bool) -> str:
    """Resolve SIFT DFIR-Nexus URL."""
    val = getattr(args, "sift", None)
    if val is not None:
        return val
    if auto:
        return "http://127.0.0.1:4508"

    is_sift = os.path.exists("/usr/share/sift") or os.path.exists("/opt/sift")
    default = "http://127.0.0.1:4508"
    if is_sift:
        print("\n--- SIFT Workstation ---")
        print(f"  DFIR-Nexus detected on SIFT. Default URL: {default}")
    else:
        print("\n--- SIFT Workstation (Forensic Analysis) ---")
        print("  If you run DFIR-Nexus on a SIFT workstation,")
        print(f"  enter its URL. Default: {default}")
    answer = _prompt("\nSIFT DFIR-Nexus URL", default)
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_windows(args, auto: bool) -> str:
    """Resolve Windows DFIR-Nexus URL."""
    val = getattr(args, "windows", None)
    if val is not None:
        return val
    if auto:
        return ""
    is_win = sys.platform == "win32"
    if is_win:
        print("\n--- Windows Forensic Workstation ---")
        print("  DFIR-Nexus detected on Windows. Default URL: http://127.0.0.1:4508")
        answer = _prompt("Windows DFIR-Nexus URL", "http://127.0.0.1:4508")
        if answer.lower() == "skip":
            return ""
        return answer
    print("\n--- Windows Forensic Workstation ---")
    print("  If you run DFIR-Nexus on a Windows machine with")
    print("  forensic tools (Zimmerman, Sysinternals, KAPE),")
    print("  enter its URL. This gives your LLM access to")
    print("  Windows forensic capabilities.")
    answer = _prompt("\nWindows DFIR-Nexus URL (or 'skip')", "skip")
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_remnux(args, auto: bool) -> str:
    """Resolve REMnux DFIR-Nexus URL."""
    val = getattr(args, "remnux", None)
    if val is not None:
        return val
    if auto:
        return ""
    print("\n--- REMnux Malware Analysis ---")
    print("  If you run DFIR-Nexus on a REMnux VM with")
    print("  malware analysis tools (capa, YARA),")
    print("  enter its URL.")
    answer = _prompt("\nREMnux DFIR-Nexus URL (or 'skip')", "skip")
    if answer.lower() == "skip":
        return ""
    return answer


def _resolve_internet_mcps(args, auto: bool) -> tuple[bool, bool]:
    no_mslearn = getattr(args, "no_mslearn", False)
    if auto:
        return (True, not no_mslearn)
    print("\n--- Internet MCPs (public, no auth) ---")
    print("  Zeltser IR Writing   Required for IR report generation")
    include_mslearn = _prompt_yn("  Microsoft Learn      Search Microsoft docs", default=True)
    return (True, include_mslearn)


# =========================================================================
# Config generation
# =========================================================================

def _generate_config(client: str, servers: dict[str, dict]) -> None:
    """Generate client config files."""
    if client == "claude-code":
        _gen_claude_code(servers)
    elif client == "claude-desktop":
        _gen_claude_desktop(servers)
    else:
        _gen_other(servers)


def _gen_claude_code(servers: dict[str, dict]) -> None:
    """Generate .mcp.json and settings.json for Claude Code CLI."""
    # Write project-level .mcp.json
    mcp_config = {"mcpServers": {}}
    for name, entry in servers.items():
        if entry.get("type") == "stdio":
            mcp_config["mcpServers"][name] = entry
        else:
            mcp_config["mcpServers"][name] = entry
    mcp_path = Path(".mcp.json")
    mcp_path.write_text(json.dumps(mcp_config, indent=2))
    print(f"\n  Wrote: {mcp_path.resolve()}")

    # Write global settings.json with deny rules
    settings_dir = Path.home() / ".claude"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_path = settings_dir / "settings.json"

    deny_rules = [
        "Edit(**/findings.json)", "Write(**/findings.json)",
        "Edit(**/timeline.json)", "Write(**/timeline.json)",
        "Edit(**/approvals.jsonl)", "Write(**/approvals.jsonl)",
        "Edit(**/todos.json)", "Write(**/todos.json)",
        "Edit(**/CASE.yaml)", "Write(**/CASE.yaml)",
        "Edit(**/audit/*.jsonl)", "Write(**/audit/*.jsonl)",
        "Edit(**/evidence_registry.json)", "Write(**/evidence_registry.json)",
        "Edit(**/iocs.json)", "Write(**/iocs.json)",
        "Bash(nexus approve*)", "Bash(*nexus approve*)",
        "Bash(nexus reject*)", "Bash(*nexus reject*)",
        "Edit(**/.nexus/)**", "Write(**/.nexus/**)",
        "Edit(**/.claude/settings.json)", "Write(**/.claude/settings.json)",
    ]

    existing = {}
    if settings_path.exists():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            existing = json.loads(settings_path.read_text())

    existing["mcpServers"] = mcp_config["mcpServers"]
    existing["allow"] = list(set(existing.get("allow", []) + [f"mcp__{n}__*" for n in servers]))
    existing["deny"] = list(set(existing.get("deny", []) + deny_rules))

    _write_protected(settings_path, json.dumps(existing, indent=2))
    print(f"  Wrote: {settings_path.resolve()}")
    print(f"\n  {len(servers)} server(s) configured.")
    print("  Deny rules protect findings/timeline/evidence from AI modification.")


def _gen_claude_desktop(servers: dict[str, dict]) -> None:
    """Generate claude_desktop_config.json."""
    config = {"mcpServers": {}}
    for name, entry in servers.items():
        if entry.get("type") == "stdio":
            config["mcpServers"][name] = entry
        else:
            config["mcpServers"][name] = entry
    config_path = Path("claude_desktop_config.json")
    config_path.write_text(json.dumps(config, indent=2))
    print(f"\n  Wrote: {config_path.resolve()}")
    print("  Copy to Claude Desktop settings directory.")


def _gen_other(servers: dict[str, dict]) -> None:
    """Print raw JSON for any MCP client."""
    config = {"mcpServers": servers}
    print("\n=== MCP Server Configuration ===\n")
    print(json.dumps(config, indent=2))
    print("\nAdd this to your MCP client's configuration.")


def _write_protected(path: Path, content: str) -> None:
    """Write file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = __import__("tempfile").mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        os.close(fd)
        with open(tmp, "w") as f:
            f.write(content)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# =========================================================================
# Uninstall
# =========================================================================

def _cmd_uninstall() -> None:
    """Remove DFIR-Nexus MCP entries from config files."""
    print("\n=== Uninstall DFIR-Nexus Client Configuration ===\n")

    # Clean .mcp.json
    mcp_path = Path(".mcp.json")
    if mcp_path.exists():
        try:
            config = json.loads(mcp_path.read_text())
            servers = config.get("mcpServers", {})
            removed = [k for k in servers if k in _MCP_NAMES or k.startswith("dfir-nexus")]
            for k in removed:
                del servers[k]
            config["mcpServers"] = servers
            if servers:
                mcp_path.write_text(json.dumps(config, indent=2))
            else:
                mcp_path.unlink()
            if removed:
                print(f"  Removed from .mcp.json: {', '.join(removed)}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Error reading .mcp.json: {e}")

    # Clean global settings.json
    settings_path = Path.home() / ".claude" / "settings.json"
    if settings_path.exists():
        try:
            config = json.loads(settings_path.read_text())
            servers = config.get("mcpServers", {})
            removed = [k for k in servers if k in _MCP_NAMES or k.startswith("dfir-nexus")]
            for k in removed:
                del servers[k]
            config["mcpServers"] = servers
            # Also clean allow/deny rules
            for key in ("allow", "deny"):
                if key in config:
                    config[key] = [r for r in config[key] if not any(n in r for n in _MCP_NAMES) and "dfir-nexus" not in r]
            if servers or config.get("allow") or config.get("deny"):
                settings_path.write_text(json.dumps(config, indent=2))
            else:
                settings_path.unlink()
            if removed:
                print(f"  Removed from settings.json: {', '.join(removed)}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Error reading settings.json: {e}")

    print("\n  Uninstall complete.")
