"""Quickstart — one-command onboarding for new DFIR-Nexus users.

Runs connectivity test, downloads baselines, creates demo case,
and prints the LLM client config snippet.
"""

import json
import os
import sys
import typer
from pathlib import Path

app = typer.Typer(help="Quickstart — one-command onboarding")


@app.command()
def init(
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    case_name: str = typer.Option("Demo Investigation", "--case", help="Demo case name"),
    download_baselines: bool = typer.Option(True, "--baselines/--no-baselines", help="Download triage baselines"),
    port: int = typer.Option(4508, "--port", "-p", help="HTTP port for config"),
):
    """Run connectivity test, download baselines, create demo case, print config.

    This is the fastest way to get started with DFIR-Nexus:

        nexus init
        nexus serve --http
    """
    typer.echo("\n=== DFIR-Nexus Quickstart ===\n")

    # 1. Connectivity test
    typer.echo("[1/4] Checking environment...")
    _check_dependencies()

    # 2. Set examiner
    from nexus.config import settings
    from nexus.audit import resolve_examiner

    if examiner:
        os.environ["NEXUS_EXAMINER"] = examiner
    elif not settings.examiner:
        default = resolve_examiner()
        os.environ["NEXUS_EXAMINER"] = default
        typer.echo(f"  Examiner: {default} (from OS username)")

    typer.echo(f"  Examiner: {resolve_examiner()}")

    # 3. Download baselines
    if download_baselines:
        typer.echo("\n[2/4] Checking triage baselines...")
        triage_dir = settings.data_root / "triage"
        has_known_good = (triage_dir / "known_good.db").exists()
        has_context = (triage_dir / "context.db").exists()
        if has_known_good and has_context:
            size_mb = sum(f.stat().st_size for f in [triage_dir / "known_good.db", triage_dir / "context.db"] if f.exists()) / (1024 * 1024)
            typer.echo(f"  Baselines already present ({size_mb:.0f} MB)")
        else:
            typer.echo("  Baselines not found. To download:")
            typer.echo("    From your LLM client, call: triage_download()")
            typer.echo("    Or via CLI later: run the server and call the tool")

    # 4. Check RAG index
    typer.echo("\n[3/4] Checking RAG index...")
    rag_dir = settings.data_root / "rag"
    if (rag_dir / "chroma").exists():
        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(rag_dir / "chroma"))
            count = client.get_collection("ir_knowledge").count()
            typer.echo(f"  RAG index ready ({count:,} records)")
        except Exception:
            typer.echo("  RAG index present but couldn't verify")
    else:
        typer.echo("  RAG index not found. To download:")
        typer.echo("    From LLM client: forensic_rag_download()")

    # 5. Print config
    typer.echo("\n[4/4] LLM Client Configuration")
    typer.echo(f"\n  Start the server: nexus serve --http --port {port}\n")
    config = {
        "mcpServers": {
            "dfir-nexus": {
                "type": "streamable-http",
                "url": f"http://127.0.0.1:{port}/mcp",
            }
        }
    }
    config_path = Path("nexus-config.json")
    config_path.write_text(json.dumps(config, indent=2))
    typer.echo(f"  Config written to: {config_path.resolve()}")
    typer.echo()
    typer.echo("  For Claude Code, add to .mcp.json or ~/.claude/settings.json:")
    typer.echo(json.dumps(config, indent=2))
    typer.echo()
    typer.echo("  Next steps from your LLM client:")
    typer.echo(f"    1. case_init(\"{case_name}\")")
    typer.echo("    2. evidence_register(path=\"...\")")
    typer.echo("    3. forensic_rag_search(query=\"investigation guidance\")")
    typer.echo("    4. run_command(...) or run_windows_command(...)")
    typer.echo("    5. record_finding(title=\"...\", artifacts=[...])")
    typer.echo()

    typer.echo("=== Quickstart complete ===")


def _check_dependencies():
    """Check optional dependencies and report status."""
    results = []
    for mod_name, pip_name in [
        ("chromadb", "dfir-nexus[rag]"),
        ("opensearchpy", "dfir-nexus[opensearch]"),
        ("pycti", "dfir-nexus[opencti]"),
    ]:
        try:
            __import__(mod_name)
            results.append((mod_name, True, ""))
        except ImportError:
            results.append((mod_name, False, f"pip install {pip_name}"))

    for name, ok, hint in results:
        status = "+" if ok else "-"
        msg = f"    [{status}] {name}"
        if not ok:
            msg += f"  ({hint})"
        typer.echo(msg)
