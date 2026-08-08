"""Quickstart — one-command onboarding for new DFIR-Nexus users.

Runs connectivity test, creates the case, registers + hashes evidence,
checks baselines, and prints the LLM client config snippet.
"""

import hashlib
import json
import os
from pathlib import Path

import typer

app = typer.Typer(help="Quickstart — one-command onboarding")


@app.command()
def init(
    case_name: str = typer.Argument("", help="Case name (default: Demo Investigation)"),
    examiner: str = typer.Option("", "--examiner", "-e", help="Examiner name"),
    case: str = typer.Option("", "--case", help="Demo case name (alternative to the positional argument)"),
    evidence: list[str] = typer.Option([], "--evidence", help="Evidence file to register (repeatable)"),
    download_baselines: bool = typer.Option(True, "--baselines/--no-baselines", help="Check triage baselines"),
    port: int = typer.Option(4508, "--port", "-p", help="HTTP port for config"),
):
    """Create a case, hash evidence, check baselines, print client config.

    This is the fastest way to get started with DFIR-Nexus:

        nexus init "Case Name" --evidence /path/to/disk.raw
        nexus serve --http
    """
    typer.echo("\n=== DFIR-Nexus Quickstart ===\n")

    # 1. Connectivity test
    typer.echo("[1/5] Checking environment...")
    _check_dependencies()

    # 2. Set examiner
    from nexus.audit import resolve_examiner
    from nexus.config import settings

    if examiner:
        os.environ["NEXUS_EXAMINER"] = examiner
        config_path = Path.home() / ".nexus" / "config.yaml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        import yaml
        existing = {}
        if config_path.exists():
            try:
                existing = yaml.safe_load(config_path.read_text()) or {}
            except Exception:
                existing = {}
        config_path.write_text(yaml.dump({**existing, "examiner": examiner}, default_flow_style=False))
    elif not settings.examiner:
        default = resolve_examiner()
        os.environ["NEXUS_EXAMINER"] = default
        typer.echo(f"  Examiner: {default} (from OS username)")

    typer.echo(f"  Examiner: {resolve_examiner()}")

    # 3. Create the case + register evidence
    name = case_name or case or "Demo Investigation"
    typer.echo(f"\n[2/5] Creating case: {name}")
    from nexus.case import CaseManager
    db_path = settings.cases_root / "cases.db"
    mgr = CaseManager(db_path)
    try:
        new_case = mgr.create_case(name=name, description=f"Case: {name}", created_by=resolve_examiner())
    except ValueError as e:
        typer.echo(f"  Error: {e}", err=True)
        raise typer.Exit(1) from None
    typer.echo(f"  Case created (ID: {new_case.id})")
    active_file = Path.home() / ".nexus" / "active_case"
    active_file.parent.mkdir(parents=True, exist_ok=True)
    active_file.write_text(new_case.id)

    for ev_path in evidence:
        fpath = Path(ev_path)
        if not fpath.exists():
            typer.echo(f"  Evidence not found, skipping: {ev_path}", err=True)
            continue
        sha256 = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()
        mgr.add_evidence(
            case_id=new_case.id,
            name=fpath.name,
            description="Registered by nexus init",
            file_path=str(fpath.resolve()),
            file_hash_sha256=digest,
        )
        typer.echo(f"  Evidence registered: {fpath.name} (SHA-256: {digest[:16]}…)")
    mgr.close()

    # 4. Download baselines
    if download_baselines:
        typer.echo("\n[3/5] Checking triage baselines...")
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

    # 5. Check RAG index
    typer.echo("\n[4/5] Checking RAG index...")
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

    # 6. Print config
    typer.echo("\n[5/5] LLM Client Configuration")
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
    typer.echo(f"    1. case_activate(\"{new_case.id}\")")
    typer.echo("    2. evidence_register(path=\"...\")  (or already registered above)")
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
