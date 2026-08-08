"""Service management — status, start, stop, restart MCP services.

Supports named services with configurable startup commands.
"""

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import typer

app = typer.Typer(help="Manage MCP services")

_SERVICE_REGISTRY: dict[str, dict] = {
    "nexus": {
        "type": "MCP",
        "description": "Main DFIR-Nexus MCP server",
        "command": [sys.executable, "-m", "nexus", "serve"],
        "http_support": True,
    },
}


def _find_pidfile(name: str) -> Path:
    return Path.home() / ".nexus" / f"{name}.pid"


def _list_services() -> dict[str, dict]:
    """Return service registry, extending from config file if present."""
    services = dict(_SERVICE_REGISTRY)
    config_path = Path.home() / ".nexus" / "services.json"
    if config_path.exists():
        try:
            extra = json.loads(config_path.read_text())
            services.update(extra)
        except (OSError, json.JSONDecodeError):
            pass
    return services


@app.command()
def status(
    name: str = typer.Argument("", help="Service name (omit for all)"),
):
    """Check status of MCP services."""
    services = _list_services()
    if name:
        services = {k: v for k, v in services.items() if k == name}

    for svc_name, info in sorted(services.items()):
        pidfile = _find_pidfile(svc_name)
        running = False
        pid = None
        if pidfile.exists():
            try:
                pid = int(pidfile.read_text().strip())
                os.kill(pid, 0)
                running = True
            except (OSError, ValueError):
                pidfile.unlink(missing_ok=True)

        status_str = "RUNNING" if running else "STOPPED"
        pid_str = str(pid) if pid else "-"
        typer.echo(f"  {svc_name:20s} [{status_str:8s}]  PID={pid_str:>6s}  {info.get('type', '?')}  {info.get('description', '')}")


@app.command()
def start(
    name: str = typer.Argument("nexus", help="Service to start"),
    http: bool = typer.Option(False, "--http", help="Start in HTTP mode"),
    port: int = typer.Option(4508, "--port", "-p", help="HTTP port"),
):
    """Start a service as a background process."""
    services = _list_services()
    if name not in services:
        typer.echo(f"Unknown service: {name}. Available: {', '.join(sorted(services.keys()))}")
        raise typer.Exit(1)

    pidfile = _find_pidfile(name)
    if pidfile.exists():
        try:
            pid = int(pidfile.read_text().strip())
            os.kill(pid, 0)
            typer.echo(f"{name} is already running (PID: {pid})")
            return
        except (OSError, ValueError):
            pidfile.unlink(missing_ok=True)

    info = services[name]
    args = list(info.get("command", [sys.executable, "-m", "nexus", "serve"]))
    if info.get("http_support") and http:
        args.extend(["--http", "--port", str(port)])

    # Allow custom args via env var
    extra_args = os.environ.get(f"NEXUS_{name.upper()}_ARGS", "").strip()
    if extra_args:
        args.extend(extra_args.split())

    typer.echo(f"Starting {name}...")
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pidfile.parent.mkdir(parents=True, exist_ok=True)
        pidfile.write_text(str(proc.pid))
        typer.echo(f"{name} started (PID: {proc.pid})")
    except FileNotFoundError:
        typer.echo(f"Command not found: {args[0]}", err=True)
        raise typer.Exit(1) from None


@app.command()
def stop(
    name: str = typer.Argument("nexus", help="Service to stop"),
):
    """Stop a running service."""
    services = _list_services()
    if name not in services:
        typer.echo(f"Unknown service: {name}")
        raise typer.Exit(1)

    pidfile = _find_pidfile(name)
    if not pidfile.exists():
        typer.echo(f"{name} is not running")
        return

    try:
        pid = int(pidfile.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        pidfile.unlink(missing_ok=True)
        typer.echo(f"{name} stopped (PID: {pid})")
    except ProcessLookupError:
        typer.echo(f"{name} already exited")
        pidfile.unlink(missing_ok=True)
    except (OSError, ValueError) as e:
        typer.echo(f"Error stopping {name}: {e}")
        pidfile.unlink(missing_ok=True)


@app.command()
def restart(
    name: str = typer.Argument("nexus", help="Service to restart"),
    http: bool = typer.Option(False, "--http", help="Restart in HTTP mode"),
    port: int = typer.Option(4508, "--port", "-p", help="HTTP port"),
):
    """Restart a service."""
    stop(name)
    start(name, http, port)
