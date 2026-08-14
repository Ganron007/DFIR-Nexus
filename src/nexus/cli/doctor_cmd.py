"""nexus doctor — honest found/missing for extras, indexes, tools, TI keys."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import typer


def _have(mod: str) -> bool:
    return importlib.util.find_spec(mod) is not None


def _key_set(name: str) -> bool:
    return bool(os.environ.get(name, "").strip())


def doctor() -> None:
    """Print found/missing extras, RAG/triage, catalog binaries, optional TI keys."""
    from nexus import __version__
    from nexus.ingest.registry import get_registry

    rows: list[tuple[str, bool, str]] = []
    golden_fail = False

    py = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    rows.append(("python>=3.12", sys.version_info >= (3, 12), py))

    extras = [
        ("extra.evtx (python-evtx)", "Evtx"),
        ("extra.python-registry", "Registry"),
        ("extra.regipy", "regipy"),
        ("extra.pylnk3", "pylnk3"),
        ("extra.chromadb (rag)", "chromadb"),
        ("extra.pysigma (detection)", "sigma"),
    ]
    # Golden-required parsers: EVTX and LNK are single-parser; registry hives
    # are satisfied by python-registry OR regipy. chromadb (RAG) and pysigma
    # (detection) are optional for the golden path.
    golden_required = {"Evtx", "pylnk3"}
    have: dict[str, bool] = {}
    for label, mod in extras:
        ok = _have(mod)
        have[mod] = ok
        if ok:
            rows.append((label, True, "installed"))
        elif mod in golden_required:
            rows.append((label, False, "missing extra"))
        else:
            note = "missing (optional)"
            if mod in {"Registry", "regipy"}:
                note = "missing (need one of python-registry / regipy)"
            rows.append((label, True, note))

    if not have.get("Evtx"):
        golden_fail = True
    if not have.get("pylnk3"):
        golden_fail = True
    if not (have.get("Registry") or have.get("regipy")):
        golden_fail = True
        rows.append(("registry parser", False, "need python-registry OR regipy"))

    rag = Path.home() / ".nexus" / "data" / "rag" / "chroma"
    triage = Path.home() / ".nexus" / "data" / "triage"
    rows.append(("rag index", rag.is_dir(), str(rag)))
    rows.append(("triage baseline", triage.is_dir() and any(triage.iterdir()), str(triage)))

    try:
        from nexus.app import create_server
        server = create_server()
        n = len(server._tool_manager._tools)  # type: ignore[union-attr]
        rows.append((f"mcp tools ({sys.platform})", n > 0, str(n)))
    except Exception as exc:
        rows.append(("mcp create_server", False, str(exc)))
        golden_fail = True

    reg = get_registry()
    rows.append(("importer sources", True, str(len(reg.all_sources()))))

    if sys.platform == "win32":
        from nexus.tools.windows import _WIN_CATALOG, _find_binary

        found = 0
        missing_core: list[str] = []
        core = {
            "evtxecmd", "pecmd", "recmd", "lecmd", "mftecmd",
            "amcacheparser", "hayabusa", "suzaku",
            "bmc-tools", "bitsparser",
        }
        for key, info in sorted(_WIN_CATALOG.items()):
            hit = _find_binary(info["name"]) or _find_binary(key)
            optional = key in {
                "kape", "yara", "winpmem", "dumpit", "moneta",
                "hollows_hunter", "densityscout", "get_injectedthreadex", "mactime",
                "kstrike", "thumbcache_viewer", "logfileparser",
            }
            if hit:
                found += 1
                rows.append((f"tool.{info['name']}", True, hit))
            else:
                rows.append((f"tool.{info['name']}", optional, "MISSING" + (" (optional)" if optional else "")))
                if key in core:
                    missing_core.append(info["name"])
        rows.append(("windows catalog present", found > 0, f"{found}/{len(_WIN_CATALOG)}"))
        if missing_core:
            golden_fail = True
            rows.append(("windows core tools", False, "missing: " + ", ".join(missing_core)))
    else:
        rows.append(("windows catalog", True, "OS-GATE — not Windows"))
        try:
            from nexus.tools.sift import _find_binary as _sift_find
        except Exception as exc:  # noqa: BLE001
            rows.append(("sift resolver", False, str(exc)))
            golden_fail = True
        else:
            for name in ("vol", "fls", "mactime"):
                hit = _sift_find(name)
                rows.append((f"sift.{name}", bool(hit), hit or "MISSING — SIFT/apt"))
                if not hit:
                    golden_fail = True
            for name in ("esedbexport", "bmc-tools.py", "BitsParser.py", "KStrike.py"):
                hit = _sift_find(name)
                rows.append((
                    f"sift.{name}",
                    True,
                    hit or "MISSING (optional portable — bash tools/fetch-linux-tools.sh)",
                ))

    for env_name in (
        "NEXUS_TI_ABUSECH_API_KEY",
        "NEXUS_TI_OTX_API_KEY",
        "NEXUS_TI_SHODAN_API_KEY",
        "NEXUS_TI_VIRUSTOTAL_API_KEY",
        "NEXUS_LLM_API_KEY",
    ):
        set_ = _key_set(env_name)
        rows.append((env_name, True, "set" if set_ else "unset (optional)"))

    typer.echo(f"nexus doctor  v{__version__}  {sys.platform}")
    for name, ok, detail in rows:
        mark = "ok" if ok else "FAIL"
        typer.echo(f"  [{mark}] {name}: {detail}")

    # Parked / gated surfaces (informational — not golden-path failures).
    typer.echo("parked / gated surfaces (not required to ship):")
    typer.echo("  [park] OpenCTI (11 tools): parked — needs OPENCTI_URL/TOKEN; org CTI graph, not findings search")
    typer.echo("  [gate] VR live: VR-GATE — mock works offline (NEXUS_VR_USE_MOCK=1); live optional via NEXUS_VR_ENDPOINT")
    typer.echo("  [park] analysis extras (translate_query/asset-graph/KG/dynamic-tables): parked — superseded by N4 query pack")

    if golden_fail:
        typer.echo("golden-path: FAIL")
        raise typer.Exit(1)
    typer.echo("golden-path: ok")
