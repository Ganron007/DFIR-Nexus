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


def resolve_health_url(cli_url: str = "") -> str | None:
    """Default loopback /health. ``skip`` / empty-after-env disables the probe."""
    raw = (cli_url or "").strip()
    if raw.lower() in {"skip", "off", "none"}:
        return None
    if raw:
        return raw.rstrip("/")
    env = os.environ.get("NEXUS_HEALTH_URL", "").strip()
    if env.lower() in {"skip", "off", "none"}:
        return None
    if env:
        return env.rstrip("/")
    from nexus.config import settings
    port = getattr(settings, "gateway_port", 4508) or 4508
    return f"http://127.0.0.1:{port}"


def probe_http_health(
    base_url: str, timeout: float = 2.0
) -> tuple[bool, bool, str]:
    """GET ``/health``. Returns ``(print_ok, fail_golden, detail)``.

    Connection refused is not a golden-path failure (serve may be down).
    A listening server that returns a non-ok body is a golden failure.
    """
    import httpx

    url = base_url.rstrip("/")
    if not url.endswith("/health"):
        url = f"{url}/health"
    try:
        resp = httpx.get(url, timeout=timeout)
    except httpx.ConnectError:
        return True, False, f"not listening (optional — nexus serve --http) [{url}]"
    except httpx.TimeoutException:
        return True, False, f"timeout (optional — nexus serve --http) [{url}]"
    except httpx.HTTPError as exc:
        return True, False, f"unreachable ({exc.__class__.__name__}) [{url}]"

    if resp.status_code != 200:
        return False, True, f"HTTP {resp.status_code} [{url}]"
    try:
        body = resp.json()
    except ValueError:
        return False, True, f"200 but non-JSON [{url}]"
    status = str(body.get("status") or "")
    service = str(body.get("service") or "")
    if status.lower() != "ok":
        return False, True, f"200 unexpected status={status!r} [{url}]"
    return True, False, f"200 {service or 'dfir-nexus'} [{url}]"


def _environment_checks() -> list[tuple[str, bool, str]]:
    """Case-start readiness: ES, LLM, RAG embedder, SIFT reachability.

    These are the Phase 5 preflight checks (WIRING-PLAN.md). Each is
    informational here — the preflight gate command will enforce them.
    """
    import os

    rows: list[tuple[str, bool, str]] = []

    # Elasticsearch (N3 backend)
    es_url = (os.environ.get("NEXUS_ES_URL") or "").strip()
    if not es_url:
        rows.append(("elasticsearch (N3)", True, "NEXUS_ES_URL empty — CSV pack backend"))
    else:
        try:
            import httpx

            r = httpx.get(es_url.rstrip("/") + "/", timeout=5)
            if r.status_code == 200 and "version" in r.json():
                rows.append(("elasticsearch (N3)", True, f"{es_url} v{r.json()['version']['number']}"))
            else:
                rows.append(("elasticsearch (N3)", False, f"HTTP {r.status_code} at {es_url}"))
        except Exception as exc:  # noqa: BLE001
            rows.append(("elasticsearch (N3)", False, f"unreachable: {exc}"))

    # LLM (configured + optionally reachable)
    llm_base = (os.environ.get("NEXUS_LLM_BASE_URL") or "").strip()
    llm_model = (os.environ.get("NEXUS_LLM_MODEL") or "").strip()
    llm_key = _key_set("NEXUS_LLM_API_KEY")
    if llm_base and llm_model:
        rows.append(("llm config", True, f"model={llm_model} base={llm_base} key={'set' if llm_key else 'unset'}"))
    else:
        rows.append(("llm config", True, "unset — heuristic scribe fallback active"))

    # RAG index + embedding model
    try:
        from nexus.tools.rag import _get_index_dir, resolve_embedding_source

        src = resolve_embedding_source()
        idx_dir = _get_index_dir()
        chroma = idx_dir / "chroma"
        rows.append((
            "rag index",
            chroma.is_dir(),
            f"{idx_dir} ({'present' if chroma.is_dir() else 'missing — nexus data rag-download'})",
        ))
        rows.append((
            "embedding model",
            src["source"] in ("hf_hub_cache", "explicit_dir"),
            f"{src['model_id']} via {src['source']}" + ("" if src["local_files_only"] else " (will download on first use)"),
        ))
    except Exception as exc:  # noqa: BLE001
        rows.append(("rag/embedder", False, str(exc)))

    # SIFT reachability (fast probe; kill-switch aware)
    try:
        from nexus.case.sift_sync import sift_reachable

        ok, msg = sift_reachable()
        rows.append(("sift ssh", ok, msg if msg else ("reachable" if ok else "unreachable")))
    except Exception as exc:  # noqa: BLE001
        rows.append(("sift ssh", False, str(exc)[:120]))

    return rows


def doctor(
    health_url: str = typer.Option(
        "",
        "--health-url",
        help=(
            "Probe HTTP /health. Default: NEXUS_HEALTH_URL or "
            "http://127.0.0.1:4508. Pass skip to disable."
        ),
    ),
    rag_preflight: bool = typer.Option(
        False,
        "--rag",
        help="Run full RAG preflight: load embedding model, open Chroma, test query.",
    ),
) -> None:
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

    # ── Environment gate checks (ES / LLM / RAG embedder / SIFT) ──
    rows.extend(_environment_checks())

    probe_url = resolve_health_url(health_url)
    if probe_url is None:
        rows.append(("http /health", True, "skipped"))
    else:
        ok, fail, detail = probe_http_health(probe_url)
        rows.append(("http /health", ok, detail))
        if fail:
            golden_fail = True

    typer.echo(f"nexus doctor  v{__version__}  {sys.platform}")
    for name, ok, detail in rows:
        mark = "ok" if ok else "FAIL"
        typer.echo(f"  [{mark}] {name}: {detail}")

    # ── RAG preflight (WP 3.13) ──
    if rag_preflight:
        typer.echo("\nRAG preflight (--rag):")
        try:
            from nexus.tools.rag_preflight import rag_preflight as _pf
            result = _pf()
            if result["ready"]:
                typer.echo(f"  [ok] embedding model: {result.get('embedding_model', '?')}")
                typer.echo(f"  [ok] model source: {result.get('model_source', '?')}")
                typer.echo(f"  [ok] document count: {result.get('document_count', 0):,}")
                typer.echo(f"  [ok] source count: {result.get('source_count', 0)}")
                typer.echo("  [ok] test query: returned results")
                typer.echo("  RAG preflight: PASS")
            else:
                for err in result.get("errors", [result.get("error", "unknown")]):
                    if err:
                        typer.echo(f"  [FAIL] {err}")
                typer.echo(f"  test query returned: {result.get('test_query_returned', False)}")
                typer.echo("  RAG preflight: FAIL")
                golden_fail = True
        except Exception as exc:
            typer.echo(f"  [FAIL] RAG preflight crashed: {exc}")
            golden_fail = True

    # Parked / gated surfaces (informational — not golden-path failures).
    typer.echo("parked / gated surfaces (not required to ship):")
    typer.echo("  [park] OpenCTI (11 tools): parked — needs OPENCTI_URL/TOKEN; org CTI graph, not findings search")
    typer.echo("  [gate] VR live: VR-GATE — mock offline; live via NEXUS_VR_MCP_URL + NEXUS_VR_MCP_API_KEY (not gRPC :8001)")
    typer.echo("  [park] analysis extras (translate_query/asset-graph/KG/dynamic-tables): parked — superseded by N4 query pack")
    try:
        from nexus.collect.paths import (
            avml_exe,
            chainsaw_exe,
            chainsaw_sigma,
            hayabusa_exe,
            kansa_ps1,
            kape_exe,
            orc_exe,
            persistencesniper_psm1,
            suzaku_exe,
            sysinternals_exe,
            uac_home,
            winpmem_exe,
        )
        from nexus.collect.vr import vr_live_status

        kape = kape_exe()
        typer.echo(f"  [info] collect kape: {kape or 'MISSING — Tools/windows/kape'}")
        typer.echo(
            f"  [info] collect kansa.ps1: {kansa_ps1() or 'not found — builtin volatile modules used'}"
        )
        typer.echo(
            f"  [info] collect dfir-orc: {orc_exe() or 'MISSING — Tools/windows/orc (run tools/fetch-ir-collect.ps1)'}"
        )
        typer.echo(f"  [info] collect uac: {uac_home() or 'not found — builtin POSIX volatile used'}")
        typer.echo(f"  [info] N2 hayabusa: {hayabusa_exe() or 'MISSING'}")
        typer.echo(f"  [info] N2 suzaku: {suzaku_exe() or 'MISSING'}")
        typer.echo(f"  [info] N2 chainsaw: {chainsaw_exe() or 'MISSING'}")
        typer.echo(f"  [info] N2 chainsaw sigma: {chainsaw_sigma() or 'MISSING — sparse clone SigmaHQ rules/'}")
        typer.echo(f"  [info] collect autorunsc: {sysinternals_exe('autorunsc') or 'MISSING'}")
        typer.echo(f"  [info] collect winpmem: {winpmem_exe() or 'MISSING'}")
        typer.echo(f"  [info] collect avml: {avml_exe() or 'MISSING'}")
        typer.echo(f"  [info] collect persistencesniper: {persistencesniper_psm1() or 'MISSING'}")
        live, reason = vr_live_status()
        mark = "ok" if live else "skip"
        typer.echo(f"  [{mark}] collect velociraptor live: {live} — {reason}")
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"  [info] collect inventory: {exc}")

    if golden_fail:
        typer.echo("golden-path: FAIL")
        raise typer.Exit(1)
    typer.echo("golden-path: ok")
