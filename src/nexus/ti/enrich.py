"""Core TI enrichment for LangGraph agents and analysis helpers."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
from typing import Any, Protocol, runtime_checkable

from nexus.ti.router import TIRouter, create_default_router

log = logging.getLogger(__name__)


try:
    # Prefer the full ingest schema if the rest of the framework is installed.
    from nexus.ingest.schemas import Artifact as _RealArtifact
except Exception:  # pragma: no cover - standalone TI module has no ingest layer
    _RealArtifact = None  # type: ignore[assignment,misc]


@runtime_checkable
class _Artifact(Protocol):
    """Duck-typed artifact used by the enrich helpers."""

    iocs: list[str]
    source_ip: str | None
    dest_ip: str | None
    file_hash_md5: str | None
    file_hash_sha1: str | None
    file_hash_sha256: str | None


def _run_async(coro: Any) -> Any:
    """Run coroutine from sync code (safe under pytest-asyncio too)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def collect_iocs(artifacts: list[_Artifact], *, max_iocs: int = 5) -> list[str]:
    """Collect unique IOC strings from artifact fields (core loop input)."""
    seen: set[str] = set()
    out: list[str] = []

    def add(value: str | None) -> None:
        if len(out) >= max_iocs:
            return
        v = (value or "").strip()
        if v and v not in seen:
            seen.add(v)
            out.append(v)

    for artifact in artifacts:
        for ioc in artifact.iocs:
            add(ioc)
        add(artifact.source_ip)
        add(artifact.dest_ip)
        add(artifact.file_hash_md5)
        add(artifact.file_hash_sha1)
        add(artifact.file_hash_sha256)
        if len(out) >= max_iocs:
            break
    return out[:max_iocs]


async def enrich_iocs_async(
    iocs: list[str],
    router: TIRouter,
) -> list[dict[str, Any]]:
    """Run core-tier ``ti_lookup`` for each IOC (never includes optional providers)."""
    return [await router.lookup(ioc) for ioc in iocs]


def enrich_artifacts(
    artifacts: list[_Artifact],
    *,
    max_iocs: int = 5,
    router: TIRouter | None = None,
) -> dict[str, Any]:
    """Sync helper for LangGraph agents — core TI only."""
    ti_router = router or create_default_router()
    iocs = collect_iocs(artifacts, max_iocs=max_iocs)
    if not iocs:
        return {
            "iocs": [],
            "lookups": [],
            "malicious_count": 0,
            "summary": "no IOCs to enrich",
        }

    async def _run() -> tuple[list[dict[str, Any]], int]:
        lookups = await enrich_iocs_async(iocs, ti_router)
        malicious = sum(int(p.get("malicious_count", 0) or 0) for p in lookups)
        return lookups, malicious

    lookups, malicious_count = _run_async(_run())
    return {
        "iocs": iocs,
        "lookups": lookups,
        "malicious_count": malicious_count,
        "summary": f"{len(iocs)} IOC(s), {malicious_count} malicious hit(s) via core TI",
    }
