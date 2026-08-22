"""Velociraptor Stage 0 — live hunts against an enrolled client.

Mock / loopback-without-key is skipped (not a live collect). CADRE lab: set
NEXUS_VR_MCP_URL + NEXUS_VR_MCP_API_KEY (HTTP :8002). Do not point
NEXUS_VR_ENDPOINT at gRPC :8001. GUI HTTP Query is optional and CSRF-gated.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from nexus.collect.types import CollectorStep, HostSpec
from nexus.vr.constants import (
    ENV_VR_MCP_URL,
    default_api_key,
    default_mcp_api_key,
    default_vr_endpoint,
    vr_mock_enabled,
)

_SAFE_ARTIFACT = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")
_SAFE_SOURCE = re.compile(r"^[A-Za-z][A-Za-z0-9_./]*$")
_CLIENT_ID = re.compile(r"^C\.[A-Za-z0-9]+$")
_FLOW_ID = re.compile(r"^F\.[A-Za-z0-9]+$")
_DONE_STATES = frozenset({"FINISHED", "ERROR", "FAILED", "CANCELLED"})

# Stage 0 collect calls enrollment proof + minimum IR triage only.
# Heavier CADRE.Hunts.* packs stay on the VR server for an explicit later hunt.
WINDOWS_HUNTS = (
    "Generic.Client.Info",
    "CADRE.Hunts.IRTriage",
)
LINUX_HUNTS = (
    "Generic.Client.Info",
    "CADRE.Hunts.LinuxIRTriage",
)


def collect_client_vql(artifact: str, client_id: str, *, timeout: int = 1800) -> str:
    """Start a collection on the enrolled client (Velociraptor 0.76+ function).

    ``collect_client`` is a VQL *function*, not a plugin. ``SELECT * FROM
    collect_client(...)`` fails on 0.76 with "Plugin collect_client not found".
    """
    if not _SAFE_ARTIFACT.match(artifact):
        raise ValueError(f"unsafe artifact name: {artifact!r}")
    if not _CLIENT_ID.match(client_id):
        raise ValueError(f"unsafe client_id: {client_id!r}")
    wait_s = max(30, int(timeout))
    return (
        f'SELECT collect_client(client_id="{client_id}", '
        f'artifacts="{artifact}", timeout={wait_s}, urgent=TRUE) '
        f"AS Collection FROM scope()"
    )


def flow_status_vql(client_id: str, flow_id: str) -> str:
    if not _CLIENT_ID.match(client_id):
        raise ValueError(f"unsafe client_id: {client_id!r}")
    if not _FLOW_ID.match(flow_id):
        raise ValueError(f"unsafe flow_id: {flow_id!r}")
    return (
        f'SELECT session_id, state, total_collected_rows, artifacts_with_results '
        f'FROM flows(client_id="{client_id}", flow_id="{flow_id}")'
    )


def enumerate_flow_vql(client_id: str, flow_id: str) -> str:
    if not _CLIENT_ID.match(client_id):
        raise ValueError(f"unsafe client_id: {client_id!r}")
    if not _FLOW_ID.match(flow_id):
        raise ValueError(f"unsafe flow_id: {flow_id!r}")
    return (
        f'SELECT Type, Data FROM enumerate_flow('
        f'client_id="{client_id}", flow_id="{flow_id}")'
    )


def flow_results_vql(client_id: str, flow_id: str, source: str) -> str:
    if not _CLIENT_ID.match(client_id):
        raise ValueError(f"unsafe client_id: {client_id!r}")
    if not _FLOW_ID.match(flow_id):
        raise ValueError(f"unsafe flow_id: {flow_id!r}")
    if not _SAFE_SOURCE.match(source) or ".." in source:
        raise ValueError(f"unsafe artifact source: {source!r}")
    return (
        f'SELECT * FROM flow_results(client_id="{client_id}", '
        f'flow_id="{flow_id}", artifact="{source}")'
    )


def _flow_id_from_rows(rows: list[dict]) -> str:
    for row in rows:
        if not isinstance(row, dict):
            continue
        coll = row.get("Collection")
        if isinstance(coll, dict):
            fid = str(coll.get("flow_id") or "")
            if _FLOW_ID.match(fid):
                return fid
        fid = str(row.get("flow_id") or row.get("session_id") or "")
        if _FLOW_ID.match(fid):
            return fid
        for value in row.values():
            if isinstance(value, dict):
                fid = str(value.get("flow_id") or "")
                if _FLOW_ID.match(fid):
                    return fid
    return ""


def _source_from_vfs(path: str) -> str:
    text = (path or "").replace("\\", "/")
    match = re.search(
        r"/artifacts/(.+)/F\.[A-Za-z0-9]+/([^/]+)\.json$",
        text,
    )
    if not match:
        return ""
    name = f"{match.group(1)}/{match.group(2)}"
    if ".." in name or not _SAFE_SOURCE.match(name):
        return ""
    return name


def _str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value:
        return [value]
    return []


def _mcp_configured() -> bool:
    url = (os.environ.get(ENV_VR_MCP_URL) or "").strip()
    return bool(url and default_mcp_api_key())


def vr_live_status() -> tuple[bool, str]:
    """Return (live, reason). Live means a real server that answers a VQL ping."""
    if vr_mock_enabled():
        return False, "NEXUS_VR_USE_MOCK is set — not a live Velociraptor"
    endpoint = default_vr_endpoint()
    key = default_api_key()
    loopback = any(tok in endpoint.lower() for tok in ("127.0.0.1", "localhost"))
    # MCP :8002 is the CADRE live path. Default NEXUS_VR_ENDPOINT is loopback gRPC
    # :8001 — do not treat that as "not live" when MCP URL+key are set.
    if not _mcp_configured() and loopback and not key:
        return False, (
            f"default endpoint {endpoint} has no API key (mock path); "
            "set NEXUS_VR_MCP_URL + NEXUS_VR_MCP_API_KEY"
        )
    try:
        from nexus.integration.vql_runner import VQLQuerySpec
        from nexus.vr.service import VRService

        svc = VRService(force_mock=False)
        if svc.use_mock:
            return False, (
                "Velociraptor client is mock — set NEXUS_VR_MCP_URL and "
                "NEXUS_VR_MCP_API_KEY (or NEXUS_VR_ENDPOINT + NEXUS_VR_API_KEY)"
            )
        health = svc.health()
        mcp = health.get("mcp_health")
        if isinstance(mcp, dict) and mcp.get("ok") is False:
            return False, f"VR MCP unhealthy: {mcp}"
        ping = svc._client.query(VQLQuerySpec(name="ping", vql="SELECT 1 AS ok", timeout_seconds=8))
        if ping.error:
            return False, f"velociraptor query failed: {ping.error}"
        where = health.get("mcp_url") or health.get("endpoint")
        return True, f"live client={health.get('client_type')} endpoint={where}"
    except Exception as exc:  # noqa: BLE001
        return False, f"velociraptor unreachable: {exc}"


def vr_step(*, wanted: bool) -> CollectorStep:
    """Dry-run / import helper — probe only."""
    if not wanted:
        return CollectorStep("velociraptor", "skipped", "disabled")
    live, reason = vr_live_status()
    if not live:
        return CollectorStep(
            "velociraptor",
            "skipped",
            reason,
            detail={"note": "live hunts need NEXUS_VR_MCP_URL + NEXUS_VR_MCP_API_KEY"},
        )
    return CollectorStep(
        "velociraptor",
        "planned",
        reason,
        detail={"live": True, "reason": reason, "hunts": list(WINDOWS_HUNTS)},
    )


def run_vr(
    spec: HostSpec,
    pack_host: Path,
    *,
    wanted: bool,
    dry_run: bool,
    client_id: str = "",
    timeout: int = 1800,
) -> CollectorStep:
    if not wanted:
        return CollectorStep("velociraptor", "skipped", "disabled")
    live, reason = vr_live_status()
    out = pack_host / "velociraptor"
    hunts = WINDOWS_HUNTS if spec.os == "windows" else LINUX_HUNTS
    detail: dict = {"reason": reason, "hunts": list(hunts), "os": spec.os}
    if not live:
        return CollectorStep("velociraptor", "skipped", reason, path=str(out), detail=detail)
    if dry_run:
        return CollectorStep("velociraptor", "planned", reason, path=str(out), detail=detail)

    from nexus.vr.service import VRService

    svc = VRService(force_mock=False)
    if svc.use_mock:
        return CollectorStep(
            "velociraptor",
            "skipped",
            "refusing mock Velociraptor during a live collect",
            path=str(out),
            detail=detail,
        )
    cid = (client_id or "").strip() or _match_client(svc, spec)
    if cid and not _CLIENT_ID.match(cid):
        return CollectorStep(
            "velociraptor",
            "skipped",
            f"client id {cid!r} is not a Velociraptor id (C.<hex>); pass --vr-client-id",
            path=str(out),
            detail=detail,
        )
    if not cid:
        return CollectorStep(
            "velociraptor",
            "skipped",
            "no enrolled VR client matching this host "
            f"(hostname={spec.hostname!r} address={spec.address!r}); "
            "enroll the agent or pass --vr-client-id",
            path=str(out),
            detail=detail,
        )
    detail["client_id"] = cid
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    any_ok = False
    for artifact in hunts:
        if not _SAFE_ARTIFACT.match(artifact):
            continue
        row = _collect_artifact(svc, artifact, cid, timeout=timeout)
        results.append({k: v for k, v in row.items() if k != "all_rows"})
        (out / f"{artifact.replace('.', '_')}.json").write_text(
            json.dumps({k: v for k, v in row.items() if k != "all_rows"}, indent=2, default=str),
            encoding="utf-8",
        )
        extra = row.get("all_rows") or []
        if extra:
            (out / f"{artifact.replace('.', '_')}.full.json").write_text(
                json.dumps(
                    {
                        "artifact": artifact,
                        "flow_id": row.get("flow_id"),
                        "state": row.get("state"),
                        "sources": row.get("sources"),
                        "row_count": len(extra),
                        "rows": extra,
                    },
                    indent=2,
                    default=str,
                ),
                encoding="utf-8",
            )
        if row.get("ok"):
            any_ok = True
            if artifact.endswith("IRTriage"):
                break
    (out / "hunts.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    if not any_ok:
        errs = "; ".join(str(r.get("error") or r.get("artifact")) for r in results[:4])
        return CollectorStep(
            "velociraptor",
            "failed",
            errs[:500] or "all hunts failed",
            path=str(out),
            detail=detail,
        )
    return CollectorStep("velociraptor", "ok", path=str(out), detail=detail)


def _ip_host(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    host, sep, port = text.rpartition(":")
    if sep and host and port.isdigit():
        return host
    return text


def _match_client(svc, spec: HostSpec) -> str:
    clients = _list_clients(svc)
    host = (spec.hostname or "").strip().lower()
    addr = (spec.address or "").strip().lower()
    for row in clients:
        cid = str(row.get("client_id") or "")
        if not _CLIENT_ID.match(cid):
            continue
        hn = str(row.get("hostname") or row.get("Hostname") or "").lower()
        fqdn = str(row.get("fqdn") or row.get("os_info.fqdn") or "").lower()
        ip = _ip_host(str(row.get("ip") or row.get("last_ip") or row.get("LastIP") or ""))
        if host and (host == hn or host in hn or host in fqdn or hn.startswith(host)):
            return cid
        if addr and addr not in {"localhost", "127.0.0.1", "::1"} and addr in {ip, hn, fqdn}:
            return cid
    if len(clients) == 1:
        cid = str(clients[0].get("client_id") or "")
        return cid if _CLIENT_ID.match(cid) else ""
    return ""


def _list_clients(svc) -> list[dict]:
    from nexus.integration.vql_runner import VQLQuerySpec

    queries = (
        "SELECT client_id, os_info.hostname AS hostname, os_info.fqdn AS fqdn, last_ip AS ip FROM clients()",
        "SELECT client_id, hostname, os, ip FROM clients()",
        "SELECT client_id, os_info.hostname AS hostname FROM clients() LIMIT 200",
    )
    for vql in queries:
        spec = VQLQuerySpec(name="clients", vql=vql, timeout_seconds=60)
        try:
            result = svc._client.query(spec)
        except Exception:  # noqa: BLE001
            continue
        if result.error or not result.rows:
            continue
        return list(result.rows)
    return []


def _query(svc, vql: str, timeout: int):
    from nexus.integration.vql_runner import VQLQuerySpec

    spec = VQLQuerySpec(name="vr", vql=vql, timeout_seconds=max(8, int(timeout)))
    return svc._client.query(spec)


def _collect_artifact(svc, artifact: str, client_id: str, *, timeout: int) -> dict:
    try:
        start_vql = collect_client_vql(artifact, client_id, timeout=timeout)
    except ValueError as exc:
        return {"artifact": artifact, "ok": False, "error": str(exc), "row_count": 0}
    wait_s = max(30, int(timeout))
    try:
        started = _query(svc, start_vql, min(60, wait_s))
    except Exception as exc:  # noqa: BLE001
        return {
            "artifact": artifact,
            "ok": False,
            "error": str(exc),
            "row_count": 0,
            "vql": start_vql,
        }
    if started.error:
        return {
            "artifact": artifact,
            "ok": False,
            "error": started.error,
            "row_count": 0,
            "vql": start_vql,
        }
    flow_id = _flow_id_from_rows(list(started.rows or []))
    if not flow_id:
        return {
            "artifact": artifact,
            "ok": False,
            "error": (
                "collect_client did not return a flow_id "
                "(Velociraptor 0.76 needs the function form, not "
                "SELECT * FROM collect_client)"
            ),
            "row_count": len(started.rows or []),
            "rows": list(started.rows or [])[:20],
            "vql": start_vql,
            "client_id": client_id,
        }

    state = ""
    sources: list[str] = []
    collected_rows = 0
    deadline = time.monotonic() + wait_s
    status_error = ""
    while True:
        try:
            status = _query(svc, flow_status_vql(client_id, flow_id), 30)
        except Exception as exc:  # noqa: BLE001
            status_error = str(exc)
            status = None
        if status and not status.error and status.rows:
            row = status.rows[0]
            state = str(row.get("state") or "")
            collected_rows = int(row.get("total_collected_rows") or 0)
            sources = [
                item for item in _str_list(row.get("artifacts_with_results")) if _SAFE_SOURCE.match(item)
            ]
            if state.upper() in _DONE_STATES:
                break
        elif status and status.error:
            status_error = status.error
        if time.monotonic() >= deadline:
            return {
                "artifact": artifact,
                "ok": False,
                "error": (
                    f"flow {flow_id} still {state or 'unknown'} after {wait_s}s"
                    + (f": {status_error}" if status_error else "")
                ),
                "row_count": 0,
                "flow_id": flow_id,
                "state": state,
                "vql": start_vql,
                "client_id": client_id,
            }
        time.sleep(2)

    if state.upper() != "FINISHED" and not sources:
        return {
            "artifact": artifact,
            "ok": False,
            "error": f"flow {flow_id} state={state}",
            "row_count": 0,
            "flow_id": flow_id,
            "state": state,
            "vql": start_vql,
            "client_id": client_id,
        }

    harvest_note = ""
    if state.upper() != "FINISHED":
        harvest_note = f"flow {flow_id} state={state} (harvested sources anyway)"

    if not sources:
        try:
            enum = _query(svc, enumerate_flow_vql(client_id, flow_id), min(60, wait_s))
        except Exception:  # noqa: BLE001
            enum = None
        if enum and not enum.error:
            for row in enum.rows or []:
                if str(row.get("Type") or "") != "Result":
                    continue
                data = row.get("Data") if isinstance(row.get("Data"), dict) else {}
                src = _source_from_vfs(str(data.get("VFSPath") or ""))
                if src and src not in sources:
                    sources.append(src)

    rows: list[dict] = []
    all_rows: list[dict] = []
    fetch_error = ""
    for src in sources:
        try:
            fetched = _query(
                svc,
                flow_results_vql(client_id, flow_id, src),
                min(120, wait_s),
            )
        except Exception as exc:  # noqa: BLE001
            fetch_error = str(exc)
            continue
        if fetched.error:
            fetch_error = fetched.error
            continue
        for item in fetched.rows or []:
            if not isinstance(item, dict):
                continue
            tagged = {"_source": src, **item}
            all_rows.append(tagged)
            if len(rows) < 200:
                rows.append(tagged)
            if len(all_rows) >= 20000:
                break
        if len(all_rows) >= 20000:
            break

    ok = True
    error = harvest_note
    if collected_rows > 0 and not rows:
        ok = False
        error = fetch_error or f"flow {flow_id} finished with {collected_rows} rows but none fetched"
    elif harvest_note and not rows:
        ok = False
        error = harvest_note
    return {
        "artifact": artifact,
        "ok": ok,
        "error": error,
        "row_count": len(all_rows) or len(rows),
        "rows": rows[:200],
        "all_rows": all_rows,
        "duration_ms": getattr(started, "duration_ms", 0),
        "client_id": client_id,
        "flow_id": flow_id,
        "state": state,
        "sources": sources,
        "vql": start_vql,
    }
