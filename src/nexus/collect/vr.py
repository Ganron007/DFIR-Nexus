"""Velociraptor Stage 0 — live hunts against an enrolled client.

Mock / loopback-without-key is skipped (not a live collect). CADRE lab: set
NEXUS_VR_ENDPOINT + NEXUS_VR_API_KEY (and optional NEXUS_VR_MCP_URL +
NEXUS_VR_MCP_API_KEY) to the Velociraptor server.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from nexus.collect.types import CollectorStep, HostSpec
from nexus.vr.constants import default_api_key, default_vr_endpoint, vr_mock_enabled

_SAFE_ARTIFACT = re.compile(r"^[A-Za-z][A-Za-z0-9_.]*$")
_CLIENT_ID = re.compile(r"^C\.[A-Za-z0-9]+$")

# Enrollment proof first, then CADRE lab hunts, then Nexus catalog, then stock.
WINDOWS_HUNTS = (
    "Generic.Client.Info",
    "CADRE.Hunts.FullBreach",
    "Nexus.Hunts.FullBreach",
    "CADRE.Hunts.ProcessTree",
    "CADRE.Hunts.NetworkState",
    "CADRE.Hunts.EventLogs",
    "CADRE.Hunts.CredentialAccess",
    "CADRE.Hunts.FilesystemTimeline",
    "CADRE.Hunts.RegistrySnapshot",
)
LINUX_HUNTS = (
    "Generic.Client.Info",
    "CADRE.Hunts.LinuxTriage",
    "Nexus.Hunts.LinuxTriage",
    "CADRE.Hunts.FullBreach",
    "Linux.Triage.UAC",
    "Generic.Collection.UAC",
)


def collect_client_vql(artifact: str, client_id: str, *, timeout: int = 1800) -> str:
    """Server-side VQL that collects *on the enrolled client*, not the API host."""
    if not _SAFE_ARTIFACT.match(artifact):
        raise ValueError(f"unsafe artifact name: {artifact!r}")
    if not _CLIENT_ID.match(client_id):
        raise ValueError(f"unsafe client_id: {client_id!r}")
    wait_s = max(30, int(timeout))
    return (
        f'SELECT * FROM collect_client(client_id="{client_id}", '
        f'artifacts="{artifact}", wait=TRUE, timeout={wait_s})'
    )


def vr_live_status() -> tuple[bool, str]:
    """Return (live, reason). Live means a real server that answers a VQL ping."""
    if vr_mock_enabled():
        return False, "NEXUS_VR_USE_MOCK is set — not a live Velociraptor"
    endpoint = default_vr_endpoint()
    key = default_api_key()
    loopback = any(tok in endpoint.lower() for tok in ("127.0.0.1", "localhost"))
    if loopback and not key:
        return False, f"default endpoint {endpoint} has no API key (mock path)"
    try:
        from nexus.integration.vql_runner import VQLQuerySpec
        from nexus.vr.service import VRService

        svc = VRService(force_mock=False)
        if svc.use_mock:
            return False, "Velociraptor client is mock — set NEXUS_VR_ENDPOINT and NEXUS_VR_API_KEY"
        health = svc.health()
        mcp = health.get("mcp_health")
        if isinstance(mcp, dict) and mcp.get("ok") is False:
            return False, f"VR MCP unhealthy: {mcp}"
        ping = svc._client.query(VQLQuerySpec(name="ping", vql="SELECT 1 AS ok", timeout_seconds=8))
        if ping.error:
            return False, f"velociraptor query failed: {ping.error}"
        return True, f"live client={health.get('client_type')} endpoint={health.get('endpoint')}"
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
            detail={"note": "live hunts need NEXUS_VR_ENDPOINT + NEXUS_VR_API_KEY"},
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
        results.append(row)
        (out / f"{artifact.replace('.', '_')}.json").write_text(
            json.dumps(row, indent=2, default=str), encoding="utf-8"
        )
        if row.get("ok"):
            any_ok = True
            if artifact.endswith("FullBreach") or artifact.endswith("LinuxTriage"):
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
        ip = str(row.get("ip") or row.get("last_ip") or row.get("LastIP") or "").lower()
        if host and (host == hn or host in hn or host in fqdn or hn.startswith(host)):
            return cid
        if addr and addr not in {"localhost", "127.0.0.1", "::1"} and addr in (ip, hn, fqdn):
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


def _collect_artifact(svc, artifact: str, client_id: str, *, timeout: int) -> dict:
    from nexus.integration.vql_runner import VQLQuerySpec

    try:
        vql = collect_client_vql(artifact, client_id, timeout=timeout)
    except ValueError as exc:
        return {"artifact": artifact, "ok": False, "error": str(exc), "row_count": 0}
    spec = VQLQuerySpec(
        name=artifact,
        vql=vql,
        artifact_name=artifact,
        timeout_seconds=timeout,
        params={"client_id": client_id},
    )
    try:
        result = svc._client.query(spec)
    except Exception as exc:  # noqa: BLE001
        return {"artifact": artifact, "ok": False, "error": str(exc), "row_count": 0, "vql": vql}
    err = result.error or ""
    ok = not err
    return {
        "artifact": artifact,
        "ok": ok,
        "error": err,
        "row_count": len(result.rows),
        "rows": result.rows[:200],
        "duration_ms": result.duration_ms,
        "client_id": client_id,
        "vql": vql,
    }
