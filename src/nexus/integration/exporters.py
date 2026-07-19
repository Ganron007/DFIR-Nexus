"""E.0.3 — Third-party case exporters (HTTP push)."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

log = logging.getLogger(__name__)


async def push_timesketch(
    *,
    base_url: str,
    api_key: str,
    sketch_id: int,
    timeline: list[dict[str, Any]],
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/api/v1/sketches/{sketch_id}/timeline/"
    headers = {"Authorization": api_key, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers=headers, json={"timeline": timeline})
        return {"status": resp.status_code, "ok": resp.is_success, "body": resp.text[:500]}


async def push_misp(
    *,
    base_url: str,
    api_key: str,
    event_info: str,
    attributes: list[dict[str, Any]],
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/events/add"
    headers = {"Authorization": api_key, "Content-Type": "application/json", "Accept": "application/json"}
    payload = {"Event": {"info": event_info, "Attribute": attributes}}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        return {"status": resp.status_code, "ok": resp.is_success, "body": resp.text[:500]}


async def push_iris(
    *,
    base_url: str,
    api_key: str,
    case_id: int,
    note_title: str,
    note_content: str,
) -> dict[str, Any]:
    url = f"{base_url.rstrip('/')}/case/notes/add"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"case_id": case_id, "note_title": note_title, "note_content": note_content}
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, headers=headers, json=payload)
        return {"status": resp.status_code, "ok": resp.is_success, "body": resp.text[:500]}


def build_timesketch_timeline(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for _idx, entry in enumerate(bundle.get("audit_log") or [], start=1):
        action = entry.action.value if hasattr(entry.action, "value") else str(entry.action)
        rows.append(
            {
                "datetime": entry.timestamp.isoformat(),
                "timestamp_desc": action,
                "message": json.dumps(entry.payload, default=str)[:500],
                "tag": ["dfir-nexus"],
            }
        )
    return rows


def build_misp_attributes(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    attrs: list[dict[str, Any]] = []
    for finding in bundle.get("findings") or []:
        attrs.append(
            {
                "type": "comment",
                "value": f"{finding.title}: {finding.description}"[:2000],
                "category": "Internal reference",
            }
        )
    for evidence in bundle.get("evidence") or []:
        if evidence.file_hash_sha256:
            attrs.append(
                {
                    "type": "sha256",
                    "value": evidence.file_hash_sha256,
                    "category": "Payload delivery",
                }
            )
    return attrs
