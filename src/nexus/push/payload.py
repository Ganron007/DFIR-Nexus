"""Normalize libre POST bodies from browser extension / webhooks."""

from __future__ import annotations

from typing import Any


def normalize_push_payload(body: dict[str, Any] | list[Any]) -> dict[str, Any]:
    """Coerce heterogeneous push JSON into a standard envelope."""
    if isinstance(body, list):
        return {
            "kind": "capture_batch",
            "captures": [_normalize_capture(item) for item in body if isinstance(item, dict)],
        }
    if not isinstance(body, dict):
        return {"kind": "unknown", "raw": str(body)[:2000]}

    kind = str(body.get("kind") or body.get("type") or "capture").lower()
    if kind in {"capture", "event", "artifact"}:
        return {"kind": "capture", "capture": _normalize_capture(body)}
    if kind in {"batch", "captures", "events"}:
        items = body.get("captures") or body.get("events") or body.get("items") or []
        return {
            "kind": "capture_batch",
            "source": body.get("source") or body.get("adapter"),
            "captures": [_normalize_capture(x) for x in items if isinstance(x, dict)],
        }
    if "artifacts" in body:
        return {
            "kind": "artifact_batch",
            "artifacts": list(body.get("artifacts") or []),
            "source": body.get("source"),
        }
    return {"kind": kind, "payload": body}


def _normalize_capture(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": item.get("title") or item.get("name") or "capture",
        "source": item.get("source") or item.get("adapter") or "extension",
        "url": item.get("url") or item.get("page_url"),
        "method": item.get("method"),
        "status": item.get("status") or item.get("status_code"),
        "timestamp": item.get("timestamp") or item.get("captured_at"),
        "body": item.get("body") or item.get("response") or item.get("data"),
        "headers": item.get("headers") or {},
        "metadata": {
            k: v
            for k, v in item.items()
            if k
            not in {
                "title",
                "name",
                "source",
                "adapter",
                "url",
                "page_url",
                "method",
                "status",
                "status_code",
                "timestamp",
                "captured_at",
                "body",
                "response",
                "data",
                "headers",
            }
        },
    }
