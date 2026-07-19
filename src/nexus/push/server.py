"""Push ingest webhook server (E.0.1)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from nexus.constants import (
    DEFAULT_CASES_DB,
    DEFAULT_PUSH_TOKENS,
    ENV_AUDIT_SECRET,
    ENV_CASES_DB,
    ENV_PUSH_TOKENS,
)

try:
    from nexus.case import CaseManager
    from nexus.case.secrets import get_audit_secret
    _HAS_CASE_MANAGER = True
except ImportError:
    CaseManager = None  # type: ignore
    get_audit_secret = None  # type: ignore
    _HAS_CASE_MANAGER = False

from nexus.push.auth import PushTokenStore
from nexus.push.pipeline import PushPipeline


class _ManagerStub:
    """Minimal manager used when the real nexus.case manager is unavailable."""

    def get_case(self, case_id: str) -> Any:
        return None

    def add_evidence(self, case_id: str, **kwargs: Any) -> Any:
        return None

    def add_finding(self, case_id: str, **kwargs: Any) -> Any:
        return None


def _get_audit_secret() -> str:
    if get_audit_secret is not None:
        return get_audit_secret()
    return os.environ.get(ENV_AUDIT_SECRET, "")


def _manager() -> Any:
    if not _HAS_CASE_MANAGER or CaseManager is None:
        return _ManagerStub()
    db = Path(os.environ.get(ENV_CASES_DB, str(DEFAULT_CASES_DB)))
    return CaseManager(db, secret_key=_get_audit_secret())


def _token_store() -> PushTokenStore:
    path = Path(os.environ.get(ENV_PUSH_TOKENS, str(DEFAULT_PUSH_TOKENS)))
    return PushTokenStore(path)


def create_push_app() -> Any:
    """Build ASGI app for push ingest."""
    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse, Response
        from starlette.routing import Route
    except ImportError as exc:
        raise RuntimeError(
            "Starlette is required for the push server. Install the 'http' extra."
        ) from exc

    async def health(_: Request) -> Response:
        return JSONResponse({"status": "ok", "service": "nexus-push"})

    async def push_case(request: Request) -> Response:
        case_id = request.path_params["case_id"]
        auth = request.headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        if not token:
            token = request.headers.get("x-push-token", "")
        store = _token_store()
        if not store.verify(token, case_id=case_id):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid json"}, status_code=400)
        pipeline = PushPipeline(_manager())
        result = pipeline.process(case_id, body)
        status = 200 if result.get("success") else 404
        return JSONResponse(result, status_code=status)

    async def push_captures(request: Request) -> Response:
        """Extension batch endpoint — case id in header or body."""
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return JSONResponse({"error": "invalid json"}, status_code=400)
        case_id = request.headers.get("x-case-id") or ""
        if isinstance(body, dict) and not case_id:
            case_id = str(body.get("case_id") or "")
        if not case_id:
            return JSONResponse({"error": "case_id required"}, status_code=400)
        auth = request.headers.get("authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        if not token:
            token = request.headers.get("x-push-token", "")
        store = _token_store()
        if not store.verify(token, case_id=case_id):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        pipeline = PushPipeline(_manager())
        return JSONResponse(pipeline.process(case_id, body))

    return Starlette(
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/cases/{case_id}/push", push_case, methods=["POST"]),
            Route("/captures", push_captures, methods=["POST"]),
        ]
    )
