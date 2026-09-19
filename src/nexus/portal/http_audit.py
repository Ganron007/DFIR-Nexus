"""Phase 4k.3 — HTTP audit trail.

Two layers:
1. **File logging** — `nexus serve --http` writes rotating access/error/app
   logs to `logs/nexus-http-YYYYMMDD.log` (uvicorn `log_config`).
2. **Case audit chain** — an ASGI middleware appends transport entries to the
   hash-chained case audit (`case/audit/http.jsonl`) for every `/portal/api/*`
   request (mutating always, reads at `NEXUS_HTTP_AUDIT=all`) and every `/mcp`
   call (tool name parsed from the JSON-RPC body when present).

Honesty rules: failures to audit log a warning (never silent), secrets are
redacted, and the middleware never touches response bytes.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

_SECRET_KEYS = (
    "token", "key", "password", "passwd", "secret", "api_key", "apikey",
    "authorization", "bearer",
)


def _truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "all"}


def http_logging_enabled() -> bool:
    raw = os.environ.get("NEXUS_HTTP_LOG", "").strip().lower()
    return raw not in {"0", "false", "no"}


def http_log_dir() -> Path:
    return Path(os.environ.get("NEXUS_HTTP_LOG_DIR", "").strip() or "logs")


def _log_max_bytes() -> int:
    try:
        return max(1, int(os.environ.get("NEXUS_HTTP_LOG_MAX_MB", "50"))) * 1024 * 1024
    except ValueError:
        return 50 * 1024 * 1024


def _log_backups() -> int:
    try:
        return max(1, int(os.environ.get("NEXUS_HTTP_LOG_BACKUPS", "7")))
    except ValueError:
        return 7


def http_log_config(log_dir: Path | None = None) -> dict[str, Any]:
    """uvicorn/`logging.config` dict for the HTTP server (file + console)."""
    directory = log_dir or http_log_dir()
    directory.mkdir(parents=True, exist_ok=True)
    dated = directory / f"nexus-http-{datetime.now(UTC):%Y%m%d}.log"
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "http": {
                "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
            },
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "http",
                "stream": "ext://sys.stderr",
            },
            "httpfile": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "http",
                "filename": str(dated),
                "maxBytes": _log_max_bytes(),
                "backupCount": _log_backups(),
                "encoding": "utf-8",
            },
        },
        "loggers": {
            "uvicorn": {"handlers": ["console", "httpfile"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"handlers": ["console", "httpfile"], "level": "INFO", "propagate": False},
            "uvicorn.access": {"handlers": ["console", "httpfile"], "level": "INFO", "propagate": False},
            "nexus": {"handlers": ["console", "httpfile"], "level": "INFO", "propagate": False},
        },
    }


def redact_query(raw: str) -> str:
    """Keep parameter names, mask secret-looking values, cap the length."""
    if not raw:
        return ""
    parts: list[str] = []
    for item in raw.split("&"):
        if not item:
            continue
        key, sep, value = item.partition("=")
        if sep and any(s in key.lower() for s in _SECRET_KEYS):
            parts.append(f"{key}=***")
        else:
            parts.append(item[:120])
        if len(parts) >= 20:
            break
    return "&".join(parts)[:400]


def _decode(values: Any) -> str:
    if isinstance(values, bytes):
        return values.decode("utf-8", errors="replace")
    return str(values or "")


def _parse_mcp_tool(body: bytes) -> str:
    """JSON-RPC body → tool label (``tools/call:<name>``) or the method."""
    try:
        payload = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return ""
    if isinstance(payload, list):
        payload = payload[0] if payload else {}
    if not isinstance(payload, dict):
        return ""
    method = str(payload.get("method") or "")
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    name = str(params.get("name") or "")
    if method == "tools/call" and name:
        return f"tools/call:{name}"
    return method


def _resolve_case_id(scope: dict[str, Any]) -> str:
    headers = {k.decode("latin-1").lower(): v.decode("latin-1", "replace")
               for k, v in scope.get("headers") or []}
    case_id = (headers.get("x-nexus-case") or "").strip()
    if not case_id:
        raw_q = _decode(scope.get("query_string"))
        for item in raw_q.split("&"):
            key, _, value = item.partition("=")
            if key == "case_id" and value:
                case_id = value
                break
    if not case_id:
        case_id = (os.environ.get("NEXUS_ACTIVE_CASE") or "").strip()
    return case_id


def _audit_dir_for(case_id: str) -> Path | None:
    """Case audit dir when resolvable; global chain only when explicitly on."""
    if case_id:
        try:
            from nexus.discipline import validate_case_id

            if validate_case_id(case_id):
                return None
            from nexus.config import settings

            case_dir = settings.cases_root / case_id
            if case_dir.is_dir():
                return case_dir / "audit"
        except Exception:  # noqa: BLE001 — audit resolution must never raise
            return None
    if _truthy("NEXUS_HTTP_AUDIT_GLOBAL"):
        return Path.home() / ".nexus" / "audit"
    return None


class HttpAuditMiddleware:
    """ASGI middleware → hash-chained audit entries for portal + MCP calls."""

    def __init__(self, app, *, path_prefixes: tuple[str, ...] = ("/portal/api/", "/mcp")):
        self.app = app
        self.path_prefixes = path_prefixes

    def _wanted(self, path: str, method: str) -> bool:
        if not path.startswith(self.path_prefixes):
            return False
        if path.startswith("/mcp"):
            return True
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            return True
        return _truthy("NEXUS_HTTP_AUDIT")

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path") or "")
        method = str(scope.get("method") or "GET").upper()
        if not self._wanted(path, method):
            await self.app(scope, receive, send)
            return

        started = time.perf_counter()
        status = [0]
        out_bytes = [0]
        body = b""

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                status[0] = int(message.get("status") or 0)
            elif message.get("type") == "http.response.body":
                out_bytes[0] += len(message.get("body") or b"")
            await send(message)

        try:
            if path.startswith("/mcp"):
                # MCP JSON-RPC bodies are small: buffer (capped) so the tool
                # name can be recorded, then replay the request downstream.
                buffered = bytearray()
                while len(buffered) < 65536:
                    message = await receive()
                    if message.get("type") != "http.request":
                        break
                    buffered.extend(message.get("body") or b"")
                    if not message.get("more_body"):
                        break
                body = bytes(buffered)
                replay = [{"type": "http.request", "body": body, "more_body": False}]

                async def receive_replay():
                    return replay.pop(0) if replay else {"type": "http.disconnect"}

                await self.app(scope, receive_replay, send_wrapper)
            else:
                await self.app(scope, receive, send_wrapper)
        finally:
            await self._record(scope, method, path, status[0], out_bytes[0], started, body)

    async def _record(self, scope, method, path, status, out_bytes, started, body) -> None:
        try:
            case_id = _resolve_case_id(scope)
            audit_dir = _audit_dir_for(case_id)
            if audit_dir is None:
                return
            tool = "http_request"
            if path.startswith("/mcp"):
                tool = f"mcp:{_parse_mcp_tool(body) or 'request'}"
            params = {
                "method": method,
                "path": path,
                "query": redact_query(_decode(scope.get("query_string"))),
                "status": status,
                "bytes_out": out_bytes,
            }
            extra = {
                "remote": str((scope.get("client") or ("", 0))[0]),
                "http_audit": True,
            }
            elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

            def _write() -> None:
                from nexus.audit import AuditWriter

                AuditWriter("http", audit_dir=audit_dir).log(
                    tool=tool, params=params, source="http",
                    elapsed_ms=elapsed_ms, extra=extra,
                )

            await asyncio.to_thread(_write)
        except Exception as exc:  # noqa: BLE001 — auditing must never break a response
            log.warning("http audit write failed for %s %s: %s", method, path, exc)
