"""Recovery surface routes (WP 10.9 / TC-3 / TC-4)."""

from __future__ import annotations

from pathlib import Path

from starlette.responses import JSONResponse
from starlette.routing import Route

from nexus.config import settings
from nexus.recovery.service import RecoveryService


def _resolve_recovery_case_dir(request) -> Path | None:
    case_id = request.path_params.get("case_id")
    if not case_id:
        case_id = request.query_params.get("case_id")
    if case_id:
        c_dir = settings.cases_root / case_id
        if c_dir.is_dir():
            return c_dir
    # Fallback to active case
    from nexus.dashboard.app import _get_case_dir
    active = _get_case_dir(request)
    if active and (not case_id or active.name == case_id):
        return active
    return None


async def api_case_recovery_summary(request):
    """GET /portal/api/case/recovery/summary — census of recovered items."""
    case_dir = _resolve_recovery_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    service = RecoveryService(case_dir)
    return JSONResponse(service.get_summary().to_dict())


async def api_case_recovery_rdp(request):
    """GET /portal/api/case/recovery/rdp — recovered RDP bitmap tiles."""
    case_dir = _resolve_recovery_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    try:
        limit = int(request.query_params.get("limit", 50))
        offset = int(request.query_params.get("offset", 0))
    except ValueError:
        limit, offset = 50, 0
    service = RecoveryService(case_dir)
    return JSONResponse(service.list_rdp_tiles(limit=limit, offset=offset))


async def api_case_recovery_thumbcache(request):
    """GET /portal/api/case/recovery/thumbcache — recovered thumbcache/iconcache entries."""
    case_dir = _resolve_recovery_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    try:
        limit = int(request.query_params.get("limit", 50))
        offset = int(request.query_params.get("offset", 0))
    except ValueError:
        limit, offset = 50, 0
    service = RecoveryService(case_dir)
    return JSONResponse(service.list_thumbcache(limit=limit, offset=offset))


async def api_case_recovery_recycle_bin(request):
    """GET /portal/api/case/recovery/recycle-bin — recovered Recycle Bin entries."""
    case_dir = _resolve_recovery_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    try:
        limit = int(request.query_params.get("limit", 50))
        offset = int(request.query_params.get("offset", 0))
    except ValueError:
        limit, offset = 50, 0
    q = request.query_params.get("query")
    service = RecoveryService(case_dir)
    return JSONResponse(service.list_recycle_bin(limit=limit, offset=offset, query=q))


async def api_case_recovery_deleted_files(request):
    """GET /portal/api/case/recovery/deleted-files — recovered deleted/unallocated files."""
    case_dir = _resolve_recovery_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    try:
        limit = int(request.query_params.get("limit", 50))
        offset = int(request.query_params.get("offset", 0))
    except ValueError:
        limit, offset = 50, 0
    q = request.query_params.get("query")
    service = RecoveryService(case_dir)
    return JSONResponse(service.list_deleted_files(limit=limit, offset=offset, query=q))


async def api_case_recovery_export(request):
    """GET /portal/api/case/recovery/export — comprehensive recovery manifest."""
    case_dir = _resolve_recovery_case_dir(request)
    if not case_dir:
        return JSONResponse({"error": "Case not found"}, status_code=404)
    service = RecoveryService(case_dir)
    return JSONResponse(service.export_manifest())


def recovery_routes() -> list[Route]:
    """Return all Starlette Route definitions for artifact recovery."""
    return [
        Route("/portal/api/case/recovery/summary", api_case_recovery_summary, methods=["GET"]),
        Route("/portal/api/case/{case_id}/recovery/summary", api_case_recovery_summary, methods=["GET"]),
        Route("/portal/api/case/recovery/rdp", api_case_recovery_rdp, methods=["GET"]),
        Route("/portal/api/case/{case_id}/recovery/rdp", api_case_recovery_rdp, methods=["GET"]),
        Route("/portal/api/case/recovery/thumbcache", api_case_recovery_thumbcache, methods=["GET"]),
        Route("/portal/api/case/{case_id}/recovery/thumbcache", api_case_recovery_thumbcache, methods=["GET"]),
        Route("/portal/api/case/recovery/recycle-bin", api_case_recovery_recycle_bin, methods=["GET"]),
        Route("/portal/api/case/{case_id}/recovery/recycle-bin", api_case_recovery_recycle_bin, methods=["GET"]),
        Route("/portal/api/case/recovery/deleted-files", api_case_recovery_deleted_files, methods=["GET"]),
        Route("/portal/api/case/{case_id}/recovery/deleted-files", api_case_recovery_deleted_files, methods=["GET"]),
        Route("/portal/api/case/recovery/export", api_case_recovery_export, methods=["GET"]),
        Route("/portal/api/case/{case_id}/recovery/export", api_case_recovery_export, methods=["GET"]),
    ]
