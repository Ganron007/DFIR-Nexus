"""Portal route for the finding exhibit (WO-A4 / WP 13.4).

`GET /portal/api/finding/exhibit?id=<finding_id>&case=<case_id>` streams the
zip for an **approved** finding. A DRAFT is refused with the reason, not with a
500: the examiner should read why, and the refusal is part of the contract.

The exhibit is built in a temporary directory and streamed - the case is never
written to, and nothing is left behind in it.
"""
from __future__ import annotations

import shutil
import tempfile

from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Route

from nexus.analysis.finding_exhibit import ExhibitRefused, build_exhibit


async def api_finding_exhibit(request):
    """GET /portal/api/finding/exhibit - the reproducibility bundle."""
    params = request.query_params
    finding_id = (params.get("id") or params.get("finding_id") or "").strip()
    if not finding_id:
        return JSONResponse({"error": "id is required"}, status_code=400)

    try:
        from nexus.analysis.finding_exhibit import resolve_case_dir
        from nexus.case.outputs import resolve_active_case_dir

        case_id = (params.get("case") or "").strip()
        case_dir = resolve_case_dir(case_id) if case_id else None
        if case_dir is None:
            case_dir = resolve_active_case_dir()
        if case_dir is None:
            return JSONResponse(
                {"error": "no case selected; pass ?case=<case_id>"}, status_code=400
            )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"case resolution failed: {exc}"}, status_code=500)

    scratch = tempfile.mkdtemp(prefix="nexus-exhibit-")
    try:
        zip_path = build_exhibit(case_dir, finding_id, dest_dir=scratch)
    except ExhibitRefused as exc:
        shutil.rmtree(scratch, ignore_errors=True)
        # 409: the request is well-formed, the case state forbids it
        return JSONResponse(
            {"error": str(exc), "finding_id": finding_id, "refused": True},
            status_code=409,
        )
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(scratch, ignore_errors=True)
        return JSONResponse(
            {"error": f"could not build the exhibit: {exc}"}, status_code=500
        )

    return FileResponse(
        zip_path,
        media_type="application/zip",
        filename=f"exhibit-{finding_id}.zip",
        background=_Cleanup(scratch),
    )


class _Cleanup:
    """Starlette background task: remove the scratch dir after the response."""

    def __init__(self, path: str) -> None:
        self.path = path

    async def __call__(self) -> None:  # pragma: no cover - I/O side effect
        shutil.rmtree(self.path, ignore_errors=True)


def exhibit_routes() -> list[Route]:
    return [
        Route("/portal/api/finding/exhibit", api_finding_exhibit, methods=["GET"]),
    ]