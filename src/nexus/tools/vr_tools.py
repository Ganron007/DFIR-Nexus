"""MCP Velociraptor tools on the main server (mock-safe by default).

Live VR is optional via NEXUS_VR_ENDPOINT / NEXUS_VR_MCP_URL.
This is the single story: hunts and ad-hoc VQL live on nexus serve, not a
second process. Ad-hoc VQL is policy-gated by `nexus.vr.vql_policy`.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter


def register_tools(server: FastMCP, audit: AuditWriter) -> None:
    @server.tool()
    def vr_health() -> dict:
        """Velociraptor client health (mock or live)."""
        from nexus.vr.service import VRService

        svc = VRService()
        detail = svc.health()
        audit.log(tool="vr_health", params={}, result_summary={"mock": detail.get("mock_mode")})
        return detail

    @server.tool()
    def vr_list_hunts(technique_id: str = "") -> dict:
        """List catalog hunts (10 Nexus.* entries)."""
        from nexus.vr.service import VRService

        svc = VRService()
        hunts = svc.list_hunts(technique_id=technique_id or None)
        return {"hunts": hunts, "count": len(hunts)}

    @server.tool()
    def vr_list_clients() -> dict:
        """List known / mock Velociraptor clients."""
        from nexus.vr.service import VRService

        svc = VRService()
        clients = [c.to_dict() if hasattr(c, "to_dict") else c.__dict__ for c in svc.list_clients()]
        return {"clients": clients, "count": len(clients), "mock": svc.use_mock}

    @server.tool()
    def vr_run_hunt(hunt_id: str, client_id: str = "C.mbr01") -> dict:
        """Run a catalog hunt. Mock returns synthetic rows unless live VR is configured."""
        from nexus.vr.service import VRService

        svc = VRService()
        result = svc.run_hunt(hunt_id, client_id)
        payload = result.to_dict() if hasattr(result, "to_dict") else result.__dict__
        audit.log(tool="vr_run_hunt", params={"hunt_id": hunt_id}, result_summary={"rows": payload.get("row_count")})
        return payload

    @server.tool()
    def vr_vql_query(vql: str, client_id: str = "", timeout_seconds: int = 60) -> dict:
        """Run an ad-hoc VQL query (policy-gated). Mock-safe; live requires NEXUS_VR_ALLOW_ADHOC.

        Replaces the retired standalone velociraptor_mcp_server process — this is
        now the single VR surface on the main server.
        """
        from nexus.vr.service import VRService

        svc = VRService()
        result = svc.vql_query(vql, client_id=client_id or None, timeout_seconds=timeout_seconds)
        audit.log(
            tool="vr_vql_query",
            params={"vql": vql[:200], "client_id": client_id},
            result_summary={"rows": result.get("result", {}).get("row_count"), "error": result.get("error")},
        )
        return result
