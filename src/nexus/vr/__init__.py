"""Velociraptor framework — CADRE hunt catalog and orchestration (D.0.2)."""

from nexus.vr.catalog import suggest_hunt_ids
from nexus.vr.constants import (
    CADRE_VR_API_PORT,
    CADRE_VR_FRONTEND_PORT,
    CADRE_VR_GUI_PORT,
    CADRE_VR_HOST,
    CADRE_VR_MCP_PORT,
)
from nexus.vr.schemas import VRCatalogEntry, VRClientInfo, VRHuntRunResult
from nexus.vr.service import VRService, create_vr_service

__all__ = [
    "CADRE_VR_API_PORT",
    "CADRE_VR_FRONTEND_PORT",
    "CADRE_VR_GUI_PORT",
    "CADRE_VR_HOST",
    "CADRE_VR_MCP_PORT",
    "VRCatalogEntry",
    "VRClientInfo",
    "VRHuntRunResult",
    "VRService",
    "create_vr_service",
    "suggest_hunt_ids",
]
