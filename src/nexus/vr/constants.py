"""Velociraptor / CADRE lab defaults (vr VM 192.168.77.51)."""

from __future__ import annotations

import os

CADRE_VR_HOST = "192.168.77.51"
CADRE_VR_GUI_PORT = 8889
CADRE_VR_API_PORT = 8001
CADRE_VR_FRONTEND_PORT = 8000
CADRE_VR_MCP_PORT = 8002

ENV_VR_MOCK = "NEXUS_VR_USE_MOCK"
ENV_VR_ENDPOINT = "NEXUS_VR_ENDPOINT"
ENV_VR_API_KEY = "NEXUS_VR_API_KEY"
ENV_VR_MCP_URL = "NEXUS_VR_MCP_URL"
ENV_VR_MCP_API_KEY = "NEXUS_VR_MCP_API_KEY"
ENV_VR_VERIFY_SSL = "NEXUS_VR_VERIFY_SSL"
ENV_VELOCIRAPTOR_ENDPOINT = "VELOCIRAPTOR_ENDPOINT"
ENV_VELOCIRAPTOR_API_KEY = "VELOCIRAPTOR_API_KEY"


def vr_mock_enabled() -> bool:
    return os.environ.get(ENV_VR_MOCK, "").lower() in ("1", "true", "yes")


def default_vr_endpoint() -> str:
    return os.environ.get(ENV_VR_ENDPOINT) or os.environ.get(
        ENV_VELOCIRAPTOR_ENDPOINT,
        f"https://{CADRE_VR_HOST}:{CADRE_VR_API_PORT}/",
    )


def default_mcp_url() -> str:
    return os.environ.get(ENV_VR_MCP_URL, f"http://{CADRE_VR_HOST}:{CADRE_VR_MCP_PORT}")


def default_api_key() -> str:
    return os.environ.get(ENV_VR_API_KEY) or os.environ.get(ENV_VELOCIRAPTOR_API_KEY, "")


def default_mcp_api_key() -> str:
    return os.environ.get(ENV_VR_MCP_API_KEY, "")


def default_verify_ssl(endpoint: str = "") -> bool:
    override = os.environ.get(ENV_VR_VERIFY_SSL, "").strip().lower()
    if override in ("1", "true", "yes"):
        return True
    if override in ("0", "false", "no"):
        return False
    endpoint_l = (endpoint or "").lower()
    return CADRE_VR_HOST not in endpoint_l and "192.168.77.51" not in endpoint_l
