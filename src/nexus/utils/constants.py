"""Centralized constants — env var names, defaults, paths.

Every external configuration point (env var, default path, port) lives here
so the gateway, portal, CLI, and tests all agree on the same names.

CADRE-specific defaults (e.g. hard-coded lab Velociraptor hosts) have been
removed or made configurable. All environment variables use the ``NEXUS_``
prefix so the package is usable outside the CADRE ecosystem.
"""

from __future__ import annotations

import os
from pathlib import Path

# ============================================================================
# Path defaults
# ============================================================================

DEFAULT_DATA_DIR = Path("./data")
"""Root directory for all runtime artifacts (cases DB, push tokens, RAG, etc.)."""

DEFAULT_CASES_DB = DEFAULT_DATA_DIR / "cases.db"
DEFAULT_PUSH_TOKENS = DEFAULT_DATA_DIR / "push_tokens.json"
DEFAULT_RAG_DATA = DEFAULT_DATA_DIR / "rag"
DEFAULT_RAG_BUNDLES = DEFAULT_DATA_DIR / "rag_bundles"
DEFAULT_TRIAGE_DATA = DEFAULT_DATA_DIR / "triage"
DEFAULT_TRIAGE_DB = DEFAULT_TRIAGE_DATA / "triage.db"
DEFAULT_DETECTION_INDEX = DEFAULT_DATA_DIR / "detection"
DEFAULT_KNOWN_GOOD_DB = DEFAULT_DATA_DIR / "known_good.db"
DEFAULT_CONTEXT_DB = DEFAULT_DATA_DIR / "context.db"
DEFAULT_SIGMAHQ_REPO = DEFAULT_DATA_DIR / "sigmahq"
DEFAULT_EZ_TOOLS_DIR = DEFAULT_DATA_DIR / "ez_tools"


# ============================================================================
# LLM / providers
# ============================================================================

ENV_DEFAULT_PROVIDER = "NEXUS_DEFAULT_PROVIDER"
"""Default LLM provider name when no API keys are configured."""


# ============================================================================
# Case management
# ============================================================================

ENV_CASES_DB = "NEXUS_CASES_DB"
"""Path to the SQLite cases database."""

ENV_AUDIT_SECRET = "NEXUS_AUDIT_SECRET"
"""HMAC secret for the audit chain (required for non-loopback deploys)."""


# ============================================================================
# Portal (Examiner Portal)
# ============================================================================

ENV_PORTAL_PASSWORD = "NEXUS_PORTAL_PASSWORD"
"""Password to gate the Examiner Portal (required for non-loopback deploys)."""

ENV_PORTAL_SESSION_TTL = "NEXUS_PORTAL_SESSION_TTL"
"""Portal session TTL in seconds. Default 8 hours."""

DEFAULT_PORTAL_SESSION_TTL = 8 * 3600


# ============================================================================
# Push ingest
# ============================================================================

ENV_PUSH_TOKENS = "NEXUS_PUSH_TOKENS"
"""Path to the per-case push token store JSON file."""


# ============================================================================
# Velociraptor
# ============================================================================

ENV_VR_ENDPOINT = "NEXUS_VR_ENDPOINT"
ENV_VR_API_KEY = "NEXUS_VR_API_KEY"
ENV_VR_VERIFY_SSL = "NEXUS_VR_VERIFY_SSL"
ENV_VR_MCP_URL = "NEXUS_VR_MCP_URL"
ENV_VR_MCP_API_KEY = "NEXUS_VR_MCP_API_KEY"
ENV_VR_USE_MOCK = "NEXUS_VR_USE_MOCK"
ENV_VR_ALLOW_ADHOC_VQL = "NEXUS_VR_ALLOW_ADHOC_VQL"
"""When set to "1", allows arbitrary ad-hoc VQL (live mode requires this opt-in)."""


# ============================================================================
# TI (threat intelligence)
# ============================================================================

ENV_TI_MOCK = "NEXUS_TI_MOCK"
ENV_TI_ABUSECH_API_KEY = "NEXUS_TI_ABUSECH_API_KEY"
ENV_TI_MISP_URL = "NEXUS_TI_MISP_URL"
ENV_TI_MISP_API_KEY = "NEXUS_TI_MISP_API_KEY"
ENV_TI_OTX_API_KEY = "NEXUS_TI_OTX_API_KEY"
ENV_TI_SHODAN_API_KEY = "NEXUS_TI_SHODAN_API_KEY"
ENV_TI_VIRUSTOTAL_API_KEY = "NEXUS_TI_VIRUSTOTAL_API_KEY"
ENV_TI_ABUSEIPDB_API_KEY = "NEXUS_TI_ABUSEIPDB_API_KEY"
ENV_TI_CROWDSTRIKE_CLIENT_ID = "NEXUS_TI_CROWDSTRIKE_CLIENT_ID"
ENV_TI_CROWDSTRIKE_CLIENT_SECRET = "NEXUS_TI_CROWDSTRIKE_CLIENT_SECRET"


# ============================================================================
# Detection / Sigma
# ============================================================================

ENV_DETECTION_INDEX = "NEXUS_DETECTION_INDEX"
"""Path to the detection rule index directory."""

ENV_SIGMAHQ_REPO = "NEXUS_SIGMAHQ_REPO"


# ============================================================================
# RAG (forensic knowledge search)
# ============================================================================

ENV_RAG_DATA = "NEXUS_RAG_DATA"
ENV_RAG_BUNDLES = "NEXUS_RAG_BUNDLES"
ENV_RAG_PERSIST = "NEXUS_RAG_PERSIST"
ENV_RAG_EMBED_MODEL = "NEXUS_RAG_EMBED_MODEL"
ENV_RAG_RELEASE_REPO = "NEXUS_RAG_RELEASE_REPO"


# ============================================================================
# Triage (Windows baseline)
# ============================================================================

ENV_TRIAGE_DATA = "NEXUS_TRIAGE_DATA"
ENV_TRIAGE_DB = "NEXUS_TRIAGE_DB"
ENV_TRIAGE_RELEASE_REPO = "NEXUS_TRIAGE_RELEASE_REPO"
ENV_KNOWN_GOOD_DB = "NEXUS_KNOWN_GOOD_DB"
ENV_CONTEXT_DB = "NEXUS_CONTEXT_DB"
ENV_DATA_ROOTS = "NEXUS_DATA_ROOTS"


# ============================================================================
# Polish
# ============================================================================

ENV_EZ_TOOLS_DIR = "NEXUS_EZ_TOOLS_DIR"


# ============================================================================
# Knowledge graph
# ============================================================================

ENV_GRAPH_MAX_EDGES = "NEXUS_GRAPH_MAX_EDGES"
DEFAULT_GRAPH_MAX_EDGES = 500


# ============================================================================
# Artifact store
# ============================================================================

ENV_ARTIFACT_STORE_MAX_COUNT = "NEXUS_ARTIFACT_STORE_MAX_COUNT"
ENV_ARTIFACT_STORE_MAX_BYTES = "NEXUS_ARTIFACT_STORE_MAX_BYTES"
DEFAULT_ARTIFACT_STORE_MAX_COUNT = 5000
DEFAULT_ARTIFACT_STORE_MAX_BYTES = 256 * 1024 * 1024  # 256 MB


# ============================================================================
# Integrations (webhooks)
# ============================================================================

ENV_SLACK_WEBHOOK = "NEXUS_SLACK_WEBHOOK"
ENV_TEAMS_WEBHOOK = "NEXUS_TEAMS_WEBHOOK"
ENV_DISCORD_WEBHOOK = "NEXUS_DISCORD_WEBHOOK"
ENV_TELEGRAM_BOT_TOKEN = "NEXUS_TELEGRAM_BOT_TOKEN"
ENV_TELEGRAM_CHAT_ID = "NEXUS_TELEGRAM_CHAT_ID"
ENV_SMTP_HOST = "NEXUS_SMTP_HOST"
ENV_SMTP_PORT = "NEXUS_SMTP_PORT"
ENV_SMTP_USER = "NEXUS_SMTP_USER"
ENV_SMTP_PASSWORD = "NEXUS_SMTP_PASSWORD"
ENV_SMTP_FROM = "NEXUS_SMTP_FROM"
ENV_SMTP_TO = "NEXUS_SMTP_TO"


# ============================================================================
# Required-for-production env vars
# ============================================================================

REQUIRED_FOR_PROD: tuple[str, ...] = (
    ENV_AUDIT_SECRET,
    ENV_PORTAL_PASSWORD,
)
"""Env vars that MUST be set when DFIR-Nexus is reachable beyond loopback."""


# ============================================================================
# Path helpers
# ============================================================================


def cases_db_path() -> Path:
    """Path to the SQLite cases database (env override or default)."""
    return Path(os.environ.get(ENV_CASES_DB, str(DEFAULT_CASES_DB)))


def push_tokens_path() -> Path:
    """Path to the per-case push token store JSON file."""
    return Path(os.environ.get(ENV_PUSH_TOKENS, str(DEFAULT_PUSH_TOKENS)))


def detection_index_path() -> Path:
    """Path to the detection rule index directory."""
    return Path(os.environ.get(ENV_DETECTION_INDEX, str(DEFAULT_DETECTION_INDEX)))


def rag_data_path() -> Path:
    """Path to the RAG data directory."""
    return Path(os.environ.get(ENV_RAG_DATA, str(DEFAULT_RAG_DATA)))


def triage_data_path() -> Path:
    """Path to the triage data directory."""
    return Path(os.environ.get(ENV_TRIAGE_DATA, str(DEFAULT_TRIAGE_DATA)))


def ez_tools_dir() -> Path:
    """Path to the EZ Tools directory."""
    return Path(os.environ.get(ENV_EZ_TOOLS_DIR, str(DEFAULT_EZ_TOOLS_DIR)))


# ============================================================================
# Environment validation
# ============================================================================


def is_loopback_bind(host: str = "127.0.0.1", *, port: int | None = None) -> bool:
    """Return True when the bind address is loopback (any port).

    Used by :func:`check_required_env` to decide whether required env vars
    (audit secret, portal password) should raise an error or just warn.
    """
    if host not in ("127.0.0.1", "localhost", "::1"):
        return False
    return port is None or port >= 1024


def check_required_env(
    *,
    host: str = "127.0.0.1",
    port: int | None = None,
    required: tuple[str, ...] = REQUIRED_FOR_PROD,
) -> list[str]:
    """Return a list of missing required env var names.

    Behaviour:
    - For loopback binds, only *warn* (return names so the caller can log them).
    - For non-loopback binds, *raise* :class:`MissingProductionEnvError` if any
      of ``required`` is unset.
    """
    missing = [name for name in required if not os.environ.get(name)]
    if not missing:
        return []
    if is_loopback_bind(host, port=port):
        return missing
    raise MissingProductionEnvError(missing)


def warn_loopback_env(logger: object = None) -> list[str]:  # noqa: ARG001
    """Convenience wrapper that returns loopback warnings without raising.

    Example:
        warnings = warn_loopback_env()
        for w in warnings:
            log.warning("env %s is not set (loopback)", w)
    """
    return check_required_env(host="127.0.0.1", port=None)


class MissingProductionEnvError(RuntimeError):
    """Raised when a required env var is missing on a non-loopback bind."""

    def __init__(self, missing: list[str]) -> None:
        self.missing = missing
        super().__init__(
            "Required env var(s) not set for non-loopback bind: "
            + ", ".join(missing)
            + ". Set them in the environment or bind to 127.0.0.1 for local use."
        )
