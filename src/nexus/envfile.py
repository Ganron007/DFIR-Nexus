"""Shared .env writer for environment preflight (UI setup + `nexus config env`).

The runtime config surface for LLM/ES is ``.env`` — read by
``llm_pipeline._load_dotenv`` from CWD then repo root. This module merges
keys into the repo-root ``.env`` (the deterministic candidate for source
checkouts) and applies them to ``os.environ`` immediately so a running
server picks them up without restart.

Only the allowlisted keys below may be written — arbitrary env injection
over HTTP would be a foot-gun the size of a workstation image.
"""

from __future__ import annotations

import os
from pathlib import Path

# Keys the preflight panel / `nexus config env` are allowed to set.
SETUP_ENV_KEYS = {
    "NEXUS_ES_URL",
    "NEXUS_LLM_MODEL",
    "NEXUS_LLM_BASE_URL",
    "NEXUS_LLM_API_KEY",
    "NEXUS_LLM_PROVIDER",
    "NEXUS_LLM_REASONING",
}

# Keys never echoed back in responses.
_SECRET_KEYS = {"NEXUS_LLM_API_KEY"}

_MAX_VALUE_LEN = 500


def env_file_path() -> Path:
    """Repo-root .env — the second candidate _load_dotenv reads (first
    for the common case where the server runs from the repo root)."""
    return Path(__file__).resolve().parents[2] / ".env"


def apply_env(mapping: dict[str, str], environ: dict | None = None) -> dict[str, str]:
    """Merge ``mapping`` into the .env file and os.environ.

    Empty string removes the key (e.g. clearing NEXUS_ES_URL returns to
    CSV-pack mode). Returns the applied (masked) key->value map. Raises
    ValueError for disallowed keys or malformed values.
    """
    environ = os.environ if environ is None else environ
    clean: dict[str, str] = {}
    for key, value in mapping.items():
        key = str(key).strip()
        if key not in SETUP_ENV_KEYS:
            raise ValueError(f"key not allowed: {key}")
        value = str(value or "").strip()
        if len(value) > _MAX_VALUE_LEN or "\n" in value or "\r" in value:
            raise ValueError(f"bad value for {key}")
        clean[key] = value
    if not clean:
        raise ValueError("no keys provided")

    path = env_file_path()
    lines: list[str] = []
    if path.is_file():
        lines = path.read_text(encoding="utf-8").splitlines()

    remaining = dict(clean)
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.partition("=")[0].strip()
            if k in remaining:
                if remaining.pop(k):  # non-empty → rewrite in place
                    out.append(f"{k}={clean[k]}")
                continue  # empty → drop the line
        out.append(line)
    for key, value in remaining.items():
        if value:
            out.append(f"{key}={value}")

    path.write_text("\n".join(out).rstrip("\n") + "\n", encoding="utf-8")

    for key, value in clean.items():
        if value:
            environ[key] = value
        else:
            environ.pop(key, None)

    return {k: ("***" if k in _SECRET_KEYS and v else v) for k, v in clean.items()}
