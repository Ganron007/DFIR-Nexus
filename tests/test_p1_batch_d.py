"""Regression tests for P1 Batch D (Docker packaging & documentation accuracy)."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def test_p1_3_dockerfile_is_multistage_with_built_spa_and_bind_host():
    """Dockerfile builds frontend/dist in a Node stage and copies it into runtime."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "AS frontend-builder" in dockerfile
    assert "npm ci" in dockerfile
    assert "npm run build" in dockerfile
    assert "COPY --from=frontend-builder" in dockerfile
    assert "./frontend/dist" in dockerfile
    assert '"--host", "0.0.0.0"' in dockerfile

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    for excluded in ("frontend/node_modules", "scratch", "cases"):
        assert excluded in dockerignore


def test_p1_3_docker_compose_declares_required_secrets():
    """docker-compose.yml requires portal password, bearer token, and audit secret on 0.0.0.0."""
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    env_list = compose["services"]["dfir-nexus"]["environment"]
    env_joined = "\n".join(str(x) for x in env_list)
    for var in ("NEXUS_AUDIT_SECRET", "NEXUS_PORTAL_PASSWORD", "NEXUS_BEARER_TOKEN"):
        assert var in env_joined
        assert ":?" in env_joined


def test_p1_doc_repo_urls_and_readme_accuracy():
    """Packaging metadata and docs reflect current repo URL, UI stack, and commands."""
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "Ganron007/DFIR-Nexus" in pyproject
    assert "Unallocated" not in pyproject
    assert 'version = "1.0.0"' in pyproject

    setup_doc = (ROOT / "Docs" / "SETUP.md").read_text(encoding="utf-8")
    assert "Unallocated/DFIR-Nexus" not in setup_doc
    assert "https://github.com/Ganron007/DFIR-Nexus.git" in setup_doc

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Tailwind" not in readme
    assert "npm run test:unit" not in readme
    assert readme.count("(Docs/ARCHITECTURE.md)") == 1
    assert "src/nexus/data/knowledge/discipline/rules.yaml" in readme
    assert "4,631 Python tests passed (0 failed, 43 skipped)" in readme
    assert "226 Vitest unit & journey tests passed (43 files)" in readme
