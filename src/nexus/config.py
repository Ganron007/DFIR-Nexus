"""Configuration management for DFIR-Nexus.

Reads from environment variables with NEXUS_ prefix, and from
~/.nexus/config.yaml. Falls back to sensible defaults.
"""

import os
from pathlib import Path

import yaml
from pydantic import BaseModel


class Settings(BaseModel):
    examiner: str = ""
    case_dir: Path = Path.home() / ".nexus" / "active_case"
    cases_root: Path = Path.home() / ".nexus" / "cases"
    data_root: Path = Path.home() / ".nexus" / "data"
    audit_dir: Path = Path.home() / ".nexus" / "audit"

    command_timeout: int = 600
    max_output_bytes: int = 50 * 1024 * 1024
    response_byte_budget: int = 10 * 1024
    preview_lines: int = 50

    tool_paths: list[str] = []
    hayabusa_dir: str = "/opt/hayabusa"
    share_root: str = ""

    gateway_host: str = "127.0.0.1"
    gateway_port: int = 4508
    bearer_token: str = ""

    def update_from_env(self):
        if v := os.environ.get("NEXUS_EXAMINER"):
            self.examiner = v
        if v := os.environ.get("NEXUS_CASE_DIR"):
            self.case_dir = Path(v)
        if v := os.environ.get("NEXUS_CASES_ROOT"):
            self.cases_root = Path(v)
        if v := os.environ.get("NEXUS_COMMAND_TIMEOUT") or os.environ.get("SIFT_TIMEOUT"):
            self.command_timeout = int(v)
        if v := os.environ.get("NEXUS_TOOL_PATHS") or os.environ.get("SIFT_TOOL_PATHS"):
            sep = os.pathsep
            # Accept both ; and : so a Windows path like C:\Tools is not split on ':'
            parts = v.split(";") if os.name == "nt" and ";" in v else v.split(sep)
            self.tool_paths = [p.strip() for p in parts if p.strip()]
        if v := os.environ.get("NEXUS_HAYABUSA_DIR") or os.environ.get("SIFT_HAYABUSA_DIR"):
            self.hayabusa_dir = v
        if v := os.environ.get("NEXUS_SHARE_ROOT"):
            self.share_root = v
        if v := os.environ.get("NEXUS_GATEWAY_HOST"):
            self.gateway_host = v
        if v := os.environ.get("NEXUS_GATEWAY_PORT"):
            self.gateway_port = int(v)
        if v := os.environ.get("NEXUS_BEARER_TOKEN"):
            self.bearer_token = v

    def load_config_file(self):
        config_path = Path.home() / ".nexus" / "config.yaml"
        if not config_path.exists():
            return
        try:
            with open(config_path, encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            return
        if not isinstance(cfg, dict):
            return
        if v := cfg.get("examiner"):
            self.examiner = v
        if v := cfg.get("cases_root"):
            self.cases_root = Path(v)
        if v := cfg.get("data_root"):
            self.data_root = Path(v)
        if v := cfg.get("command_timeout"):
            self.command_timeout = v
        if v := cfg.get("tool_paths"):
            self.tool_paths = v
        if v := cfg.get("gateway_host"):
            self.gateway_host = v
        if v := cfg.get("gateway_port"):
            self.gateway_port = v


settings = Settings()
settings.update_from_env()
settings.load_config_file()
