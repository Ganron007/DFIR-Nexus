"""AI vision — screenshot/image analysis via LLM.

Uses the LLM router (with a vision-capable model) to analyze screenshots
and images registered as evidence.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus.llm.router import LLMRouter
from nexus.utils.paths import resolve_read_path

log = logging.getLogger(__name__)


class VisionError(Exception):
    """Raised when vision analysis fails."""


@dataclass
class VisionResult:
    """Result of analyzing an image."""

    file_path: str
    file_name: str
    file_size: int
    mime_type: str
    description: str
    text_extracted: str = ""
    iocs: list[str] = field(default_factory=list)
    technique_ids: list[str] = field(default_factory=list)
    error: str | None = None
    llm_model: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "mime_type": self.mime_type,
            "description": self.description,
            "text_extracted": self.text_extracted,
            "ioc_count": len(self.iocs),
            "iocs": self.iocs[:50],
            "technique_ids": self.technique_ids,
            "error": self.error,
            "llm_model": self.llm_model,
            "timestamp": self.timestamp.isoformat(),
        }


IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ipv4_port": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "url": re.compile(r"https?://[^\s<>\"]+"),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE),
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "btc": re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
    "ipfs": re.compile(r"\bQm[1-9A-HJ-NP-Za-km-z]{44}\b"),
    "registry_key": re.compile(r"HKEY_[A-Z_]+\\[^\s\"']+"),
    "file_path_win": re.compile(r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"),
    "file_path_unix": re.compile(r"(?:/[\w.-]+)+"),
    "guid": re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "mitre": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}


def extract_iocs_from_text(text: str) -> dict[str, list[str]]:
    """Extract IoCs from text using regex patterns."""
    found: dict[str, set[str]] = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = pattern.findall(text)
        if matches:
            found[ioc_type] = set()
            for m in matches:
                if isinstance(m, tuple):
                    m = m[0]
                found[ioc_type].add(m)
    return {k: sorted(v) for k, v in found.items()}


def detect_mime_type(path: Path) -> str:
    """Guess MIME type from file extension."""
    suffix = path.suffix.lower()
    types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".bmp": "image/bmp",
        ".tiff": "image/tiff",
        ".svg": "image/svg+xml",
        ".pdf": "application/pdf",
    }
    return types.get(suffix, "application/octet-stream")


class VisionAnalyzer:
    """Analyze images using a vision-capable LLM via OpenAI-compatible API."""

    DEFAULT_MODEL = "gpt-4o"

    def __init__(
        self,
        llm_router: LLMRouter | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 2000,
        temperature: float = 0.1,
    ) -> None:
        self.llm_router = llm_router
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature

    def _build_prompt(self) -> str:
        return """Analyze this image for forensic indicators. Extract and return:

1. **Description**: What is shown in the image? (1-2 sentences)
2. **Text content**: Any visible text, error messages, dialog boxes, command lines
3. **IoCs**: IP addresses, URLs, domain names, file paths, registry keys, hashes, BTC addresses
4. **MITRE techniques**: If you see any attacker activity or suspicious behavior, list the relevant MITRE ATT&CK technique IDs

Format your response as JSON with keys: "description", "text", "iocs" (array), "techniques" (array of technique IDs like "T1003.001").

If the image is not relevant or is just a UI screenshot with no security context, return a brief description and empty arrays."""

    def analyze_file(self, path: str | Path) -> VisionResult:
        """Analyze a single image file."""
        path = Path(path)
        try:
            resolve_read_path(path)
        except ValueError as exc:
            return VisionResult(
                file_path=str(path),
                file_name=path.name,
                file_size=0,
                mime_type="",
                description="",
                error=f"Path sandbox rejected: {exc}",
            )

        if not path.exists():
            return VisionResult(
                file_path=str(path),
                file_name=path.name,
                file_size=0,
                mime_type="",
                description="",
                error=f"File not found: {path}",
            )

        file_size = path.stat().st_size
        mime_type = detect_mime_type(path)

        if self.llm_router is None:
            return VisionResult(
                file_path=str(path),
                file_name=path.name,
                file_size=file_size,
                mime_type=mime_type,
                description="",
                error="No LLM router configured — vision analysis requires a vision-capable LLM",
            )

        try:
            image_data = base64.b64encode(path.read_bytes()).decode("ascii")
        except OSError as e:
            return VisionResult(
                file_path=str(path),
                file_name=path.name,
                file_size=file_size,
                mime_type=mime_type,
                description="",
                error=f"Failed to read file: {e}",
            )

        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": self._build_prompt()},
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{mime_type};base64,{image_data}",
                        },
                    },
                ],
            }
        ]

        try:
            import asyncio
            response = asyncio.run(
                self.llm_router.chat(
                    messages=messages,
                    model=self.model,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
            )
        except Exception as e:
            return VisionResult(
                file_path=str(path),
                file_name=path.name,
                file_size=file_size,
                mime_type=mime_type,
                description="",
                error=f"LLM call failed: {e}",
                llm_model=self.model,
            )

        content = response.content.strip()
        parsed: dict[str, Any] = {}
        try:
            if content.startswith("{"):
                parsed = json.loads(content)
            else:
                start = content.find("{")
                end = content.rfind("}") + 1
                if start >= 0 and end > start:
                    parsed = json.loads(content[start:end])
                else:
                    parsed = {"description": content, "text": "", "iocs": [], "techniques": []}
        except json.JSONDecodeError:
            parsed = {"description": content, "text": "", "iocs": [], "techniques": []}

        description = parsed.get("description", "")
        text_extracted = parsed.get("text", "")
        llm_iocs = parsed.get("iocs", [])
        techniques = parsed.get("techniques", [])

        combined_text = text_extracted + " " + " ".join(str(i) for i in llm_iocs)
        regex_iocs = extract_iocs_from_text(combined_text)
        all_iocs = list(llm_iocs)
        for ioc_list in regex_iocs.values():
            for ioc in ioc_list:
                if ioc not in all_iocs:
                    all_iocs.append(ioc)

        return VisionResult(
            file_path=str(path),
            file_name=path.name,
            file_size=file_size,
            mime_type=mime_type,
            description=description,
            text_extracted=text_extracted,
            iocs=all_iocs,
            technique_ids=techniques,
            llm_model=self.model,
        )

    def analyze_artifact(self, artifact: Any) -> VisionResult:
        """Analyze an Artifact that has a file_path pointing to an image."""
        file_path = getattr(artifact, "file_path", None) or ""
        if not file_path:
            return VisionResult(
                file_path="",
                file_name="(no path)",
                file_size=0,
                mime_type="",
                description="",
                error="Artifact has no file_path",
            )
        return self.analyze_file(file_path)


_vision_analyzer: VisionAnalyzer | None = None


def get_vision_analyzer() -> VisionAnalyzer:
    """Get the singleton VisionAnalyzer (no LLM by default)."""
    global _vision_analyzer
    if _vision_analyzer is None:
        _vision_analyzer = VisionAnalyzer()
    return _vision_analyzer


def set_vision_analyzer(analyzer: VisionAnalyzer) -> None:
    """Set the singleton VisionAnalyzer (with LLM)."""
    global _vision_analyzer
    _vision_analyzer = analyzer
