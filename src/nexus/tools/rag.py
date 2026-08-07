"""RAG knowledge search — real ChromaDB semantic search over IR knowledge base.

Downloads a pre-built index (~23K records, ~50MB) from GitHub releases, or
builds from YAML data. Searches cover: Sigma rules, MITRE ATT&CK, Atomic Red
Team, Splunk, KAPE, Velociraptor, LOLBAS, GTFOBins, and more.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter
from nexus.config import settings

logger = logging.getLogger(__name__)

try:
    import chromadb
    from sentence_transformers import SentenceTransformer
    _HAS_RAG = True
except ImportError:
    _HAS_RAG = False

MAX_TEXT_LENGTH = 1500
MAX_TOP_K = 50
MAX_RETRIEVE = 500
DEFAULT_MODEL_NAME = "BAAI/bge-base-en-v1.5"
ALLOWED_MODELS = frozenset({
    "BAAI/bge-base-en-v1.5", "BAAI/bge-small-en-v1.5", "BAAI/bge-large-en-v1.5",
    "sentence-transformers/all-MiniLM-L6-v2", "sentence-transformers/all-mpnet-base-v2",
})

MITRE_ID_PATTERN = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)

REPO = "AppliedIR/sift-mcp"
CHUNK_SIZE = 1024 * 1024
_ASSETS = ("rag-index.tar.zst", "rag-checksums.sha256")


def _get_index_dir() -> Path:
    return settings.data_root / "rag"


def _check_rag_available() -> tuple[bool, str]:
    if not _HAS_RAG:
        return False, "RAG dependencies not installed. Install: pip install dfir-nexus[rag]"
    return True, ""


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        try:
            result = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                token = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _fetch_latest_release() -> dict:
    headers = _github_headers()
    url = f"https://api.github.com/repos/{REPO}/releases?per_page=100"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        releases = json.loads(resp.read())
        matching = [
            r for r in releases
            if r["tag_name"].startswith("rag-index-")
            and any(a["name"] == "rag-index.tar.zst" for a in r.get("assets", []))
        ]
        if matching:
            return matching[0]
        raise ValueError("No RAG index releases found")


def _download_asset(url: str, dest: Path) -> None:
    headers = _github_headers()
    headers["Accept"] = "application/octet-stream"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=300) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total > 0:
                    pct = downloaded * 100 // total
                    mb = downloaded / (1024 * 1024)
                    print(f"\r  {dest.name}: {mb:.1f} MB ({pct}%)", end="", flush=True)
        print()


def _verify_checksums(temp_dir: Path) -> bool:
    checksum_file = temp_dir / "rag-checksums.sha256"
    if not checksum_file.is_file():
        return True
    ok = True
    for line in checksum_file.read_text().strip().splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        expected = parts[0]
        fname = parts[1]
        fpath = temp_dir / fname
        if not fpath.is_file():
            continue
        actual = hashlib.sha256(fpath.read_bytes()).hexdigest()
        if actual == expected:
            print(f"  OK: {fname}")
        else:
            print(f"  FAILED: {fname}")
            ok = False
    return ok


def _extract_bundle(src: Path, dest: Path) -> None:
    import zstandard as zstd
    dctx = zstd.ZstdDecompressor()
    with open(src, "rb") as compressed:
        with dctx.stream_reader(compressed) as reader:
            with tarfile.open(fileobj=reader, mode="r|") as tar:
                if hasattr(tarfile, "data_filter"):
                    tar.extractall(path=dest, filter="data")
                else:
                    tar.extractall(path=dest)


def _verify_index(data_dir: Path) -> bool:
    chroma_path = data_dir / "chroma"
    if not chroma_path.exists():
        print("  ChromaDB directory not found")
        return False
    try:
        client = chromadb.PersistentClient(path=str(chroma_path))
        collection = client.get_collection("ir_knowledge")
        count = collection.count()
        if count < 20000:
            print(f"  Only {count:,} records (expected 20,000+)")
            return False
        print(f"  Collection: {count:,} records")
        return True
    except Exception as e:
        print(f"  ChromaDB load failed: {e}")
        return False


class RAGIndex:
    def __init__(self, index_dir: Path | None = None):
        self.index_dir = index_dir or _get_index_dir()
        self.model: SentenceTransformer | None = None
        self.collection: Any = None
        self.available_sources: list[str] = []
        self._mitre_lookup: dict[str, str] = {}
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        if self._loaded:
            return
        logger.info("Loading RAG index...")
        chroma_path = self.index_dir / "chroma"
        if not chroma_path.exists():
            raise FileNotFoundError(
                "RAG index not found. Run forensic_rag_rebuild() or "
                "forensic_rag_download() to install."
            )
        self.model = SentenceTransformer(DEFAULT_MODEL_NAME)
        client = chromadb.PersistentClient(path=str(chroma_path))
        self.collection = client.get_collection("ir_knowledge")
        self._load_available_sources()
        self._load_mitre_lookup()
        count = self.collection.count()
        logger.info(f"Ready: {count} records from {len(self.available_sources)} sources")
        self._loaded = True

    def _load_available_sources(self) -> None:
        metadata_file = self.index_dir / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, encoding="utf-8") as f:
                    meta = json.load(f)
                    self.available_sources = meta.get("sources", [])
                    if self.available_sources:
                        return
            except (OSError, json.JSONDecodeError):
                pass
        if self.collection is None:
            return
        results = self.collection.get(include=["metadatas"])
        sources: set[str] = set()
        for m in results["metadatas"]:
            if m and "source" in m:
                sources.add(m["source"])
        self.available_sources = sorted(sources)

    def _load_mitre_lookup(self) -> None:
        sources_dir = self.index_dir / "sources"
        mitre_jsonl = sources_dir / "mitre_attack.jsonl"
        if not mitre_jsonl.exists():
            return
        lookup: dict[str, str] = {}
        try:
            with open(mitre_jsonl, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        meta = record.get("metadata", {})
                        title = meta.get("title", "")
                        tid = meta.get("mitre_techniques", "")
                        if tid and title and re.match(r"^T\d{4}(\.\d{3})?$", tid.strip().upper()):
                            if not title.endswith(" Mitigation"):
                                lookup[tid.strip().upper()] = title
                    except json.JSONDecodeError:
                        continue
        except OSError:
            pass
        self._mitre_lookup = lookup

    def _augment_query(self, query: str) -> str:
        if not self._mitre_lookup:
            return query
        def replace_id(m: re.Match) -> str:
            tid = m.group(1).upper()
            if tid in self._mitre_lookup:
                return f"{tid} {self._mitre_lookup[tid]}"
            return m.group(0)
        return MITRE_ID_PATTERN.sub(replace_id, query)

    def _get_matching_sources(self, source_filter: str | None) -> list[str]:
        if not source_filter:
            return self.available_sources
        sf = source_filter.lower()
        return [s for s in self.available_sources if sf in s.lower() or s.lower() in sf]

    def search(
        self,
        query: str,
        top_k: int = 5,
        source: str | None = None,
        source_ids: list[str] | None = None,
        technique: str | None = None,
        platform: str | None = None,
    ) -> dict[str, Any]:
        if not self._loaded:
            self.load()
        if not isinstance(top_k, int) or top_k < 1:
            top_k = 5
        elif top_k > MAX_TOP_K:
            top_k = MAX_TOP_K

        augmented = self._augment_query(query)
        retrieve_k = top_k
        if source or source_ids or technique or platform:
            retrieve_k = min(MAX_RETRIEVE, top_k * 50)

        query_emb = self.model.encode(augmented).tolist()
        results = self.collection.query(
            query_embeddings=[query_emb],
            n_results=retrieve_k,
            include=["documents", "metadatas", "distances"],
        )

        source_ids_set = set(source_ids) if source_ids else None
        matched_sources = self._get_matching_sources(source.lower() if source and not source_ids else None)

        formatted = []
        for i in range(len(results["ids"][0])):
            doc = results["documents"][0][i]
            meta = results["metadatas"][0][i]
            distance = results["distances"][0][i]
            score = 1 - distance

            result_source = meta.get("source", "")
            if source_ids_set:
                if result_source not in source_ids_set:
                    continue
            elif source:
                sl = result_source.lower()
                sf = source.lower()
                if sf not in sl and sl not in sf:
                    continue

            if technique:
                t_str = meta.get("mitre_techniques", "")
                if technique.upper() not in t_str.upper():
                    continue
            if platform:
                p_str = meta.get("platform", "")
                if platform.lower() not in p_str.lower():
                    continue

            formatted.append({
                "rank": 0,
                "score": round(score, 3),
                "source": result_source or "unknown",
                "mitre_techniques": meta.get("mitre_techniques", ""),
                "platform": meta.get("platform", ""),
                "title": meta.get("title", ""),
                "text": doc[:MAX_TEXT_LENGTH],
            })

        formatted.sort(key=lambda x: x["score"], reverse=True)
        formatted = formatted[:top_k]
        for i, r in enumerate(formatted):
            r["rank"] = i + 1

        return {
            "results": formatted,
            "source_filter": source.lower() if source and not source_ids else None,
            "source_ids": list(source_ids_set) if source_ids_set else None,
            "matched_sources": matched_sources if source and not source_ids else None,
        }

    def get_stats(self) -> dict[str, Any]:
        if not self._loaded:
            self.load()
        return {
            "document_count": self.collection.count(),
            "source_count": len(self.available_sources),
            "sources": self.available_sources,
            "model": DEFAULT_MODEL_NAME,
        }


_global_index: RAGIndex | None = None


def _get_index() -> RAGIndex:
    global _global_index
    if _global_index is None:
        _global_index = RAGIndex()
    return _global_index


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def forensic_rag_search(
        query: str,
        top_k: int = 10,
        source: str = "",
        source_ids: list[str] | None = None,
        technique: str = "",
        platform: str = "",
    ) -> list:
        """Semantic search across the forensic knowledge base (~23K records).

        Covers: Sigma rules, MITRE ATT&CK, Atomic Red Team, Splunk,
        KAPE, Velociraptor, LOLBAS, GTFOBins.

        Examples:
            forensic_rag_search("credential dumping detection")
            forensic_rag_search("T1003", technique="T1003")
            forensic_rag_search("lateral movement", platform="windows")
            forensic_rag_search("sigma rules for powershell", source="sigma")

        Args:
            query: Natural language search query (e.g. 'credential dumping detection')
            top_k: Number of results (default: 10, max: 50)
            source: Filter by source name (e.g. 'sigma')
            source_ids: Exact source IDs to filter (takes precedence over source)
            technique: Filter by MITRE technique ID (e.g. 'T1003')
            platform: Filter by platform (windows, linux, macos)
        """
        available, msg = _check_rag_available()
        if not available:
            return [{"error": msg}]

        from nexus.audit import resolve_examiner

        audit_id = audit.log(
            tool="forensic_rag_search",
            params={"query": query[:200], "top_k": top_k},
            result_summary={"status": "searched"},
        )

        idx = _get_index()
        try:
            result = idx.search(
                query=query,
                top_k=top_k,
                source=source or None,
                source_ids=source_ids,
                technique=technique or None,
                platform=platform or None,
            )
            response = {
                "status": "ok",
                "query": query,
                "results": result.get("results", []),
                "audit_id": audit_id or audit.last_audit_id or "",
                "examiner": resolve_examiner(),
                "caveats": [
                    "Search results are semantic (vector) matches, not exact keyword matches",
                    "Relevance scores above 0.85 are excellent; 0.75-0.84 are good",
                ],
                "interpretation_constraint": "Scores are cosine similarity (0-1). Higher is better.",
            }
            if result.get("matched_sources"):
                response["matched_sources"] = result["matched_sources"]
            if result.get("source_filter"):
                response["source_filter_applied"] = result["source_filter"]
            return response
        except FileNotFoundError as e:
            return {"status": "error", "query": query, "error": str(e)}
        except Exception as e:
            logger.exception("RAG search failed")
            return {"status": "error", "query": query, "error": f"Search failed: {e}"}

    @server.tool()
    def forensic_rag_status() -> dict:
        """Check RAG index status and statistics."""
        available, msg = _check_rag_available()
        if not available:
            return {"status": "unavailable", "message": msg}

        idx_dir = _get_index_dir()
        chroma_path = idx_dir / "chroma"
        if not chroma_path.exists():
            return {"status": "not_initialized", "records": 0}

        idx = _get_index()
        try:
            stats = idx.get_stats()
            return {"status": "ready", **stats}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @server.tool()
    def forensic_rag_rebuild(data_dir: str = "") -> dict:
        """Local source-to-index rebuild (deferred).

        Building a fresh index from the 23 upstream sources requires a
        dedicated ingest pipeline that is not yet part of the standalone
        package. For now, use `forensic_rag_download()` to fetch the
        pre-built index.

        Args:
            data_dir: Optional custom data directory for sources cache
        """
        available, msg = _check_rag_available()
        if not available:
            return {"status": "failed", "error": msg}

        audit.log(
            tool="forensic_rag_rebuild",
            params={"data_dir": data_dir},
            result_summary={"status": "deferred"},
        )
        return {
            "status": "deferred",
            "message": (
                "Local source-to-index rebuild is not yet implemented in the "
                "standalone package. Use forensic_rag_download() for the "
                "pre-built index."
            ),
        }

    @server.tool()
    def forensic_rag_download(tag: str = "latest") -> dict:
        """Download pre-built RAG index from GitHub releases (~50MB).

        Downloads a ChromaDB bundle with 23K+ records from 23 authoritative
        IR sources. Much faster than building from scratch.

        Args:
            tag: Release tag (default: 'latest', or specific tag like 'rag-index-v1')
        """
        available, msg = _check_rag_available()
        if not available:
            return {"status": "failed", "error": msg}

        audit.log(
            tool="forensic_rag_download",
            params={"tag": tag},
            result_summary={"status": "downloading"},
        )

        dest = _get_index_dir()
        dest.mkdir(parents=True, exist_ok=True)

        print(f"Fetching release info from {REPO}...")
        try:
            if tag == "latest":
                release = _fetch_latest_release()
            else:
                headers = _github_headers()
                url = f"https://api.github.com/repos/{REPO}/releases/tags/{tag}"
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    release = json.loads(resp.read())
        except Exception as e:
            return {"status": "failed", "error": f"Failed to fetch release: {e}"}

        tag_name = release.get("tag_name", tag)
        print(f"Release: {tag_name}")

        temp_dir = Path(tempfile.mkdtemp(prefix="rag-index-"))
        try:
            for asset_name in _ASSETS:
                url = None
                for a in release.get("assets", []):
                    if a["name"] == asset_name:
                        url = a["url"]
                        break
                if not url:
                    continue
                try:
                    _download_asset(url, temp_dir / asset_name)
                except Exception as e:
                    return {"status": "failed", "error": f"Download failed: {e}"}

            if not _verify_checksums(temp_dir):
                return {"status": "failed", "error": "Checksum verification failed"}

            bundle = temp_dir / "rag-index.tar.zst"
            if bundle.exists():
                print("Extracting bundle...")
                _extract_bundle(bundle, dest)

            if not _verify_index(dest):
                return {"status": "failed", "error": "Index verification failed"}

            print("RAG index installed successfully.")
            idx = _get_index()
            stats = idx.get_stats()
            return {"status": "success", "tag": tag_name, **stats}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    @server.tool()
    def forensic_rag_list_sources() -> list:
        """List all available knowledge sources in the RAG index."""
        available, msg = _check_rag_available()
        if not available:
            return [{"error": msg}]

        idx = _get_index()
        try:
            if not idx.is_loaded:
                idx.load()
            return sorted(idx.available_sources)
        except FileNotFoundError:
            return []
        except Exception as e:
            return [{"error": str(e)}]
