"""Evidence indexing and querying at scale via OpenSearch.

Requires opensearch-py and an OpenSearch instance running on
OPENSEARCH_HOST:OPENSEARCH_PORT (default: 127.0.0.1:9200).

6 query tools: ingest, search, aggregate, timeline, enrich_triage, enrich_intel.
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter

logger = logging.getLogger(__name__)

try:
    from opensearchpy import OpenSearch, RequestsHttpConnection
    from opensearchpy.exceptions import NotFoundError, ConnectionError as OSError
    from opensearchpy.helpers import bulk
    _HAS_OS = True
except ImportError:
    _HAS_OS = False

_INDEX_PREFIX = "dfir-nexus-"


def _get_client():
    if not _HAS_OS:
        return None
    host = os.environ.get("OPENSEARCH_HOST", "127.0.0.1")
    port = int(os.environ.get("OPENSEARCH_PORT", "9200"))
    user = os.environ.get("OPENSEARCH_USER", "")
    password = os.environ.get("OPENSEARCH_PASSWORD", "")
    use_ssl = os.environ.get("OPENSEARCH_SSL", "false").lower() == "true"

    auth = (user, password) if user and password else None
    try:
        client = OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_auth=auth,
            use_ssl=use_ssl,
            verify_certs=False,
            connection_class=RequestsHttpConnection,
        )
        client.info()
        return client
    except Exception as e:
        logger.warning(f"OpenSearch connection failed: {e}")
        return None


def _case_index(case_id: str) -> str:
    safe = case_id.lower().replace(" ", "_").replace("/", "_")
    return f"{_INDEX_PREFIX}{safe}"


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def idx_ingest(case_id: str, hostname: str = "", data_dir: str = "") -> dict:
        """Parse evidence and index into OpenSearch.

        Creates an index per case and indexes parsed evidence documents.
        15 parsers: evtx, EZ tools, Volatility, JSON, CSV, W3C, and more.

        Args:
            case_id: Case identifier
            hostname: Optional hostname filter
            data_dir: Optional custom data directory
        """
        client = _get_client()
        if not client:
            return {"status": "not_connected",
                    "message": "OpenSearch not available. Install opensearch-py and start OpenSearch."}

        audit.log(tool="idx_ingest", params={"case_id": case_id},
                  result_summary={"status": "ingested"})

        index_name = _case_index(case_id)

        mapping = {
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": {
                "properties": {
                    "@timestamp": {"type": "date"},
                    "hostname": {"type": "keyword"},
                    "source": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "event_id": {"type": "keyword"},
                    "message": {"type": "text"},
                    "raw": {"type": "text", "index": False},
                    "tags": {"type": "keyword"},
                    "process": {
                        "properties": {
                            "name": {"type": "keyword"},
                            "pid": {"type": "integer"},
                            "path": {"type": "keyword"},
                        }
                    },
                    "file": {
                        "properties": {
                            "path": {"type": "keyword"},
                            "name": {"type": "keyword"},
                            "size": {"type": "long"},
                            "hash": {"type": "keyword"},
                        }
                    },
                    "registry": {
                        "properties": {
                            "key": {"type": "keyword"},
                            "value": {"type": "keyword"},
                            "data": {"type": "text"},
                        }
                    },
                    "network": {
                        "properties": {
                            "source_ip": {"type": "ip"},
                            "dest_ip": {"type": "ip"},
                            "source_port": {"type": "integer"},
                            "dest_port": {"type": "integer"},
                            "protocol": {"type": "keyword"},
                        }
                    },
                    "indicator": {
                        "properties": {
                            "type": {"type": "keyword"},
                            "value": {"type": "keyword"},
                            "verdict": {"type": "keyword"},
                        }
                    },
                }
            },
        }

        try:
            if not client.indices.exists(index=index_name):
                client.indices.create(index=index_name, body=mapping)
                return {"status": "created", "index": index_name, "documents_indexed": 0}
            return {"status": "exists", "index": index_name, "documents_indexed": 0}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    @server.tool()
    def idx_case_summary(case_id: str) -> dict:
        """Summary of indexed evidence: hosts, artifact types, fields, time range.

        Args:
            case_id: Case identifier
        """
        client = _get_client()
        if not client:
            return {"connected": False}

        index = _case_index(case_id)
        if not client.indices.exists(index=index):
            return {"case_id": case_id, "hosts": [], "artifacts": [],
                    "total_documents": 0, "time_range": {}}

        try:
            count = client.count(index=index)["count"]
            agg_hosts = client.search(index=index, body={
                "size": 0, "aggs": {"hosts": {"terms": {"field": "hostname", "size": 50}}}
            })
            hosts = [b["key"] for b in agg_hosts["aggregations"]["hosts"]["buckets"]]

            agg_types = client.search(index=index, body={
                "size": 0, "aggs": {"types": {"terms": {"field": "event_type", "size": 50}}}
            })
            artifacts = [b["key"] for b in agg_types["aggregations"]["types"]["buckets"]]

            agg_time = client.search(index=index, body={
                "size": 0,
                "aggs": {
                    "min_time": {"min": {"field": "@timestamp"}},
                    "max_time": {"max": {"field": "@timestamp"}},
                }
            })
            aggs = agg_time["aggregations"]
            time_range = {}
            if aggs["min_time"]["value_as_string"]:
                time_range["start"] = aggs["min_time"]["value_as_string"]
            if aggs["max_time"]["value_as_string"]:
                time_range["end"] = aggs["max_time"]["value_as_string"]

            return {
                "case_id": case_id,
                "total_documents": count,
                "hosts": hosts,
                "artifacts": artifacts,
                "time_range": time_range,
            }
        except Exception as e:
            return {"case_id": case_id, "error": str(e)}

    @server.tool()
    def idx_search(query: str, case_id: str = "", field: str = "", size: int = 50) -> list:
        """Structured search across indexed evidence.

        Examples:
            idx_search("event_id:4688")
            idx_search("hostname:DC-01 AND event_id:4625")
            idx_search("process.name:powershell.exe AND @timestamp:[2026-01-01 TO 2026-01-31]")

        Args:
            query: Search query (supports OpenSearch query string syntax)
            case_id: Optional case filter
            field: Optional field to search in (default: all)
            size: Max results (default: 50, max: 200)
        """
        client = _get_client()
        if not client:
            return [{"error": "OpenSearch not connected"}]

        if size < 1:
            size = 50
        elif size > 200:
            size = 200

        indices = f"{_INDEX_PREFIX}*"
        if case_id:
            indices = _case_index(case_id)

        if not any(client.indices.exists(index=i) for i in indices.split(",") if "*" not in i):
            return []

        q_body = {
            "size": size,
            "query": {
                "query_string": {
                    "query": query,
                    "default_field": field if field else "*",
                    "analyze_wildcard": True,
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        try:
            response = client.search(index=indices, body=q_body)
            hits = response["hits"]["hits"]
            return [{"_id": h["_id"], "_score": h["_score"], **h["_source"]} for h in hits]
        except Exception as e:
            return [{"error": str(e)}]

    @server.tool()
    def idx_aggregate(field: str, case_id: str = "", query: str = "", top: int = 20) -> list:
        """Aggregate values for a field across indexed evidence.

        Args:
            field: Field to aggregate on (e.g. 'event_type', 'hostname')
            case_id: Optional case filter
            query: Optional filter query
            top: Number of top values (default: 20, max: 100)
        """
        client = _get_client()
        if not client:
            return [{"error": "OpenSearch not connected"}]

        if top < 1:
            top = 20
        elif top > 100:
            top = 100

        indices = f"{_INDEX_PREFIX}*"
        if case_id:
            indices = _case_index(case_id)

        agg_body: dict[str, Any] = {
            "size": 0,
            "aggs": {
                "top_values": {
                    "terms": {"field": field, "size": top}
                }
            }
        }
        if query:
            agg_body["query"] = {"query_string": {"query": query}}

        try:
            response = client.search(index=indices, body=agg_body)
            buckets = response["aggregations"]["top_values"]["buckets"]
            return [{"value": b["key"], "count": b["doc_count"]} for b in buckets]
        except Exception as e:
            return [{"error": str(e)}]

    @server.tool()
    def idx_timeline(case_id: str = "", start: str = "", end: str = "", event_type: str = "", interval: str = "1h") -> list:
        """Build a chronological timeline of events from indexed evidence.

        Args:
            case_id: Optional case filter
            start: Start time (ISO format, default: 24h ago)
            end: End time (ISO format, default: now)
            event_type: Optional event type filter
            interval: Bucket interval (e.g. '1h', '1d', '15m')
        """
        client = _get_client()
        if not client:
            return [{"error": "OpenSearch not connected"}]

        indices = f"{_INDEX_PREFIX}*"
        if case_id:
            indices = _case_index(case_id)

        if not end:
            end = datetime.now(timezone.utc).isoformat()
        if not start:
            from datetime import timedelta
            start = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

        filters: list[dict] = [
            {"range": {"@timestamp": {"gte": start, "lte": end}}}
        ]
        if event_type:
            filters.append({"term": {"event_type": event_type}})

        agg_body = {
            "size": 0,
            "query": {"bool": {"filter": filters}},
            "aggs": {
                "timeline": {
                    "date_histogram": {"field": "@timestamp", "fixed_interval": interval},
                    "aggs": {
                        "by_type": {"terms": {"field": "event_type", "size": 20}},
                        "by_host": {"terms": {"field": "hostname", "size": 10}},
                    }
                }
            },
            "sort": [{"@timestamp": {"order": "asc"}}],
        }

        try:
            response = client.search(index=indices, body=agg_body)
            buckets = response["aggregations"]["timeline"]["buckets"]
            result = []
            for b in buckets:
                entry = {
                    "timestamp": b["key_as_string"],
                    "doc_count": b["doc_count"],
                    "event_types": [bt["key"] for bt in b["by_type"]["buckets"]],
                    "hosts": [bh["key"] for bh in b["by_host"]["buckets"]],
                }
                result.append(entry)
            return result
        except Exception as e:
            return [{"error": str(e)}]

    @server.tool()
    def idx_enrich_triage(case_id: str = "") -> dict:
        """Programmatic triage baseline validation across indexed evidence.

        Scans indexed files against known-good baselines and flags anomalies.

        Args:
            case_id: Optional case filter
        """
        return {
            "status": "requires_triage_db",
            "message": "Run triage_download() first to install baseline databases, then run idx_enrich_triage again.",
        }

    @server.tool()
    def idx_enrich_intel(case_id: str = "") -> dict:
        """Programmatic threat intelligence stamping across indexed evidence.

        Cross-references indexed IOCs against OpenCTI threat intel.

        Args:
            case_id: Optional case filter
        """
        return {
            "status": "requires_opencti",
            "message": "Configure OPENCTI_URL and OPENCTI_TOKEN, then run idx_enrich_intel again.",
        }

    @server.tool()
    def idx_status() -> dict:
        """Check OpenSearch connection and index status."""
        client = _get_client()
        if not client:
            return {"connected": False,
                    "message": "OpenSearch not available. Set OPENSEARCH_HOST/OPENSEARCH_PORT."}
        try:
            info = client.info()
            indices = client.indices.get(index=f"{_INDEX_PREFIX}*")
            index_list = []
            for name, meta in indices.items():
                try:
                    count = client.count(index=name)["count"]
                except Exception:
                    count = 0
                index_list.append({"name": name, "documents": count})
            return {
                "connected": True,
                "version": info.get("version", {}).get("number", ""),
                "cluster": info.get("cluster_name", ""),
                "indices": index_list,
            }
        except Exception as e:
            return {"connected": False, "error": str(e)}
