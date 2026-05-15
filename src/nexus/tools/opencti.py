"""Threat intelligence — IOC lookup, threat actor/malware/report search via OpenCTI.

Requires pycti and an OpenCTI server configured via OPENCTI_URL and
OPENCTI_TOKEN environment variables.

Exposes 8 tools matching the original opencti-mcp server.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from mcp.server.fastmcp import FastMCP

from nexus.audit import AuditWriter

logger = logging.getLogger(__name__)

try:
    from pycti import OpenCTIApiClient
    _HAS_CTI = True
except ImportError:
    _HAS_CTI = False

_RETRY_MAX = 3
_RETRY_BACKOFF = 1.5


def _get_cti_client():
    if not _HAS_CTI:
        return None
    url = os.environ.get("OPENCTI_URL") or os.environ.get("NEXUS_OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN") or os.environ.get("NEXUS_OPENCTI_TOKEN")
    if not url or not token:
        return None
    try:
        return OpenCTIApiClient(url, token)
    except Exception as e:
        logger.warning(f"OpenCTI connection failed: {e}")
        return None


def _cti_retry(client, method_name: str, *args, **kwargs):
    """Call a pycti client method with exponential backoff retry.

    Args:
        client: OpenCTIApiClient instance
        method_name: Method name to call (e.g. 'indicator.read')
        *args: Positional args passed to the method
        **kwargs: Keyword args passed to the method

    Returns:
        Method result, or None if all retries exhausted.
    """
    import time as _time
    method = getattr(client, method_name, None)
    if method is None:
        # Handle dotted method names (e.g. 'indicator.read')
        parts = method_name.split(".")
        obj = client
        for part in parts:
            obj = getattr(obj, part, None)
            if obj is None:
                break
        method = obj
    if method is None:
        logger.warning(f"OpenCTI method not found: {method_name}")
        return None

    last_error = None
    for attempt in range(1, _RETRY_MAX + 1):
        try:
            return method(*args, **kwargs)
        except Exception as e:
            last_error = e
            if attempt < _RETRY_MAX:
                delay = _RETRY_BACKOFF ** attempt
                logger.debug(f"OpenCTI {method_name} attempt {attempt} failed, retrying in {delay:.1f}s: {e}")
                _time.sleep(delay)
            else:
                logger.warning(f"OpenCTI {method_name} failed after {_RETRY_MAX} attempts: {e}")
    return None


def _cti_safe_call(method_name: str, *args, **kwargs):
    """Safely call an OpenCTI method with retry and error handling.

    Returns the result dict on success, or {"error": str(e)} on failure.
    Handles None client gracefully.
    """
    client = _get_cti_client()
    if not client:
        return {"connected": False, "message": "OpenCTI not configured. Set OPENCTI_URL and OPENCTI_TOKEN."}
    result = _cti_retry(client, method_name, *args, **kwargs)
    if result is None:
        return {"error": f"OpenCTI call failed after retries: {method_name}"}
    return result


def _safe_results(results: list | None) -> list:
    return results if results is not None else []


def _detect_ioc_type(value: str) -> str:
    import re
    value = value.strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value):
        return "IPv4-Addr"
    if re.match(r"^[0-9a-fA-F]{64}$", value):
        return "File-SHA256"
    if re.match(r"^[0-9a-fA-F]{40}$", value):
        return "File-SHA1"
    if re.match(r"^[0-9a-fA-F]{32}$", value):
        return "File-MD5"
    if "://" in value:
        return "Url"
    if "." in value and " " not in value:
        return "Domain-Name"
    return "Unknown"


def _build_filters(
    confidence_min: int | None = None,
    labels: list[str] | None = None,
    created_after: str = "",
    created_before: str = "",
) -> dict | None:
    filters = []
    if confidence_min is not None:
        filters.append({"key": "confidence", "values": [confidence_min], "operator": "gte"})
    if labels:
        filters.append({"key": "objectLabel", "values": labels, "operator": "eq"})
    if created_after:
        filters.append({"key": "created_at", "values": [created_after], "operator": "gt"})
    if created_before:
        filters.append({"key": "created_at", "values": [created_before], "operator": "lt"})
    if not filters:
        return None
    return {"mode": "and", "filters": filters}


def _list_with_filters(method: Any, query: str, limit: int, offset: int = 0,
                       filters: dict | None = None) -> list:
    kwargs = {"search": query, "first": limit}
    if offset > 0:
        kwargs["offset"] = offset
    if filters:
        kwargs["filters"] = filters
    return _safe_results(method.list(**kwargs))


_ENTITY_TYPE_METHODS = {
    "threat_actor": "threat_actor",
    "malware": "malware",
    "attack_pattern": "attack_pattern",
    "vulnerability": "vulnerability",
    "campaign": "campaign",
    "tool": "tool",
    "infrastructure": "infrastructure",
    "incident": "incident",
    "organization": "organization",
    "sector": "sector",
    "location": "location",
    "course_of_action": "course_of_action",
    "note": "note",
}

VALID_ENTITY_TYPES = sorted(_ENTITY_TYPE_METHODS.keys())


def register_tools(server: FastMCP, audit: AuditWriter):
    @server.tool()
    def opencti_status() -> dict:
        """Check OpenCTI connection status and server health."""
        client = _get_cti_client()
        if not client:
            return {
                "connected": False,
                "message": "OpenCTI not configured. Set OPENCTI_URL and OPENCTI_TOKEN.",
            }
        try:
            client.health()
            return {"connected": True, "status": "healthy"}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    @server.tool()
    def search_threat_intel(
        query: str,
        limit: int = 5,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str = "",
        created_before: str = "",
    ) -> dict:
        """Broad search across all OpenCTI entity types.

        Searches indicators, threat actors, malware, techniques, CVEs, and
        reports. Returns up to limit results per entity type.

        Args:
            query: Search term (IOC, threat actor name, malware, CVE, etc.)
            limit: Max results per entity type (default: 5, max: 20)
            offset: Result offset for pagination
            labels: Optional OpenCTI label filters
            confidence_min: Minimum confidence threshold (0-100)
            created_after: ISO timestamp lower bound
            created_before: ISO timestamp upper bound
        """
        client = _get_cti_client()
        if not client:
            return {"connected": False, "message": "OpenCTI not configured"}

        if limit < 1:
            limit = 5
        elif limit > 20:
            limit = 20
        if offset < 0:
            offset = 0

        filters = _build_filters(confidence_min, labels, created_after, created_before)

        results: dict[str, list] = {}

        try:
            results["indicators"] = _list_with_filters(client.indicator, query, limit, offset, filters)
        except Exception as e:
            results["indicators_error"] = str(e)

        for entity_type in ["threat_actor", "malware", "attack_pattern", "vulnerability", "campaign", "tool"]:
            try:
                method = getattr(client, entity_type)
                results[entity_type] = _list_with_filters(method, query, limit, offset, filters)
            except Exception as e:
                results[f"{entity_type}_error"] = str(e)

        try:
            results["reports"] = _list_with_filters(client.report, query, limit, offset, filters)
        except Exception as e:
            results["reports_error"] = str(e)

        return {"query": query, "limit": limit, "offset": offset, "filters": filters or {}, "results": results}

    @server.tool()
    def search_entity(
        entity_type: str,
        query: str,
        limit: int = 10,
        offset: int = 0,
        labels: list[str] | None = None,
        confidence_min: int | None = None,
        created_after: str = "",
        created_before: str = "",
    ) -> dict:
        """Search OpenCTI entities filtered by a single type.

        More precise than search_threat_intel — returns up to 50 results
        for one entity type.

        Args:
            entity_type: Entity type to search (threat_actor, malware, attack_pattern, vulnerability, campaign, tool, infrastructure, incident, organization, sector, location, course_of_action, note)
            query: Search term
            limit: Max results (default: 10, max: 50)
            offset: Result offset for pagination
        """
        client = _get_cti_client()
        if not client:
            return {"connected": False, "message": "OpenCTI not configured"}

        normalized_type = entity_type.lower().replace(" ", "_")
        if normalized_type not in _ENTITY_TYPE_METHODS:
            return {
                "error": f"Invalid entity type: '{entity_type}'. Valid types: {', '.join(VALID_ENTITY_TYPES)}"
            }

        if limit < 1:
            limit = 10
        elif limit > 50:
            limit = 50
        if offset < 0:
            offset = 0

        filters = _build_filters(confidence_min, labels, created_after, created_before)

        try:
            method = getattr(client, normalized_type)
            results = _list_with_filters(method, query, limit, offset, filters)
            return {"type": normalized_type, "query": query, "results": results,
                    "total": 0, "limit": limit, "offset": offset, "filters": filters or {}}
        except Exception as e:
            return {"type": normalized_type, "error": str(e)}

    @server.tool()
    def lookup_indicator(value: str, type: str = "auto") -> dict:
        """Look up an IOC in OpenCTI threat intelligence with full context.

        Returns related threat actors, malware families, and campaigns.

        Args:
            value: IOC value (IP, hash, domain, URL)
            type: IOC type hint (auto, IPv4-Addr, Domain-Name, Url, File-SHA256, File-MD5, File-SHA1)
        """
        client = _get_cti_client()
        if not client:
            return {"value": value, "verdict": "UNKNOWN", "message": "OpenCTI not configured"}

        ioc_type = type if type != "auto" else _detect_ioc_type(value)

        try:
            indicators = client.indicator.read(
                filters={"mode": "and", "filters": [{"key": "value", "values": [value]}]}
            )
            if indicators and isinstance(indicators, list) and len(indicators) > 0:
                indicator = indicators[0] if isinstance(indicators, list) else indicators
                result = {
                    "value": value,
                    "type": ioc_type,
                    "verdict": "FOUND",
                    "indicator_id": indicator.get("id", ""),
                    "name": indicator.get("name", ""),
                    "description": indicator.get("description", ""),
                    "score": indicator.get("confidence", 0),
                    "labels": indicator.get("labels", []),
                    "created": indicator.get("created", ""),
                    "valid_from": indicator.get("valid_from", ""),
                    "valid_until": indicator.get("valid_until", ""),
                }

                indicator_id = indicator.get("id", "")
                if indicator_id:
                    try:
                        relations = client.stix_core_relationship.list(
                            filters={
                                "mode": "and",
                                "filters": [
                                    {"key": "fromId", "values": [indicator_id]}
                                ],
                            }
                        )
                        related = []
                        for rel in _safe_results(relations):
                            rel_type = "related-to"
                            target = None
                            for k in rel:
                                if k.startswith("to") and "name" in rel:
                                    target = rel.get("name", "")
                                    break
                            related.append({
                                "type": rel_type,
                                "target": target or "",
                                "relationship": rel.get("relationship_type", ""),
                            })
                        if related:
                            result["relationships"] = related
                    except Exception:
                        pass

                return result
        except Exception as e:
            return {"value": value, "type": ioc_type, "verdict": "ERROR", "error": str(e)}

        return {"value": value, "type": ioc_type, "verdict": "NOT_FOUND"}

    @server.tool()
    def get_recent_indicators(days: int = 7, limit: int = 20) -> dict:
        """Get recently added IOCs from the last N days.

        Args:
            days: Number of days to look back (default: 7, max: 90)
            limit: Max results (default: 20, max: 100)
        """
        client = _get_cti_client()
        if not client:
            return {"connected": False, "message": "OpenCTI not configured"}

        if days < 1:
            days = 7
        elif days > 90:
            days = 90
        if limit < 1:
            limit = 20
        elif limit > 100:
            limit = 100

        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()

        try:
            results = client.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "created_at", "values": [since], "operator": "gt"}
                    ],
                },
                first=limit,
                orderBy="created_at",
                orderMode="desc",
            )
            return {"days": days, "results": _safe_results(results), "total": 0}
        except Exception as e:
            return {"days": days, "error": str(e)}

    @server.tool()
    def get_entity(entity_id: str) -> dict:
        """Get full details for a specific entity by its OpenCTI UUID.

        Args:
            entity_id: OpenCTI entity ID (UUID format)
        """
        client = _get_cti_client()
        if not client:
            return {"connected": False, "message": "OpenCTI not configured"}

        try:
            result = client.stix_domain_object.read(id=entity_id)
            if result is None:
                return {"found": False, "entity_id": entity_id}
            return {"found": True, "entity": result}
        except Exception as e:
            return {"found": False, "entity_id": entity_id, "error": str(e)}

    @server.tool()
    def get_relationships(
        entity_id: str,
        direction: str = "both",
        relationship_types: list[str] | None = None,
        limit: int = 50,
    ) -> dict:
        """Get relationships for an entity.

        Maps threat actor toolkits, malware capabilities, or indicator context.

        Args:
            entity_id: Entity ID to get relationships for
            direction: 'from' (outgoing), 'to' (incoming), or 'both' (default)
            relationship_types: Filter by types (e.g. ['indicates', 'uses', 'targets'])
            limit: Max results (default: 50)
        """
        client = _get_cti_client()
        if not client:
            return {"connected": False, "message": "OpenCTI not configured"}

        if direction not in ("from", "to", "both"):
            direction = "both"
        if limit < 1:
            limit = 50
        elif limit > 50:
            limit = 50

        try:
            filters = []
            if direction in ("from", "both"):
                filters.append({"key": "fromId", "values": [entity_id]})
            if direction in ("to", "both"):
                filters.append({"key": "toId", "values": [entity_id]})

            filter_obj = {
                "mode": "or",
                "filters": filters,
            } if len(filters) > 1 else {
                "mode": "and",
                "filters": filters,
            } if filters else None

            results = client.stix_core_relationship.list(
                filters=filter_obj,
                first=limit,
            )
            return {"entity_id": entity_id, "relationships": _safe_results(results), "total": 0}
        except Exception as e:
            return {"entity_id": entity_id, "error": str(e)}

    @server.tool()
    def search_reports(
        query: str,
        limit: int = 10,
    ) -> dict:
        """Search threat intelligence reports by keyword.

        Returns report metadata, publication date, and associated entities.

        Args:
            query: Search term (campaign name, threat actor, CVE, etc.)
            limit: Max results (default: 10, max: 50)
        """
        client = _get_cti_client()
        if not client:
            return {"connected": False, "message": "OpenCTI not configured"}

        if limit < 1:
            limit = 10
        elif limit > 50:
            limit = 50

        try:
            results = client.report.list(search=query, first=limit)
            return {"results": _safe_results(results), "total": 0}
        except Exception as e:
            return {"error": str(e)}

    @server.tool()
    def search_threat_actor(name: str) -> list:
        """Search for a threat actor in OpenCTI. (Convenience wrapper)."""
        return search_entity("threat_actor", name, 20).get("results", [])

    @server.tool()
    def search_malware(name: str) -> list:
        """Search for malware in OpenCTI. (Convenience wrapper)."""
        return search_entity("malware", name, 20).get("results", [])

    @server.tool()
    def search_mitre_technique(technique_id: str) -> dict:
        """Look up a MITRE ATT&CK technique in OpenCTI.

        Args:
            technique_id: MITRE technique ID (e.g. 'T1003')
        """
        client = _get_cti_client()
        if not client:
            return {"technique_id": technique_id, "error": "OpenCTI not configured"}
        try:
            techniques = client.attack_pattern.list(search=technique_id)
            for t in _safe_results(techniques):
                if t.get("x_mitre_id") == technique_id:
                    return {
                        "technique_id": technique_id,
                        "name": t.get("name", ""),
                        "description": t.get("description", ""),
                    }
        except Exception as e:
            return {"technique_id": technique_id, "error": str(e)}
        return {"technique_id": technique_id, "name": "", "description": ""}
