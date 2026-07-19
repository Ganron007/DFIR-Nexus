"""Canned TI responses for offline tests."""

from __future__ import annotations

from typing import Any

_MOCK_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def mock_threatfox(value: str) -> dict[str, Any]:
    return {
        "query_status": "ok",
        "data": [
            {
                "ioc": value,
                "ioc_type": "domain",
                "threat_type": "botnet_cc",
                "malware": "emotet",
                "confidence_level": 75,
            }
        ],
    }


def mock_malware_bazaar(value: str) -> dict[str, Any]:
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": value if len(value) == 64 else _MOCK_HASH,
                "signature": "Emotet",
                "file_name": "invoice.doc",
                "tags": ["emotet", "doc"],
            }
        ],
    }


def mock_urlhaus(value: str) -> dict[str, Any]:
    return {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
        "url_status": "online",
        "threat": "malware_download",
        "url": value,
        "tags": ["emotet"],
    }


def mock_yaraify(value: str) -> dict[str, Any]:
    return {
        "query_status": "ok",
        "data": [
            {
                "sha256_hash": value if len(value) == 64 else _MOCK_HASH,
                "yara_rules": [{"rule_name": "win_emotet_dropper", "author": "nexus-mock"}],
            }
        ],
    }


def mock_misp(value: str) -> dict[str, Any]:
    return {
        "response": {
            "Attribute": [
                {
                    "id": "1",
                    "event_id": "42",
                    "type": "domain",
                    "category": "Network activity",
                    "value": value,
                    "to_ids": True,
                    "comment": "mock MISP hit",
                }
            ]
        }
    }


def mock_otx(value: str) -> dict[str, Any]:
    return {"pulse_info": {"count": 3, "pulses": [{"name": "mock-pulse", "id": "1"}]}, "indicator": value}


def mock_shodan(ip: str) -> dict[str, Any]:
    return {"ip_str": ip, "ports": [443, 8443], "tags": ["mock"]}


def mock_virustotal(value: str) -> dict[str, Any]:
    return {
        "data": {
            "id": value,
            "attributes": {
                "last_analysis_stats": {"malicious": 12, "undetected": 40},
                "meaningful_name": "evil.bin",
            },
        }
    }


def mock_abuseipdb(ip: str) -> dict[str, Any]:
    return {"data": {"ipAddress": ip, "abuseConfidenceScore": 88, "totalReports": 42, "countryCode": "RU"}}


def mock_crowdstrike(value: str) -> dict[str, Any]:
    return {"resources": [{"indicator": value, "malicious_confidence": "high"}]}
