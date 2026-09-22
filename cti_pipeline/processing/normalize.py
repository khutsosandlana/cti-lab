"""Indicator normalization and lightweight validation."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from cti_pipeline.models.indicator import IndicatorType

_HASH_LENGTHS = {32: IndicatorType.MD5, 40: IndicatorType.SHA1, 64: IndicatorType.SHA256}
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_value(value: str, indicator_type: IndicatorType) -> str:
    value = value.strip()
    if indicator_type in {IndicatorType.DOMAIN, IndicatorType.EMAIL, IndicatorType.CVE}:
        return value.lower().rstrip(".")
    if indicator_type == IndicatorType.URL:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        hostname = (parts.hostname or "").lower().rstrip(".")
        port = f":{parts.port}" if parts.port else ""
        netloc = f"{hostname}{port}"
        return urlunsplit((scheme, netloc, parts.path or "/", parts.query, ""))
    if indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
        return value.lower()
    return value


def detect_type(value: str, declared: str | None = None) -> IndicatorType:
    if declared:
        try:
            return IndicatorType(declared)
        except ValueError:
            pass
    candidate = value.strip()
    try:
        address = ipaddress.ip_address(candidate)
        return IndicatorType.IPV4 if address.version == 4 else IndicatorType.IPV6
    except ValueError:
        pass
    if _CVE_PATTERN.match(candidate):
        return IndicatorType.CVE
    if _EMAIL_PATTERN.match(candidate):
        return IndicatorType.EMAIL
    if candidate.lower().startswith(("http://", "https://")):
        return IndicatorType.URL
    if len(candidate) in _HASH_LENGTHS and all(char in "0123456789abcdefABCDEF" for char in candidate):
        return _HASH_LENGTHS[len(candidate)]
    if "." in candidate and " " not in candidate:
        return IndicatorType.DOMAIN
    return IndicatorType.UNKNOWN


def normalize_record(record: dict) -> dict:
    raw_value = str(record.get("value", ""))
    indicator_type = detect_type(raw_value, record.get("type") or record.get("indicator_type"))
    normalized = normalize_value(raw_value, indicator_type)
    return {
        "value": normalized,
        "indicator_type": indicator_type.value,
        "source": str(record.get("source", "unknown")),
        "labels": sorted(set(record.get("labels", []))),
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "source_url": record.get("source_url"),
        "raw": record,
    }
