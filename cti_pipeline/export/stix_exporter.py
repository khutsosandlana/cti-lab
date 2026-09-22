"""STIX 2.1 export helpers."""

from __future__ import annotations

import json
import uuid
from typing import Any


def _pattern_for_indicator(indicator: dict[str, Any]) -> str:
    indicator_type = indicator.get("indicator_type", "unknown")
    value = indicator.get("value", "")

    patterns = {
        "ipv4-addr": f"[ipv4-addr:value = '{value}']",
        "ipv6-addr": f"[ipv6-addr:value = '{value}']",
        "domain-name": f"[domain-name:value = '{value}']",
        "url": f"[url:value = '{value}']",
        "md5": f"[file:hashes.MD5 = '{value}']",
        "sha1": f"[file:hashes.SHA-1 = '{value}']",
        "sha256": f"[file:hashes.SHA-256 = '{value}']",
        "email-addr": f"[email-addr:value = '{value}']",
        "cve": (f"[vulnerability:external_references[*].external_id = '{value}']"),
    }

    return patterns.get(
        indicator_type,
        f"[artifact:payload_bin = '{value}']",
    )


def export_stix(indicators: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a STIX 2.1 bundle from normalized indicators."""
    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [],
    }

    for indicator in indicators:
        value = indicator.get("value", "")
        labels = [str(label) for label in indicator.get("labels", [])]

        bundle["objects"].append(
            {
                "type": "indicator",
                "id": f"indicator--{uuid.uuid4()}",
                "spec_version": "2.1",
                "created": "2026-01-01T00:00:00Z",
                "modified": "2026-01-01T00:00:00Z",
                "name": value,
                "description": f"Normalized indicator for {value}",
                "pattern": _pattern_for_indicator(indicator),
                "pattern_type": "stix",
                "labels": labels or ["cti"],
                "confidence": int(indicator.get("confidence", 0)),
                "valid_from": "2026-01-01T00:00:00Z",
            }
        )

    return bundle


def export_stix_json(
    indicators: list[dict[str, Any]],
    output_path: str | None = None,
) -> str:
    """Serialize indicators as a STIX JSON bundle."""
    payload = json.dumps(export_stix(indicators), indent=2)

    if output_path:
        with open(output_path, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")

    return payload
