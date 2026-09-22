"""End-to-end processing for the first pipeline milestone."""

from __future__ import annotations

from cti_pipeline.processing.normalize import normalize_record
from cti_pipeline.processing.score import score_indicator


def process_records(records: list[dict]) -> list[dict]:
    by_key: dict[str, dict] = {}
    for record in records:
        normalized = normalize_record(record)
        if not normalized["value"]:
            continue
        key = f"{normalized['indicator_type']}:{normalized['value']}"
        if key not in by_key:
            normalized["confidence"] = score_indicator(normalized)
            normalized["id"] = key
            by_key[key] = normalized
        else:
            existing = by_key[key]
            existing["labels"] = sorted(set(existing["labels"]) | set(normalized["labels"]))
            existing["confidence"] = max(existing["confidence"], score_indicator(normalized))
            existing["raw_sources"] = sorted(
                set(existing.get("raw_sources", [existing["source"]])) | {normalized["source"]}
            )
    return sorted(by_key.values(), key=lambda item: item["id"])
