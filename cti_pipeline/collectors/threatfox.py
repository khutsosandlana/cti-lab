from __future__ import annotations

import requests

from cti_pipeline.collectors.base import Collector
from cti_pipeline.processing.normalize import normalize_record
from cti_pipeline.storage.repository import IndicatorRepository


class ThreatFoxCollector(Collector):
    name = "threatfox"

    def __init__(self, repository: IndicatorRepository | None = None, timeout: int = 30):
        self.repository = repository
        self.timeout = timeout

    @staticmethod
    def _map_type(raw_type: str) -> str:
        mapping = {
            "IP_ADDRESS": "ipv4-addr",
            "IPV6_ADDRESS": "ipv6-addr",
            "DOMAIN": "domain-name",
            "URL": "url",
            "HASH_MD5": "md5",
            "HASH_SHA1": "sha1",
            "HASH_SHA256": "sha256",
        }
        return mapping.get(raw_type.upper(), "unknown")

    def collect(self) -> list[dict]:
        endpoint = "https://threatfox.abuse.ch/api/v1/"
        try:
            response = requests.get(endpoint, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError):
            return []

        items = payload.get("data", []) if isinstance(payload, dict) else []
        records: list[dict] = []

        for item in items:
            raw_type = str(item.get("ioc_type", "unknown")).upper()
            value = str(item.get("ioc_value", "")).strip()
            if not value:
                continue

            indicator_type = self._map_type(raw_type)
            if indicator_type == "unknown":
                continue

            record = {
                "value": value,
                "type": indicator_type,
                "source": "threatfox",
                "labels": [str(item.get("malware", "threatfox")).strip()],
                "first_seen": item.get("first_seen", item.get("date")),
                "last_seen": item.get("last_seen"),
                "source_url": item.get("reference") or item.get("link"),
                "raw": item,
            }
            normalized = normalize_record(record)
            normalized["confidence"] = max(
                normalized.get("confidence", 0), int(item.get("confidence", 50))
            )
            normalized["source"] = "threatfox"
            normalized["labels"] = sorted(
                set(normalized.get("labels", []) + [str(item.get("malware", "threatfox"))])
            )
            records.append(normalized)

        if self.repository is not None:
            run_id = self.repository.start_collection_run("threatfox")
            for record in records:
                indicator_id = self.repository.upsert_indicator(record)
                self.repository.add_observation(
                    indicator_id,
                    "threatfox",
                    record.get("source_url"),
                    run_id,
                    record.get("raw", {}),
                )
            self.repository.finish_collection_run(
                run_id, "completed", f"imported {len(records)} indicators"
            )

        return records
