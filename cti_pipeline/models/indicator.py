"""Normalized cyber indicator model."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class IndicatorType(StrEnum):
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    EMAIL = "email-addr"
    CVE = "cve"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class Indicator:
    value: str
    indicator_type: IndicatorType
    source: str = "unknown"
    confidence: int = 0
    labels: list[str] = field(default_factory=list)
    first_seen: str | None = None
    last_seen: str | None = None
    source_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.indicator_type.value}:{self.value}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["indicator_type"] = self.indicator_type.value
        data["id"] = self.key
        return data
