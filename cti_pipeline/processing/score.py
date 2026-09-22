"""Transparent confidence scoring for normalized indicators."""

from __future__ import annotations

from datetime import datetime, timezone


def score_indicator(indicator: dict) -> int:
    """Return a bounded score; this is an analytical aid, not a verdict."""
    score = 0
    if indicator.get("source") not in {None, "", "unknown"}:
        score += 25
    if indicator.get("source_url"):
        score += 10
    if indicator.get("labels"):
        score += min(20, 5 * len(indicator["labels"]))
    if indicator.get("last_seen"):
        score += 15
    if indicator.get("indicator_type") in {"sha256", "sha1", "md5"}:
        score += 10
    return min(100, score)


def is_expired(indicator: dict, now: datetime | None = None) -> bool:
    """Check an optional ISO-8601 expiration field, if supplied."""
    expires_at = indicator.get("expires_at")
    if not expires_at:
        return False
    current = now or datetime.now(timezone.utc)
    return datetime.fromisoformat(expires_at.replace("Z", "+00:00")) <= current
