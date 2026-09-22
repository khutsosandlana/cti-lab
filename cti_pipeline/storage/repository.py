from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from cti_pipeline.storage.db import DEFAULT_DB_PATH, db_session


class IndicatorRepository:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self.db_path = db_path

    def initialize(self) -> None:
        with db_session(self.db_path):
            pass

    def add_source(
        self,
        name: str,
        source_type: str = "feed",
        url: str | None = None,
        description: str | None = None,
    ) -> int:
        with db_session(self.db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO sources(name, source_type, url, description)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    source_type = excluded.source_type,
                    url = excluded.url,
                    description = excluded.description
                """,
                (name, source_type, url, description),
            )
            return int(cur.lastrowid)

    def start_collection_run(self, source_name: str, notes: str | None = None) -> int:
        with db_session(self.db_path) as conn:
            cur = conn.execute(
                """
                INSERT INTO collection_runs(source_name, status, notes)
                VALUES (?, 'running', ?)
                """,
                (source_name, notes),
            )
            return int(cur.lastrowid)

    def finish_collection_run(
        self,
        run_id: int,
        status: str = "completed",
        summary: str | None = None,
    ) -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                UPDATE collection_runs
                SET status = ?, finished_at = ?, notes = COALESCE(notes, '') || ' | ' || ?
                WHERE id = ?
                """,
                (status, datetime.now(timezone.utc).isoformat(), summary, run_id),
            )

    def upsert_indicator(self, indicator: dict) -> str:
        indicator_id = f"{indicator['indicator_type']}:{indicator['value']}"
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO indicators (
                    id, indicator_type, value, source, confidence,
                    labels, first_seen, last_seen, source_url, raw_json, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    indicator_type = excluded.indicator_type,
                    value = excluded.value,
                    source = excluded.source,
                    confidence = MAX(indicators.confidence, excluded.confidence),
                    labels = excluded.labels,
                    first_seen = COALESCE(indicators.first_seen, excluded.first_seen),
                    last_seen = COALESCE(indicators.last_seen, excluded.last_seen),
                    source_url = COALESCE(indicators.source_url, excluded.source_url),
                    raw_json = excluded.raw_json,
                    updated_at = excluded.updated_at
                """,
                (
                    indicator_id,
                    indicator["indicator_type"],
                    indicator["value"],
                    indicator.get("source", "unknown"),
                    int(indicator.get("confidence", 0)),
                    json.dumps(indicator.get("labels", [])),
                    indicator.get("first_seen"),
                    indicator.get("last_seen"),
                    indicator.get("source_url"),
                    json.dumps(indicator.get("raw", {})),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return indicator_id

    def add_observation(
        self,
        indicator_id: str,
        source_name: str,
        source_url: str | None,
        run_id: int | None,
        raw: dict,
    ) -> None:
        with db_session(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO observations(indicator_id, source_name, source_url, run_id, raw_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (indicator_id, source_name, source_url, run_id, json.dumps(raw)),
            )

    def list_indicators(self, limit: int = 100) -> list[dict]:
        with db_session(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, indicator_type, value, source, confidence, labels, first_seen, last_seen, source_url
                FROM indicators
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def fetch_indicator(self, indicator_id: str) -> dict | None:
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM indicators WHERE id = ?",
                (indicator_id,),
            ).fetchone()
        if row is None:
            return None
        return dict(row)
