"""Input normalization, deduplication, and scoring."""

from cti_pipeline.processing.normalize import normalize_record
from cti_pipeline.processing.pipeline import process_records
from cti_pipeline.processing.score import score_indicator

__all__ = ["normalize_record", "process_records", "score_indicator"]
