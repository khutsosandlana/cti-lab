import json

from cti_pipeline.processing.normalize import normalize_record
from cti_pipeline.processing.pipeline import process_records


def test_domain_is_normalized():
    result = normalize_record({"value": "Example.COM."})
    assert result["value"] == "example.com"
    assert result["indicator_type"] == "domain-name"


def test_duplicate_indicators_are_merged():
    records = [
        {"value": "Example.COM", "source": "one", "labels": ["a"]},
        {"value": "example.com.", "source": "two", "labels": ["b"]},
    ]

    result = process_records(records)

    assert len(result) == 1
    assert result[0]["labels"] == ["a", "b"]
    assert result[0]["raw_sources"] == ["one", "two"]


def test_sample_data_can_be_processed():
    with open("sample_data/indicators.json", encoding="utf-8") as file:
        source = json.load(file)

    output = process_records(source["indicators"])

    assert len(output) == 2
    assert output[0]["confidence"] >= 0
