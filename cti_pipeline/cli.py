"""Command-line interface for CTI Lab."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cti_pipeline.collectors.threatfox import ThreatFoxCollector
from cti_pipeline.export.stix_exporter import export_stix_json
from cti_pipeline.processing.pipeline import process_records
from cti_pipeline.storage.repository import IndicatorRepository


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize and score CTI indicators.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser(
        "ingest",
        help="Process a JSON indicator file.",
    )
    ingest.add_argument("input", type=Path, help="Input JSON file")
    ingest.add_argument("--output", type=Path, required=True)

    db_init = subparsers.add_parser(
        "db-init",
        help="Initialize the SQLite database.",
    )
    db_init.add_argument(
        "--db-path",
        type=Path,
        default=Path("data/cti.db"),
    )

    collect = subparsers.add_parser(
        "collect",
        help="Collect indicators from a supported feed.",
    )
    collect.add_argument(
        "--feed",
        choices=["threatfox"],
        default="threatfox",
    )
    collect.add_argument(
        "--db-path",
        type=Path,
        default=Path("data/cti.db"),
    )

    export = subparsers.add_parser(
        "export",
        help="Export indicators.",
    )
    export.add_argument(
        "--format",
        choices=["stix"],
        default="stix",
    )
    export.add_argument("input", type=Path)
    export.add_argument("--output", type=Path, required=True)

    return parser


def load_records(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(data, dict):
        data = data.get("indicators", [])

    if not isinstance(data, list):
        raise TypeError("Input must be a JSON list or an object containing 'indicators'.")

    return data


def main() -> int:
    args = build_parser().parse_args()

    if args.command == "ingest":
        result = process_records(load_records(args.input))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2) + "\n",
            encoding="utf-8",
        )
        print(f"Wrote {len(result)} normalized indicators to {args.output}")
        return 0

    if args.command == "db-init":
        repository = IndicatorRepository(args.db_path)
        repository.initialize()
        print(f"Initialized database at {args.db_path}")
        return 0

    if args.command == "collect":
        repository = IndicatorRepository(args.db_path)
        collector = ThreatFoxCollector(repository=repository)
        records = collector.collect()
        print(f"Collected {len(records)} indicators from {args.feed}")
        return 0

    if args.command == "export":
        indicators = load_records(args.input)
        args.output.parent.mkdir(parents=True, exist_ok=True)

        if args.format == "stix":
            export_stix_json(indicators, str(args.output))
            print(f"Wrote STIX bundle to {args.output}")
            return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
