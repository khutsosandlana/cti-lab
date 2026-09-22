"""Command-line interface for the CTI Lab foundation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cti_pipeline.processing.pipeline import process_records


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize and score CTI indicators.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest = subparsers.add_parser("ingest", help="Process a JSON or JSONL indicator file.")
    ingest.add_argument("input", type=Path, help="Input JSON array or JSONL file")
    ingest.add_argument("--output", type=Path, required=True, help="Output JSON file")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "ingest":
        records = json.loads(args.input.read_text(encoding="utf-8"))
        result = process_records(records)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {len(result)} normalized indicators to {args.output}")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
