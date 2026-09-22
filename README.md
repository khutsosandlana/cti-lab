# CTI Lab

CTI Lab is a modular cyber threat-intelligence pipeline for collecting, normalizing, enriching, scoring, and exporting indicators. The repository also keeps third-party OSINT tools as integrations under `scripts/` while the original CTI pipeline lives in `cti_pipeline/`.

## Current status

The foundation provides:

- A typed indicator model for IPs, domains, URLs, hashes, emails, and CVEs
- Deterministic normalization and deduplication
- Transparent confidence scoring
- JSON/CSV ingestion through a small CLI
- A testable package layout for future STIX, MISP, and database integrations

## Quick start

Requires Python 3.10 or newer.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
```

Ingest the included sample data:

```bash
cti-pipeline ingest sample_data/indicators.json --output artifacts/normalized.json
```

The command normalizes indicators, removes duplicates, calculates a transparent score, and writes JSON output.

## Architecture

```text
Input feeds/files
       ↓
Collectors and parsers
       ↓
Indicator normalization + validation
       ↓
Deduplication + provenance preservation
       ↓
Confidence scoring and expiration
       ↓
SQLite / STIX / MISP / reports (planned)
```

```text
cti_pipeline/
  cli.py                 Command-line entry point
  models/                Indicator and observation data models
  processing/            Normalization, deduplication, and scoring
  collectors/            Feed adapters (planned)
  enrichment/            Context enrichment (planned)
  export/                JSON, STIX, MISP, and report exporters (planned)
  storage/               SQLite persistence (planned)
```

## Repository layout

- `cti_pipeline/` — original CTI pipeline code
- `sample_data/` — safe, documentation-only test data using reserved IPs/domains
- `tests/` — tests for the original pipeline
- `scripts/` — third-party tools retained for integration experiments
- `tools/` — local analyst utilities retained from the original workspace
- `docs/` — design notes and implementation roadmap

## Responsible use

Use collection and enrichment features only on data and systems you are authorized to investigate. Do not commit API keys, personal data, credentials, or live malware samples. The OSINT tools under `scripts/` retain their upstream licenses and notices.

## Roadmap

- [ ] SQLite storage and collection-run tracking
- [ ] ThreatFox/Abuse.ch adapter with mocked tests
- [ ] STIX 2.1 export
- [ ] MITRE ATT&CK mappings
- [ ] Markdown intelligence reports
- [ ] Streamlit dashboard

## License and provenance

The new `cti_pipeline/` code is intended to be original project code. Existing software under `scripts/` and `tools/` remains subject to its respective upstream licenses; review those notices before redistribution.
