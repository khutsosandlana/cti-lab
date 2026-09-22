# CTI Lab implementation notes

## Phase 1 — foundation

- Define a stable normalized indicator model.
- Preserve source provenance when indicators are deduplicated.
- Keep scoring transparent and bounded.
- Use reserved example data in tests.

## Phase 2 — persistence

Add SQLite repositories for indicators, observations, sources, relationships, and collection runs. The pipeline should preserve raw observations rather than overwriting them during deduplication.

## Phase 3 — integrations

Add collectors behind a common interface. Start with local JSON/CSV fixtures, then add one public threat-intelligence feed with mocked HTTP tests. Avoid making the test suite dependent on live APIs.

## Phase 4 — interoperability

Add STIX 2.1 export, MITRE ATT&CK technique references, analyst-ready Markdown reports, and eventually MISP export.
