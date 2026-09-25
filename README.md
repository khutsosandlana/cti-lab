# CTI Lab

CTI Lab is a modular cyber threat intelligence pipeline for collecting, normalizing, enriching, scoring, and exporting indicators. The project is designed as a practical learning platform for security analysts, detection engineers, and anyone exploring end-to-end CTI workflows.

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green.svg" />
  <img alt="Status" src="https://img.shields.io/badge/Status-Active-blue" />
</p>

## Why this project matters

Threat intelligence is only useful when it is structured, validated, and operationalized. This repository focuses on the part of CTI that often gets overlooked: turning noisy raw indicators into reliable intelligence that can support detections, investigations, and analyst workflows.

## What is included

- typed indicator models for IPs, domains, URLs, hashes, emails, and CVEs
- deterministic normalization and deduplication
- transparent confidence scoring
- JSON/CSV ingestion through a command-line interface
- modular architecture for future STIX, MISP, SQLite, and reporting integrations

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
