# CTI Recommender Architecture

**Last Updated:** March 2026

This document describes the current project architecture only. Historical analysis, investigations, and improvement proposals are kept in `docs/archived/`.

---

## Overview

The project is organized around four main layers:

1. Data acquisition and enrichment
2. Feature engineering and labeling
3. Model training and evaluation
4. API and operational tooling

---

## High-Level Flow

```text
External Sources
  -> cache/
  -> SQLite database
  -> feature generation
  -> training/evaluation
  -> outputs/ and models/
```

Primary external sources:
- NVD
- EPSS
- CISA KEV
- MITRE ATT&CK
- CHPL
- healthcare OSINT / curated healthcare mappings

---

## Runtime Data Layers

### Cache Layer

The `cache/` directory stores fetched or reusable source data to reduce repeated remote calls.

Main cache groups:
- `cache/nvd/`
- `cache/epss/`
- `cache/kev/`
- `cache/attack/`
- `cache/chpl/`
- `cache/healthcare_osint/`

### Database Layer

The project uses SQLite as the main working store for normalized CVE and enrichment data.

Main concepts stored in the database:
- CVE records
- enrichment attributes
- fetch and update metadata

### Derived Artifacts

Generated outputs are stored outside the database when they are better handled as files:
- trained models in `models/`
- reports and exports in `outputs/`
- logs in `logs/`

---

## Source Tree

### Application Code

- `src/core/` - core ingestion, database, fetchers, healthcare logic
- `src/features/` - feature engineering, labels, production features
- `src/models/` - ranking, graph, ensemble, and baseline models
- `src/evaluation/` - metrics and significance utilities
- `src/analysis/` - mapping and data-quality analysis helpers
- `src/api/` - API entrypoint and serving layer
- `src/utils/` - shared operational and utility helpers

### Operational Scripts

- `scripts/data/` - refresh, enrichment, cache preparation
- `scripts/training/` - training and validation entrypoints
- `scripts/evaluation/` - reporting and recommendation scripts
- `scripts/analyze/` - analytical studies
- `scripts/ops/` - DB and enrichment monitoring utilities

### Interactive Work

- `notebooks/` - exploration, feature, and model notebooks

---

## Training Architecture

The training path is:

1. load and enrich CVE data
2. generate features and labels
3. split data for evaluation strategy
4. train ranking or graph-based models
5. save metrics, reports, and model artifacts

Model families currently represented in the codebase include:
- learning-to-rank models
- baseline ranking models
- ensemble models
- graph-based models such as RGCN variants
- diffusion-based ranking variants

---

## API / Serving Architecture

The serving layer exposes model-driven recommendations and prediction endpoints from `src/api/`.

Operationally, the project can run:
- locally in Python
- through Docker and docker-compose
- through Makefile shortcuts for common commands

See `DOCKER_GUIDE.md` for runtime and troubleshooting details.

---

## Diagrams

Rendered and source diagrams are kept in `docs/diagrams/`:
- project architecture
- notebook pipeline
- data pipeline
- evaluation strategies
- LTR model
- examiner flowchart

---

## What Is Not In This Document

This file intentionally does not include:
- bug investigations
- migration plans
- historical refactor plans
- proposed alternative architectures
- one-off action plans

Those belong in `docs/archived/` so the active documentation stays focused.
