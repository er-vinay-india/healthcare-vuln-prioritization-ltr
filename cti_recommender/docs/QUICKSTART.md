# Quick Start

**Last Updated:** March 2026

This guide is for a new user who wants to get the project running quickly.

## Prerequisites

- Python 3.10+
- SQLite available on your machine
- Enough disk space for local data and caches

## Setup

```bash
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti_recommender

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Optional:

```bash
cp .env.example .env
```

## First Local Run

### 1. Enrich CVE data

```bash
python scripts/data/enrich_cves.py --years 1 --workers 4
```

This pulls and enriches CVE data from the configured external sources.

### 2. Train the ranking model

```bash
python scripts/training/train_ltr.py
```

This trains the main ranking model and saves artifacts under `models/`.

### 3. Check results

```bash
python scripts/analyze/enrichment_stats.py
```

## Docker Alternative

If you prefer Docker, use the commands in `DOCKER_GUIDE.md`.

Quick start:

```bash
docker-compose up -d
curl http://localhost:8000/health
```

## Common Issues

### Rate limit or slow upstream APIs

Reduce worker count:

```bash
python scripts/data/enrich_cves.py --years 1 --workers 2
```

### Database locked

Stop other running scripts and retry.

### Missing dependency

```bash
pip install -r requirements.txt --upgrade
```

## What To Read Next

- `ARCHITECTURE.md` for system structure
- `DEVELOPMENT.md` if you plan to change code
- `DOCKER_GUIDE.md` if you want containerized runs
- `RANKING_LOGIC.md` if you want to understand ranking behavior
