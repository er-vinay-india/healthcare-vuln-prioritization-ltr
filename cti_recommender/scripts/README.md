# Scripts Directory

This directory contains utility scripts for the CTI Recommender project.

## Available Scripts

### Core Operations

#### `backfill_cves.py`
Backfills CVE data from NVD API for specified date ranges.
```bash
python scripts/data/backfill_cves.py --start-date 2024-01-01 --end-date 2024-12-31
```

#### `enrich_cves.py`
Enriches CVE database with data from multiple threat intelligence sources:
- EPSS (Exploit Prediction Scoring System)
- CISA KEV (Known Exploited Vulnerabilities)
- MITRE ATT&CK mappings
- CHPL (Certified Health IT Product List)
- Healthcare context patterns

```bash
python scripts/data/enrich_cves.py
```

#### `recommend_cves.py`
Generates prioritized CVE recommendations for healthcare environments.
```bash
python scripts/evaluation/recommend_cves.py --top-k 20
```

#### `refresh_cves.py`
Refreshes CVE data from NVD API (daily updates).
```bash
python scripts/data/refresh_cves.py
```

### Model Operations

#### `train_ltr.py`
Trains the Learning-to-Rank (LambdaMART) model.
```bash
python scripts/training/train_ltr.py
```

### Evaluation & Analysis

#### `temporal_validation.py`
Performs temporal validation to check for data leakage.
```bash
python scripts/training/temporal_validation.py
```

#### `cross_validation.py`
Runs k-fold cross-validation on the LTR model.
```bash
python scripts/training/cross_validation.py
```

#### `generate_report.py`
Generates comprehensive evaluation reports.
```bash
python scripts/evaluation/generate_report.py
```

### Maintenance & Diagnostics

#### `check_db_status.py`
Checks database status and statistics.
```bash
python scripts/ops/check_db_status.py
```

## Cache Management

### View Cache Status
```bash
python -m src.utils.cache_manager
```

### Clear Cache (Requires Confirmation)
```python
from src.utils.cache_manager import clear_cache

# Clear specific source
clear_cache('epss', confirm=True)
clear_cache('kev', confirm=True)

# Clear all cache (nuclear option)
clear_cache(confirm=True)  # Will prompt for 'DELETE ALL'
```

Available cache sources: `nvd`, `epss`, `kev`, `attack`, `chpl`

### Refresh Cache
```bash
# Re-fetch all enrichment data
python scripts/data/enrich_cves.py
```

## Common Workflows

### Initial Setup
```bash
# 1. Backfill CVE data
python scripts/data/backfill_cves.py --start-date 2018-01-01 --end-date 2025-01-20

# 2. Enrich CVEs with threat intelligence
python scripts/data/enrich_cves.py

# 3. Train LTR model
python scripts/training/train_ltr.py
```

### Daily Updates
```bash
# 1. Refresh latest CVEs
python scripts/data/refresh_cves.py

# 2. Re-enrich (updates EPSS, KEV)
python scripts/data/enrich_cves.py

# 3. Generate recommendations
python scripts/evaluation/recommend_cves.py --top-k 20
```

### Model Evaluation
```bash
# Temporal validation
python scripts/training/temporal_validation.py

# Cross-validation
python scripts/training/cross_validation.py

# Generate report
python scripts/evaluation/generate_report.py
```

### Troubleshooting

#### Cache Issues
```bash
# If cache is corrupted, clear and rebuild
python -c "from src.utils.cache_manager import clear_cache; clear_cache('epss', confirm=True)"
python scripts/data/enrich_cves.py
```

#### Database Issues
```bash
# Check database status
python scripts/ops/check_db_status.py

# Rebuild database if needed
rm data/cve_database.db
python scripts/data/backfill_cves.py --start-date 2018-01-01 --end-date 2025-01-20
```

## Notes

- All scripts should be run from the project root directory
- Use the venv Python interpreter: `/path/to/venv/bin/python`
- Check logs in `logs/` directory for detailed execution information
- Cache is stored in `cache/` directory (organized by source: nvd, epss, kev, attack, chpl)
- Database is at `data/cve_database.db` (currently ~226K CVEs)

## Environment Setup

Make sure you're using the virtual environment:
```bash
source venv/bin/activate  # macOS/Linux
# or
.\venv\Scripts\activate   # Windows
```

For more information, see:
- [docs/QUICKSTART.md](../docs/QUICKSTART.md) - Quick start guide
- [docs/DEVELOPMENT.md](../docs/DEVELOPMENT.md) - Development guide
- [docs/KT_GUIDE.md](../docs/KT_GUIDE.md) - Knowledge transfer guide
