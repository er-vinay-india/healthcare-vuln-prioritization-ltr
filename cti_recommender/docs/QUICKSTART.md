# Quick Start Guide

**Last Updated:** 2026-01-17  
**Version:** 2.0.0

---

## Prerequisites

- Python 3.10+ (tested on 3.14)
- 4GB RAM minimum
- 10GB disk space for CVE database

---

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti_recommender
```

### 2. Setup Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment (Optional)

```bash
cp .env.example .env
# Edit .env for custom paths, API keys, etc.
```

---

## Basic Usage

### Step 1: Enrich CVE Data

Download and enrich CVEs with all data sources:

```bash
python scripts/data/enrich_cves.py --years 1 --workers 4
```

**What it does:**
- Downloads CVEs from NVD (last N years)
- Fetches EPSS exploitation scores
- Checks CISA KEV catalog
- Detects healthcare relevance
- Maps to ATT&CK techniques
- Matches CHPL certified products
- Calculates priority labels

**Options:**
- `--years N` - Number of years to fetch (default: 1)
- `--workers N` - Parallel workers (default: 4)
- `--skip-attack` - Skip ATT&CK mapping (faster)
- `--skip-chpl` - Skip CHPL matching (faster)

**Expected time:** ~8 minutes for 1 year of CVEs

---

### Step 2: Train LTR Model

Train the Learning-to-Rank model:

```bash
python scripts/training/train_ltr.py
```

**What it does:**
- Loads enriched CVEs from database
- Extracts 14 features
- Trains LightGBM LambdaRank model
- Saves trained model to `models/`
- Reports NDCG@10, P@100, MRR metrics

**Expected output:**
```
Training LTR model...
NDCG@10: 0.7674
P@100: 1.0000
MRR: 0.8523
Model saved to models/ltr_model.pkl
```

**Expected time:** ~2 minutes

---

### Step 3: Validate Model (Optional)

Run temporal validation:

```bash
python scripts/training/temporal_validation.py
```

**What it does:**
- Splits data into 3-month windows
- Trains on past, tests on future
- Reports per-window NDCG metrics

**Expected time:** ~5 minutes

---

### Step 4: View Results

Check enrichment statistics:

```bash
python scripts/analyze/enrichment_stats.py
```

**Sample output:**
```
Total CVEs: 226,320
Healthcare CVEs: 125,606 (55.5%)
KEV CVEs: 1,460 (0.6%)
ATT&CK mapped: 83,574 (36.9%)
CHPL matched: 5,089 (2.2%)

Label Distribution:
  0 (Low): 180,256 (79.7%)
  1 (Medium): 32,048 (14.2%)
  2 (High): 10,124 (4.5%)
  3 (Critical): 2,456 (1.1%)
  4 (Urgent): 892 (0.4%)
  5 (Emergency): 544 (0.2%)
```

---

## Docker Usage (Alternative)

### 1. Build and Run

```bash
docker-compose up -d
```

### 2. Check Health

```bash
curl http://localhost:8000/health
```

### 3. Get Recommendations

```bash
curl -X POST http://localhost:8000/api/v1/recommendations \
  -H "Content-Type: application/json" \
  -d '{"limit": 20, "healthcare_only": true, "min_cvss": 7.0}'
```

---

## Common Tasks

### Update CVE Database

```bash
# Re-run enrichment with latest data
python scripts/data/enrich_cves.py --years 1 --workers 4
```

### Retrain Model

```bash
# After updating database
python scripts/training/train_ltr.py
```

### Run All Analysis Scripts

```bash
# Enrichment statistics
python scripts/analyze/enrichment_stats.py

# Coverage analysis
python scripts/analyze/coverage_analysis.py

# Medical terms analysis
python scripts/analyze/medical_terms.py

# Feature ablation study
python scripts/analyze/ablation_study.py

# Feature correlation
python scripts/analyze/feature_correlation.py
```

---

## Troubleshooting

### Issue: NVD API Rate Limit

**Error:** `429 Too Many Requests`

**Solution:** Wait a few minutes, or reduce `--workers` parameter:
```bash
python scripts/data/enrich_cves.py --years 1 --workers 2
```

---

### Issue: Database Locked

**Error:** `database is locked`

**Solution:** Close other scripts/connections:
```bash
# Kill any running Python processes
pkill -f "python scripts"

# Retry
python scripts/data/enrich_cves.py --years 1
```

---

### Issue: Out of Memory

**Error:** `MemoryError` or system slowdown

**Solution:** Process fewer CVEs:
```bash
# Fetch only recent CVEs
python scripts/data/enrich_cves.py --years 0.5
```

---

### Issue: Missing Dependencies

**Error:** `ModuleNotFoundError: No module named 'X'`

**Solution:** Reinstall dependencies:
```bash
pip install -r requirements.txt --upgrade
```

---

## Next Steps

- **Read full documentation:** See `docs/` directory
- **API usage:** See `DOCKER_GUIDE.md` for REST API run and troubleshooting
- **Development guide:** See `docs/DEVELOPMENT.md`
- **Architecture details:** See `ARCHITECTURE.md`
- **Historical docs:** See `archived/archive_README.md`

---

## Performance Expectations

| Task | Time | Output |
|------|------|--------|
| Enrich 1 year CVEs | ~8 min | 226K CVEs enriched |
| Train LTR model | ~2 min | NDCG@10=0.77 |
| Temporal validation | ~5 min | Per-window metrics |
| Ablation study | ~10 min | Feature importance |

**System:** MacBook Pro M1, 16GB RAM, 4 workers

---

## Getting Help

- **GitHub Issues:** https://github.com/er-vinay-india/cti-recommender/issues
- **Documentation:** `docs/` directory
- **Email:** [your-email]

---

- **You're all set!** Start with Step 1 above to enrich your CVE database.
