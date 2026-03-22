# Healthcare Vulnerability Prioritization Using a Learning-to-Rank Framework with Integrated Cyber Threat Intelligence

[![Python CI](https://github.com/er-vinay-india/cti-recommender/actions/workflows/python-ci.yml/badge.svg)](https://github.com/er-vinay-india/cti-recommender/actions/workflows/python-ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Overview

This project builds a **healthcare-focused vulnerability prioritization system** that goes beyond raw CVSS scores. Instead of treating all CVEs equally, it fuses signals from four authoritative threat-intelligence sources and trains a **LightGBM LambdaRank (Learning-to-Rank)** model to produce a ranked list of CVEs that are most likely to affect healthcare infrastructure — medical devices, EHR systems, and certified health IT products.

The system evolved iteratively from a weighted heuristic baseline to an AI-enhanced ranking pipeline with ablation studies, hyperparameter tuning, and multi-model comparison.

---

## Key Results

| Model | NDCG@5 | NDCG@10 | NDCG@20 | P@10 | MAP@10 |
|---|---|---|---|---|---|
| **Our Weighted LTR** | **1.000** | **0.998** | **0.990** | 0.070 | 0.472 |
| Weighted Heuristic | 0.955 | 0.967 | 0.972 | 0.064 | 0.384 |
| DiffusionRank | 0.862 | 0.900 | 0.924 | 0.045 | 0.214 |
| CVSS-Only Baseline | 0.846 | 0.889 | 0.890 | 0.043 | 0.172 |
| RGCN | 0.807 | 0.802 | 0.788 | 0.024 | 0.172 |

> Best LTR hyperparameters: `learning_rate=0.01`, `num_leaves=20`, `min_data_in_leaf=10`, `objective=lambdarank`, `num_boost_round=500`.

---

## Data Sources

| Source | Role |
|---|---|
| **NVD v2.0** | Baseline CVE metadata — CVSS scores, descriptions, publication dates |
| **CISA KEV** | Known Exploited Vulnerabilities — ground-truth exploitability signal |
| **MITRE ATT&CK Enterprise** | Tactic/technique mapping (~835 techniques, 36 CAPEC-linked) |
| **CHPL** (Certified Health IT Product List) | Healthcare domain relevance — ~6.9k certified products matched against CVE descriptions |

All sources are fetched with a TTL-based cache (gzipped parquet/pickle in `data_cache/` and `data/processed/`) so repeated runs are fast and offline-capable.

---

## Architecture

```
cti_recommender/src/
├── core/               # Fetchers (NVD, CHPL, EPSS), main scoring engine, LTR entry-point
│   ├── chpl_fetcher.py
│   ├── cti_recommender.py
│   ├── epss_fetcher.py
│   ├── ltr.py
│   └── multi_level_labels.py
├── features/           # Feature engineering, weak-supervision labeling
│   ├── engineering.py
│   ├── enhanced_features.py
│   ├── labeling.py
│   └── temporal_labeling.py
├── models/             # LTR, ensemble, RGCN, DiffusionRank, baselines
│   ├── ltr.py
│   ├── ensemble.py
│   ├── diffusion_rank.py
│   ├── rgcn_ranker.py
│   └── schemas.py
├── evaluation/         # Ranking metrics (NDCG, Precision@K, MAP, significance tests)
├── analysis/           # Ablation studies, weight grid search
├── api/                # FastAPI serving layer
└── visualization/      # Plotting and reporting utilities
```

**Feature set used by the LTR model:**

- `recency_score` — exponential decay over 180 days from publication date
- `cvss_norm` — CVSS v3 base score normalised to [0, 1]
- `kev_flag` — binary; 1 if CVE appears in CISA KEV (weighted label=2 in LTR)
- `attack_flag` — binary; 1 if CVE description matches a MITRE ATT&CK technique name/alias
- `chpl_flag` — binary; 1 if CVE description matches a certified health IT product
- `is_healthcare` — broader healthcare keyword signal

**Weak supervision labels:** `KEV hit → label 2`, `other intelligence hit → label 1`, `no signal → label 0`. Grouped by publication week for LambdaRank contexts.

---

## Quickstart

```bash
# 1. Clone and create a virtual environment
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti-recommender
python -m venv .venv && source .venv/bin/activate

# 2. Install dependencies
pip install -r cti_recommender/requirements.txt

# 3. Run the ETL (fetches NVD, KEV, ATT&CK, CHPL; populates data/processed/)
python -m cti_recommender.src.core.healthcare_local    # or the script directly

# 4. Train and evaluate the LTR model
python -m cti_recommender.src.core.ltr

# 5. Run tests
PYTHONPATH=. pytest -q
```

> A CHPL API key must be set in your environment (`CHPL_API_KEY`) for live CHPL fetches. The cache in `data_cache/` is used automatically when the key is absent or the TTL has not expired.

---

## Repository Layout

```
.
├── cti_recommender/        # Python package — all source code
│   ├── src/                # Modular sub-packages (see Architecture above)
│   ├── tests/              # Pytest test suite
│   ├── notebooks/          # Exploratory analysis notebooks
│   ├── config/             # Configuration files
│   ├── requirements.txt    # Runtime dependencies
│   └── Dockerfile          # Container build
├── data/
│   ├── raw/                # Unmodified source downloads
│   └── processed/          # Parquet/CSV artefacts (not committed)
├── data_cache/             # TTL-based API response cache (not committed)
├── models/                 # Serialised model artefacts (e.g. ltr_model.pkl)
├── outputs/                # Evaluation summaries, top-K CSVs, grid-search results
├── METHODOLOGY_REPORT.md   # Full research methodology and design decisions
├── CHANGELOG.md            # Development log
└── LICENSE                 # MIT
```

---

## Tech Stack

- **Python 3.10+**
- **LightGBM** — LambdaRank learning-to-rank
- **PyTorch + PyG** — RGCN and DiffusionRank graph models
- **scikit-learn / XGBoost** — baseline models and grid search
- **pandas / pyarrow** — data wrangling and parquet I/O
- **FastAPI + Uvicorn** — optional REST API layer
- **SHAP** — feature importance and explainability
- **pytest** — test suite

---

## License

MIT — see [LICENSE](LICENSE).
