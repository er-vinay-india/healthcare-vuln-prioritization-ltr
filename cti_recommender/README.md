# CTI Healthcare Vulnerability Recommender

A multi-source vulnerability scoring and ranking system specifically designed for healthcare organizations. Integrates data from NVD, CISA KEV, MITRE ATT&CK, and CHPL to provide actionable vulnerability prioritization.

## Project Objective

**Build an intelligent vulnerability prioritization system that answers:** *"Which vulnerabilities should healthcare security teams patch first?"*

Traditional vulnerability management relies on CVSS scores alone. This system combines:
- **NVD** - 226K+ CVEs with severity scores
- **CISA KEV** - 1,460+ actively exploited vulnerabilities
- **MITRE ATT&CK** - 835 adversary techniques and tactics
- **CHPL** - 6,900 certified healthcare IT products
- **EPSS** - Exploit prediction scores
- **Healthcare Mappings** - Breach and medical device data

**Current Performance:**
- Model: NDCG@10=0.75+, Confidence-Weighted LambdaRank
- Multi-source: 6 authoritative sources (NVD, KEV, EPSS, Healthcare, ATT&CK, CHPL)
- Database: 226,320 CVEs (2018-2025)
- Healthcare coverage: 125,606 CVEs (55.5%)
- ATT&CK mapping: 83,574 CVEs (36.9%)
- CHPL integration: 706 products, 5,089 CVEs matched
- **NEW**: GPU-accelerated training (Apple M5/CUDA support)

---

## Quick Start

### Run the Final Notebook

```bash
# Activate environment
source venv/bin/activate

# Launch Jupyter
jupyter notebook notebooks/CVE_Prioritization_Final.ipynb
```

**The consolidated notebook** (`CVE_Prioritization_Final.ipynb`) provides a complete pipeline:
1. Data loading from SQLite database
2. Feature engineering (CVSS, EPSS, KEV, ATT&CK, Healthcare)
3. Weak label construction with confidence scores
4. Temporal train/val/test split
5. Confidence-weighted LambdaRank training
6. Evaluation against baselines
7. Explainability (Feature importance, SHAP)
8. Results summary

**Streamlined**: 400 lines (down from 2,425 lines) using modular functions.

---

## Architecture Diagrams

### Project Architecture
![Project Architecture](docs/diagrams/project_architecture.svg)

### Data Pipeline
![Data Pipeline](docs/diagrams/data_pipeline.svg)

### LTR Model
![LTR Model](docs/diagrams/ltr_model.svg)

> **Diagram Sources:** See [docs/diagrams/](docs/diagrams/) for Mermaid source files (.mmd)

---

## Project Structure

```
cti_recommender/
├── notebooks/
│   └── CVE_Prioritization_Final.ipynb    # Production notebook (streamlined)
├── archive/notebooks/                     # Original research notebooks
│   ├── healthcare_cve_prioritization_ltr.ipynb
│   └── confidence_weighted_weak_supervision_ltr.ipynb
├── src/                                   # Modular source code
│   ├── core/                             # Core vulnerability scoring
│   │   ├── cve_database.py              # SQLite database interface
│   │   └── cti_recommender.py           # Multi-source scoring engine
│   ├── data/                             # Data loading and preprocessing
│   │   ├── loader.py                    # CVE data loading
│   │   └── preprocessing.py             # Data cleaning
│   ├── features/                         # Feature engineering
│   │   ├── engineering.py               # Feature extraction
│   │   └── labeling.py                  # Weak label construction ⭐
│   ├── models/                           # ML models
│   │   ├── ltr.py                       # LambdaRank training ⭐
│   │   ├── baselines.py                 # Baseline models
│   │   ├── diffusion_imputer.py         # DiffusionRank (GPU)
│   │   ├── rgcn_ranker.py               # Graph neural network (GPU)
│   │   └── bootstrap_ensemble.py        # Uncertainty-aware ensemble
│   ├── evaluation/                       # Evaluation metrics
│   │   ├── metrics.py                   # NDCG@K, Precision@K ⭐
│   │   ├── comparison.py                # Model comparison
│   │   └── significance.py              # Statistical tests
│   ├── visualization/                    # Visualization
│   │   ├── eda.py                       # Exploratory data analysis
│   │   └── explainability.py            # Feature importance, SHAP ⭐
│   ├── utils/                            # Utilities
│   │   ├── temporal.py                  # Temporal splits ⭐
│   │   ├── config.py                    # Configuration management
│   │   └── device_manager.py            # GPU device detection ⭐
│   └── analysis/                         # Data quality & healthcare mapping
│       ├── data_quality.py              # Validation framework
│       └── healthcare_mapper.py         # CHPL/breach mapping
├── cache/                                # Cached API responses
├── data/                                 # SQLite database
├── models/                               # Trained models
├── outputs/                              # Results and reports
├── scripts/                              # Utility scripts
├── tests/                                # Unit tests
└── docs/                                 # Documentation

⭐ = New modular functions (Phase 3 refactor)
```
│   │   └── healthcare_mapping.py # Healthcare relevance detection
│   └── utils/                    # Utility modules
│       ├── cache_manager.py     # Unified cache management
│       └── logging_config.py    # Structured logging
│
├── scripts/                      # Executable scripts
│   ├── enrich_cves.py           # Consolidated enrichment pipeline
│   ├── train_ltr.py             # LTR model training
│   ├── temporal_validation.py   # Temporal validation
│   ├── generate_report.py       # DOCX report generator
│   └── analyze/                 # Analysis scripts
│       ├── enrichment_stats.py  # Show enrichment statistics
│       ├── coverage_analysis.py # CHPL/KEV coverage analysis
│       ├── medical_terms.py     # Medical vendor analysis
│       ├── ablation_study.py    # Feature ablation study
│       └── feature_correlation.py # Feature correlation matrix
│
├── notebooks/                    # Jupyter notebooks
│   └── healthcare_cve_prioritization_ltr.ipynb  # Main analysis notebook
│
├── tests/                        # Unit tests
│   ├── test_attack_mapping.py
│   ├── test_features_chpl.py
│   └── test_ltr_smoke.py
│
├── data/                         # Configuration & database
│   ├── cve_database.db          # SQLite database (226K+ CVEs)
│   └── config/
│       └── healthcare_mapping.csv  # 142 healthcare patterns
│
├── cache/                        # API response cache (organized by source)
│   ├── nvd/                     # NVD API responses
│   ├── epss/                    # EPSS scores cache
│   ├── kev/                     # CISA KEV catalog
│   ├── attack/                  # MITRE ATT&CK techniques
│   └── chpl/                    # CHPL healthcare products
│
├── models/                       # Trained ML models
│   ├── ltr_ranker.model         # Full LightGBM model
│   └── ltr_ranker_pruned.model  # Pruned model
│
├── outputs/                      # Generated results
│   ├── top_scored.csv           # Scored CVEs
│   └── *.csv                    # Analysis outputs
│
├── docs/                         # Documentation
│   ├── README.md                # Documentation index
│   ├── QUICKSTART.md            # Installation & basic usage
│   ├── API.md                   # REST API & Docker deployment
│   ├── DEVELOPMENT.md           # Development guide
│   ├── RESEARCH_CONTEXT.md      # Literature review
│   ├── guides/                  # Technical guides
│   │   ├── ARCHITECTURE_GUIDE.md
│   │   └── MIGRATION_GUIDE.md
│   └── reports/                 # Generated analysis reports
│
├── archive/                      # Archived/unused files
│   ├── adhoc_scripts/           # Consolidated scripts (Phase 2)
│   ├── historical_docs/         # Old documentation
│   └── notebooks/               # Old experiment notebooks
│
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

---

## Quick Start

**For detailed installation and usage instructions, see [docs/QUICKSTART.md](docs/QUICKSTART.md)**

### 1. Setup Environment

```bash
# Clone repository
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti_recommender

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Enrich CVE Data

```bash
python scripts/enrich_cves.py --years 1 --workers 4
```

**Features:**
- Downloads CVEs from NVD (last N years)
- Enriches with KEV, EPSS, CHPL, ATT&CK, healthcare flags
- Calculates multi-level labels (0-5 scale)
- Single consolidated pipeline (no manual steps)

**Optional flags:**
- `--skip-attack` - Skip ATT&CK technique mapping
- `--skip-chpl` - Skip CHPL product matching

### 3. Train LTR Model

```bash
python scripts/train_ltr.py
```

**Outputs:**
- `models/ltr_model.pkl` - Trained LightGBM model
- `models/ltr_model_pruned.pkl` - Optimized model (fewer features)
- Console: Training metrics, NDCG@10, P@100

### 4. Run Temporal Validation

```bash
python scripts/temporal_validation.py
```

**Outputs:**
- Temporal split evaluation (3-month windows)
- Per-window NDCG@5/10/20 metrics
- Overall performance summary

### 5. Run Analysis Scripts

```bash
# View enrichment statistics
python scripts/analyze/enrichment_stats.py

# Analyze CHPL/KEV coverage
python scripts/analyze/coverage_analysis.py

# Medical vendor analysis
python scripts/analyze/medical_terms.py

# Feature ablation study
python scripts/analyze/ablation_study.py

# Feature correlation matrix
python scripts/analyze/feature_correlation.py
```

**Outputs:** Console summaries, plots in `outputs/plots/`

### 6. Explore with Jupyter

```bash
jupyter notebook notebooks/healthcare_cve_prioritization_ltr.ipynb
```

---

## Configuration

### Scoring Weights (Phase 1 Calibrated)

```python
w_recency = 0.25  # Recency score (0-1)
w_kev     = 0.30  # KEV membership (0/1)
w_cvss    = 0.15  # CVSS normalized (0-1)
w_health  = 0.10  # Healthcare relevance (0/1)
w_chpl    = 0.15  # CHPL product match (0/1)
w_attack  = 0.05  # ATT&CK technique (0/1)
```

### Data Sources

| Source | URL | Update Frequency |
|--------|-----|------------------|
| **NVD** | `services.nvd.nist.gov` | Daily (auto-cached 30 days) |
| **CISA KEV** | `cisa.gov/known_exploited_vulnerabilities.csv` | Weekly |
| **MITRE ATT&CK** | `github.com/mitre/cti` | Monthly |
| **CHPL** | `chpl.healthit.gov/rest` | Weekly (currently unavailable) |

---

## Phase 1 Results

### Data Quality Metrics

| Metric | Value | Status |
|--------|-------|--------|
| Total CVEs | 2,000 | - |
| Missing CVSS | 34.4% | - Acceptable |
| KEV Entries | 1,488 | - |
| ATT&CK Techniques | 835 | - |
| CHPL Products | 0 (API issue) | - External |
| Healthcare Flagged | 66.6% (1,333/2,000) | - |

### Top-20 Performance

| Metric | Before | After Calibration | Change |
|--------|--------|------------------|--------|
| Healthcare Precision | 60% | 50% | -10% (CHPL unavailable) |
| KEV Detection | 5% (1/20) | **15% (3/20)** | - +200% |
| Healthcare Vendors | 0 | 1 (Epic) | - Improved |

---

## Development

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test
python -m pytest tests/test_attack_mapping.py -v
```

### Adding New Features

1. Create feature module in `src/core/` or `src/analysis/`
2. Add unit tests in `tests/`
3. Update `src/__init__.py` exports
4. Document in README.md

### Code Style

- Follow PEP 8
- Type hints for public functions
- Docstrings for all modules/classes
- Maximum line length: 100 characters

---

## Roadmap

### - Phase 1: Data Quality & Validation (COMPLETE)
- - Data quality framework
- - Healthcare mapping system
- - Bug fixes & weight calibration
- - Automated audit pipeline

### - Phase 2: Refactoring & Consolidation (COMPLETE)
- - Consolidated enrichment pipeline (9 steps → 4 steps)
- - Database schema standardization
- - Script cleanup (24 scripts → 10 main scripts)
- - Analysis scripts organization
- - EPSS integration
- - Multi-level labels (0-5 scale)

### Phase 3: Advanced Features (NEXT)
- [ ] Enhanced ATT&CK technique weighting
- [ ] Temporal trend analysis
- [ ] Vendor risk scoring
- [ ] Scanner integration (Nessus, Qualys)

### Phase 4: LTR Model Optimization
- [x] Hyperparameter tuning (Phase 2 complete)
- [x] Model comparison (LightGBM selected)
- [x] Feature importance analysis (Phase 2 complete)
- [ ] Advanced feature engineering
- [ ] Ensemble models

### Phase 5: Evaluation & Ablation
- [x] Precision@K metrics (Phase 2 complete)
- [x] NDCG@K metrics (Phase 2 complete)
- [x] Ablation studies (Phase 2 complete)
- [x] Temporal validation (Phase 2 complete)
- [ ] Cross-dataset validation

### Phase 6: Production Interface
- [ ] CLI tool
- [ ] REST API (FastAPI)
- [ ] Automated refresh pipeline
- [ ] Docker containerization

### Phase 7: Advanced Analytics
- [ ] Vendor dashboards
- [ ] Trend analysis
- [ ] What-if scenarios
- [ ] Real-time alerting

### Phase 8: Research Publication
- [ ] Methodology paper
- [ ] Benchmark dataset
- [ ] Baseline comparisons
- [ ] Conference submission

---

## Documentation

**Complete documentation available in [docs/](docs/) directory:**

- **[Quick Start](docs/QUICKSTART.md)** - Installation and basic usage
- **[API Guide](docs/API.md)** - REST API and Docker deployment
- **[Development Guide](docs/DEVELOPMENT.md)** - Contributing and development setup
- **[Architecture Guide](ARCHITECTURE_GUIDE.md)** - System architecture and design
- **[Migration Guide](MIGRATION_GUIDE.md)** - Upgrading from older versions
- **[Research Context](docs/RESEARCH_CONTEXT.md)** - Academic background and literature review

---

## Contributing

This is a research project. Contributions welcome for:
- Healthcare vendor/product patterns
- CHPL API workarounds
- Label quality improvements
- Evaluation metrics

**See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for development guidelines.**

---

## License

[Specify License]

---

## Authors

- Vinay Kumar Sharma (@er-vinay-india)
- [Add other contributors]

---

## References

1. **NVD API**: https://nvd.nist.gov/developers
2. **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. **MITRE ATT&CK**: https://attack.mitre.org/
4. **CHPL**: https://chpl.healthit.gov/

---

## Support

For issues or questions:
- **Documentation**: See [docs/README.md](docs/README.md) for complete documentation index
- **GitHub Issues**: https://github.com/er-vinay-india/cti-recommender/issues
- **Email**: [your-email]

---

**Last Updated:** 2026-01-17  
**Version:** 2.0.0  
**Status:** Phase 4 Complete - - Production-Ready with Improvements
