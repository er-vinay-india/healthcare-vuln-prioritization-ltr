# CTI Healthcare Vulnerability Recommender

A multi-source vulnerability scoring and ranking system specifically designed for healthcare organizations. Integrates data from NVD, CISA KEV, MITRE ATT&CK, and CHPL to provide actionable vulnerability prioritization.

## 🎯 Project Objective

**Build an intelligent vulnerability prioritization system that answers:** *"Which vulnerabilities should healthcare security teams patch first?"*

Traditional vulnerability management relies on CVSS scores alone. This system combines:
- **NVD** - 2,000+ recent CVEs with severity scores
- **CISA KEV** - 1,460+ actively exploited vulnerabilities
- **MITRE ATT&CK** - 835 adversary techniques and tactics
- **CHPL** - 6,900 certified healthcare IT products

**Current Performance:**
- ✅ Model: NDCG@10=0.75, P@100=100%
- ✅ Multi-source: 6 authoritative sources (NVD, KEV, EPSS, Healthcare, ATT&CK, CHPL)
- ✅ Database: 226,320 CVEs (2018-2025)
- ✅ Healthcare coverage: 125,606 CVEs (55.5%)
- ✅ ATT&CK mapping: 83,574 CVEs (36.9%)
- ✅ CHPL integration: 706 products, 5,089 CVEs matched
- ✅ Ablation study: +27.5% NDCG improvement vs baseline

---

## 📁 Project Structure

```
cti_recommender/
├── src/                          # Source code
│   ├── core/                     # Core vulnerability scoring
│   │   ├── cti_recommender.py   # Multi-source scoring engine
│   │   └── ltr.py               # Learning-to-rank (LightGBM)
│   ├── analysis/                 # Data quality & healthcare mapping
│   │   ├── data_quality.py      # Validation framework
│   │   └── healthcare_mapping.py # Healthcare relevance detection
│   └── utils/                    # Utility modules (future)
│
├── scripts/                      # Executable scripts
│   ├── audit_phase1.py          # Data quality audit
│   ├── rescore_weights.py       # Weight calibration tool
│   └── generate_report.py       # DOCX report generator
│
├── notebooks/                    # Jupyter notebooks
│   └── simple_cti_recommender.ipynb  # Main analysis notebook
│
├── tests/                        # Unit tests
│   ├── test_attack_mapping.py
│   ├── test_features_chpl.py
│   └── test_ltr_smoke.py
│
├── data/                         # Configuration data
│   └── config/
│       └── healthcare_mapping.csv  # 142 healthcare patterns
│
├── data_cache/                   # API response cache (auto-generated)
├── outputs/                      # Generated results
│   ├── top20_recalibrated.csv   # Current top-20 recommendations
│   ├── top_scored.csv           # Full scored dataset
│   └── phase1_quality_report.txt
│
├── docs/                         # Documentation
│   ├── PHASE1_SUMMARY.md        # Phase 1 audit results
│   ├── PHASE1_FIXES.md          # Bug fixes & calibration
│   ├── RESEARCH_CONTEXT.md      # Literature review & gaps
│   └── reports/                 # Generated reports & plots
│
├── archive/                      # Archived/unused files
│   ├── notebooks/               # Old experiment notebooks
│   ├── experiments/             # Experimental scripts
│   └── titanic_data/            # Unrelated Kaggle data
│
├── requirements.txt             # Python dependencies
└── README.md                    # This file
```

---

## 🚀 Quick Start

### 1. Setup Environment

```bash
# Clone repository
git clone https://github.com/er-vinay-india/cti-recommender.git
cd cti_recommender

# Create virtual environment
python3.14 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run Data Quality Audit

```bash
python scripts/audit_phase1.py
```

**Outputs:**
- `outputs/phase1_quality_report.txt` - Comprehensive quality report
- `outputs/top20_enriched.csv` - Top-20 with healthcare features
- `data/config/healthcare_mapping.csv` - Healthcare patterns

### 3. Generate Recommendations

```bash
python scripts/rescore_weights.py
```

**Outputs:**
- `outputs/top20_recalibrated.csv` - Current top-20 CVEs
- `outputs/top_scored.csv` - Full dataset with scores
- Console: Comparison of old vs new weights

### 4. Explore with Jupyter

```bash
jupyter notebook notebooks/simple_cti_recommender.ipynb
```

---

## ⚙️ Configuration

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

## 📊 Phase 1 Results

### Data Quality Metrics

| Metric | Value | Status |
|--------|-------|--------|
| Total CVEs | 2,000 | ✅ |
| Missing CVSS | 34.4% | ⚠️ Acceptable |
| KEV Entries | 1,488 | ✅ |
| ATT&CK Techniques | 835 | ✅ |
| CHPL Products | 0 (API issue) | ⚠️ External |
| Healthcare Flagged | 66.6% (1,333/2,000) | ✅ |

### Top-20 Performance

| Metric | Before | After Calibration | Change |
|--------|--------|------------------|--------|
| Healthcare Precision | 60% | 50% | -10% (CHPL unavailable) |
| KEV Detection | 5% (1/20) | **15% (3/20)** | ✅ +200% |
| Healthcare Vendors | 0 | 1 (Epic) | ✅ Improved |

---

## 🔧 Development

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

## 📈 Roadmap

### ✅ Phase 1: Data Quality & Validation (COMPLETE)
- ✅ Data quality framework
- ✅ Healthcare mapping system
- ✅ Bug fixes & weight calibration
- ✅ Automated audit pipeline

### 🔄 Phase 2: Improved Labeling Strategy (NEXT)
- [ ] Integrate EPSS scores
- [ ] Add ExploitDB references
- [ ] Create curated healthcare CVE dataset
- [ ] Multi-level labels (0-5 scale)

### ⏳ Phase 3: LTR Model Optimization
- [ ] Hyperparameter tuning
- [ ] Cross-validation
- [ ] Model comparison (LightGBM vs XGBoost vs CatBoost)
- [ ] Feature importance analysis

### ⏳ Phase 4: Evaluation & Ablation
- [ ] Precision@5/10/20/50
- [ ] NDCG@K metrics
- [ ] Ablation studies
- [ ] Temporal validation

### ⏳ Phase 5: Production Interface
- [ ] CLI tool
- [ ] REST API (FastAPI)
- [ ] Automated refresh pipeline
- [ ] Docker containerization

### ⏳ Phase 6: Advanced Analytics
- [ ] Vendor dashboards
- [ ] Trend analysis
- [ ] Scanner integration
- [ ] What-if scenarios

### ⏳ Phase 7: Research Publication
- [ ] Methodology paper
- [ ] Benchmark dataset
- [ ] Baseline comparisons
- [ ] Conference submission

---

## 🤝 Contributing

This is a research project. Contributions welcome for:
- Healthcare vendor/product patterns
- CHPL API workarounds
- Label quality improvements
- Evaluation metrics

---

## 📝 License

[Specify License]

---

## 👥 Authors

- Vinay Kumar Sharma (@er-vinay-india)
- [Add other contributors]

---

## 📚 References

1. **NVD API**: https://nvd.nist.gov/developers
2. **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. **MITRE ATT&CK**: https://attack.mitre.org/
4. **CHPL**: https://chpl.healthit.gov/

---

## 🆘 Support

For issues or questions:
- GitHub Issues: https://github.com/er-vinay-india/cti-recommender/issues
- Email: [your-email]

---

**Last Updated:** 2026-01-17  
**Version:** 2.0.0  
**Status:** Phase 4 Complete ✅ - Production-Ready with Improvements
