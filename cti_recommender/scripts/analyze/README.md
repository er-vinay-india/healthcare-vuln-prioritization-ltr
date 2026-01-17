# Analysis Scripts

This directory contains scripts for analyzing the CTI recommender system's data, features, and model performance.

## Scripts Overview

### Model Analysis

#### `ablation_study.py`
**Purpose:** Evaluate the incremental contribution of each feature set  
**Use Cases:**
- Understand feature importance
- Validate new feature additions
- Identify redundant features

**Usage:**
```bash
python scripts/analyze/ablation_study.py
```

**Output:**
- NDCG scores for different feature combinations
- Feature set contributions (KEV, EPSS, Healthcare, ATT&CK, CHPL)
- Recommendations on which features to keep/remove

---

#### `feature_correlation.py`
**Purpose:** Analyze feature correlations and multicollinearity  
**Use Cases:**
- Detect highly correlated features
- Identify potential feature redundancy
- Guide feature engineering decisions

**Usage:**
```bash
python scripts/analyze/feature_correlation.py
```

**Output:**
- Correlation matrix heatmap
- List of highly correlated feature pairs
- Variance Inflation Factor (VIF) scores

---

### Data Analysis

#### `coverage_analysis.py`
**Purpose:** Analyze healthcare technology data coverage vs ecosystem  
**Use Cases:**
- Identify gaps in healthcare vendor coverage
- Understand dataset completeness
- Prioritize data acquisition efforts

**Usage:**
```bash
python scripts/analyze/coverage_analysis.py
```

**Output:**
- Coverage statistics by vendor/product
- Gap analysis report
- Recommendations for additional data sources

---

#### `medical_terms.py`
**Purpose:** Analyze CVE descriptions for medical vendors and terms  
**Use Cases:**
- Find medical vendors not in CHPL
- Discover new healthcare-related terminology
- Validate healthcare keyword detection

**Usage:**
```bash
python scripts/analyze/medical_terms.py
```

**Output:**
- Medical vendor frequency analysis
- Terms found in CVEs but not in CHPL
- Recommendations for expanding healthcare detection

---

#### `enrichment_stats.py`
**Purpose:** Show database enrichment summary and sample CVEs  
**Use Cases:**
- Quick overview of enrichment status
- Validate enrichment pipeline ran successfully
- Sample high-priority CVEs

**Usage:**
```bash
python scripts/analyze/enrichment_stats.py
```

**Output:**
- Total CVE count and date range
- Enrichment coverage (KEV, EPSS, healthcare, etc.)
- Label distribution breakdown
- Sample high-priority CVEs

---

## Typical Analysis Workflow

### After Enrichment
```bash
# 1. Check enrichment stats
python scripts/analyze/enrichment_stats.py

# 2. Analyze coverage
python scripts/analyze/coverage_analysis.py

# 3. Check feature correlations
python scripts/analyze/feature_correlation.py
```

### Before Model Training
```bash
# 4. Run ablation study to validate features
python scripts/analyze/ablation_study.py
```

### Understanding Healthcare Detection
```bash
# 5. Analyze medical terms and gaps
python scripts/analyze/medical_terms.py
```

---

## Output Locations

Most analysis scripts output to:
- **Console:** Summary statistics and key findings
- **`outputs/`:** Generated reports, charts, and detailed analysis files
- **`logs/`:** Detailed execution logs (if structured logging enabled)

---

## Dependencies

All scripts require:
- Database enrichment completed (`scripts/enrich_cves.py`)
- Core modules: `src/core/cve_database.py`, `src/analysis/*`
- Standard ML libraries: pandas, numpy, scikit-learn, matplotlib

---

## Adding New Analysis Scripts

When adding new analysis scripts to this directory:

1. **Follow naming convention:** `<analysis_type>_<subject>.py`
   - Good: `model_performance.py`, `vendor_coverage.py`
   - Bad: `script1.py`, `analysis.py`

2. **Include docstring:** Brief description and usage examples

3. **Add to this README:** Update the Scripts Overview section

4. **Use structured logging:** Import from `src.utils.logging_config`

5. **Output to `outputs/`:** Don't clutter project root

---

## Archived Scripts

See `archive/adhoc_scripts/` for historical analysis scripts that are no longer actively maintained.
