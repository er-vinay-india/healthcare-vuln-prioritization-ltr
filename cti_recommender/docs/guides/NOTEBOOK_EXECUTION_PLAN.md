# Notebook Execution Plan: Safe Phased Approach

**Date:** 2026-01-18  
**Notebook:** `notebooks/healthcare_cve_prioritization_ltr.ipynb`  
**Strategy:** Execute in phases with checkpoints and commits

---

## - PRE-FLIGHT CHECK

### Data Status (Verified):
- - **Database:** `data/cve_database.db` (319 MB) - EXISTS
- - **Cache:** `cache/` (organized by source) - EXISTS
- - **NVD Cache:** `cache/nvd/` - Multiple files (7d, 30d, enhanced)
- - **KEV Cache:** `cache/kev/kev_catalog.pkl.gz`
- - **EPSS Cache:** `cache/epss/epss_persistent.json` + daily cache
- - **ATT&CK Cache:** `cache/attack/attack_techniques.pkl.gz`
- - **CHPL Cache:** `cache/chpl/` - Products JSON & pickle

### Code Analysis (Reviewed):
**- NO API CALLS IN NOTEBOOK!** All data sources use cached data:

1. **CVEDatabase** (`cve_database.py`):
   - Reads from SQLite database
   - No external API calls
   - Already populated with 226K+ CVEs

2. **EPSSFetcher** (`epss_fetcher.py`):
   - Has `_load_persistent_cache()` method
   - Checks cache validity before API
   - Cache exists → No API calls

3. **LTRModel** (`ltr.py`):
   - Works purely with database data
   - Feature extraction is local
   - No external dependencies

4. **CacheManager** (`cache_manager.py`):
   - Only reads cache metadata
   - No API interaction

### Potential Bottlenecks Identified:
1. **Cell 20 (Feature Engineering)**: May take 1-2 min for 226K CVEs
2. **Cell 24 (Model Training)**: May take 2-5 min depending on hyperparameters
3. **Cell 36 (Ablation Study)**: Involves multiple model training runs

---

## 📋 PHASED EXECUTION PLAN

### **PHASE 1: Setup & Validation** (Cells 1-6) ⚡ Fast (~30 sec)
**Goal:** Verify environment, imports, cache status

**Cells:**
- Cell 3: Bootstrap packages (mostly already installed)
- Cell 4: Import libraries  
- Cell 6: Check cache status

**Expected Output:**
- All imports successful
- Cache summary table showing ~24 MB cached data

**Action After Phase 1:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 1 - Setup & validation complete"
git push
```

---

### **PHASE 2: Data Loading** (Cells 8, 10) ⚡ Fast (~10-20 sec)
**Goal:** Load CVE data from database

**Cells:**
- Cell 8: Load CVEs with enrichments from SQLite
- Cell 10: Data quality checks

**Expected Output:**
- ~226K CVEs loaded
- Enrichment coverage percentages
- Missing data analysis

**Why Fast:** SQLite reads are very fast, data is local

**Action After Phase 2:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 2 - Data loading complete"
git push
```

---

### **PHASE 3: EDA Visualizations** (Cells 13-17) ⚡ Medium (~1-2 min)
**Goal:** Generate exploratory plots

**Cells:**
- Cell 13: Temporal CVE trends (Plotly plot)
- Cell 14: CVSS distribution  
- Cell 15: KEV analysis
- Cell 16: Healthcare vs non-healthcare
- Cell 17: Feature correlations

**Expected Output:**
- Interactive Plotly visualizations
- Trend insights printed

**Why Medium:** Plotly rendering + aggregations on 226K rows

**Action After Phase 3:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 3 - EDA visualizations complete"
git push
```

---

### **PHASE 4: Feature Engineering** (Cell 20) - BOTTLENECK (~2-3 min)
**Goal:** Extract 14 features per CVE

**Cell:**
- Cell 20: Feature extraction using LTRModel

**Expected Output:**
- Feature matrix for all CVEs
- Feature statistics table

**Why Slow:** 
- Processing 226K CVEs
- 14 features per CVE
- Temporal calculations (days since published)

**Optimization Check:**
The code uses pandas `.apply()` which can be slow. Consider:
- Using vectorized operations
- Batch processing with `.itertuples()` instead of `.apply()`

**Action After Phase 4:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 4 - Feature engineering complete"
git push
```

---

### **PHASE 5: Train/Test Split** (Cell 22) ⚡ Fast (~5 sec)
**Goal:** Temporal split (2018-2023 train, 2024+ test)

**Cell:**
- Cell 22: Date-based split

**Expected Output:**
- Train size: ~200K CVEs
- Test size: ~26K CVEs
- Date range summary

**Action After Phase 5:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 5 - Train/test split complete"
git push
```

---

### **PHASE 6: Model Training** (Cell 24) - MAJOR BOTTLENECK (~5-10 min)
**Goal:** Train LambdaMART model

**Cell:**
- Cell 24: LTRModel.train() with temporal windows

**Expected Output:**
- Training metrics (NDCG@10, NDCG@20)
- Number of windows trained
- Model saved to disk

**Why Slow:**
- Gradient boosting on large dataset
- Multiple temporal windows (6-month windows with 3-month step)
- LightGBM iterations

**Mitigation:**
- Add timeout handling
- Print progress updates
- Consider reducing `num_boost_rounds` in initial runs

**- TIMEOUT HANDLING:**
If stuck > 10 minutes, interrupt and check:
1. Are labels correctly generated?
2. Is data properly formatted for LightGBM?
3. Consider reducing window size or date range

**Action After Phase 6:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 6 - Model training complete"
git push
```

---

### **PHASE 7: Evaluation** (Cells 26, 28, 30-31, 33-34) ⚡ Fast (~30 sec)
**Goal:** Evaluate model performance

**Cells:**
- Cell 26: Feature importance
- Cell 28: Evaluation metrics (NDCG, Precision@K)
- Cell 30: Generate predictions
- Cell 31: LTR model test set results
- Cell 33: Baseline comparison
- Cell 34: Top 20 predictions analysis

**Expected Output:**
- NDCG@10 scores
- Precision@K metrics
- Comparison table vs CVSS-only baseline
- Top-20 ranked CVEs

**Action After Phase 7:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 7 - Evaluation complete"
git push
```

---

### **PHASE 8: Ablation Study** (Cell 36) - BOTTLENECK (~3-5 min)
**Goal:** Measure feature source importance

**Cell:**
- Cell 36: Train models with different feature subsets

**Expected Output:**
- Performance comparison (Full vs -KEV vs -EPSS vs CVSS-only)
- Key insights table

**Why Slow:** Trains 4 different model variants

**Action After Phase 8:**
```bash
git add notebooks/healthcare_cve_prioritization_ltr.ipynb
git commit -m "chore: Execute Phase 8 - Ablation study complete"
git push
```

---

### **PHASE 9: Cache Management** (Cells 41, 43, 45, 47) ⚡ Fast (~10 sec)
**Goal:** Demonstrate cache operations (OPTIONAL)

**Cells:**
- Cell 41: Cache fallback testing
- Cell 43: Cache burst (nuclear option) - SKIP unless needed
- Cell 45: Clear specific cache - SKIP unless needed  
- Cell 47: Cache management guide

**- WARNING:** Cells 43 & 45 clear cache - SKIP these cells unless intentional

**Action:** These cells can be executed individually if needed for testing

---

## 🚨 RISK MITIGATION

### Timeout Strategy:
```python
# Add to top of problematic cells (24, 36)
import signal
from contextlib import contextmanager

@contextmanager
def timeout(seconds):
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Cell execution exceeded {seconds} seconds")
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

# Usage:
try:
    with timeout(600):  # 10 minute timeout
        # Cell code here
        pass
except TimeoutError as e:
    print(f"- {e}")
    print("Check logs and data quality")
```

### Progress Monitoring:
Add to Cell 24 (training):
```python
# Add verbose logging
import sys
from tqdm import tqdm

# LightGBM callback for progress
callbacks = [
    lgb.log_evaluation(period=10),
    lgb.early_stopping(stopping_rounds=50)
]
```

---

## ESTIMATED TIMELINE

| Phase | Description | Time | Risk |
|-------|-------------|------|------|
| 1 | Setup & Validation | 30s | - Low |
| 2 | Data Loading | 20s | - Low |
| 3 | EDA Visualizations | 1-2 min | ⚡ Medium |
| 4 | Feature Engineering | 2-3 min | - Medium-High |
| 5 | Train/Test Split | 5s | - Low |
| 6 | Model Training | 5-10 min | 🔴 HIGH |
| 7 | Evaluation | 30s | - Low |
| 8 | Ablation Study | 3-5 min | - Medium-High |
| 9 | Cache Management | 10s | - Low |
| **TOTAL** | **12-20 minutes** | **~15 min avg** | |

---

## EXECUTION COMMANDS

### Option 1: Manual Phase-by-Phase (RECOMMENDED)
Execute each phase sequentially in VS Code, verify output, then commit.

### Option 2: Automated with Checkpoints
```bash
# Run notebook programmatically with nbconvert
jupyter nbconvert --to notebook --execute \
    --ExecutePreprocessor.timeout=600 \
    --ExecutePreprocessor.kernel_name=python3 \
    notebooks/healthcare_cve_prioritization_ltr.ipynb \
    --output healthcare_cve_prioritization_ltr_executed.ipynb
```

---

## - VALIDATION CHECKLIST

After full execution, verify:
- [ ] All cells executed without errors
- [ ] NDCG@10 score > 0.70 (target: 0.77)
- [ ] Model file saved in `models/` or cache
- [ ] Top-20 predictions look reasonable (high CVSS, KEV membership)
- [ ] Ablation study shows KEV > EPSS > CVSS-only
- [ ] All outputs committed to git
- [ ] No API calls were made (check logs)

---

## 🐛 TROUBLESHOOTING

### If Cell 24 (Training) Hangs:
1. Check if labels are properly distributed (not all zeros)
2. Verify temporal window logic generates valid groups
3. Reduce training parameters temporarily:
   ```python
   # In LTRModel.train()
   num_boost_rounds=50  # Instead of 100+
   learning_rate=0.1     # Faster convergence
   ```

### If Feature Engineering is Slow:
Replace pandas `.apply()` with vectorized operations:
```python
# Instead of: df.apply(extract_features, axis=1)
# Use vectorized:
df['days_since_published'] = (ref_date - pd.to_datetime(df['published'])).dt.days
df['recency_score'] = np.maximum(0, 1.0 - (df['days_since_published'] / 365.0))
```

### If Memory Issues:
Process in batches:
```python
chunk_size = 50000
for i in range(0, len(df), chunk_size):
    chunk = df.iloc[i:i+chunk_size]
    # Process chunk
```

---

## NOTES

1. **No API Calls:** All data is cached - confirmed by code review
2. **Database is Read-Only:** Notebook only reads from SQLite
3. **Cache is Pre-Populated:** 24 MB of cached data exists
4. **Model Training is Local:** No external services
5. **Visualizations are Lightweight:** Plotly handles aggregations well

**READY TO EXECUTE! 🚀**
