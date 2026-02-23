# TODO Categorization & Action Plan
**Date:** January 27, 2026  
**Total TODOs:** 28

---

## [OK] Category 1: REMOVE (Not Needed - 15 TODOs)
**Action:** Delete stub functions entirely

### Visualization EDA (5 TODOs)
- `src/visualization/eda.py:29` - temporal trend plot
- `src/visualization/eda.py:44` - CVSS histogram  
- `src/visualization/eda.py:58` - KEV analysis plots
- `src/visualization/eda.py:77` - correlation heatmap
- `src/visualization/eda.py:91` - EPSS analysis
**Reason:** We have comprehensive explainability.py with SHAP. EDA stubs not used in production pipeline.

### Features (2 TODOs)
- `src/features/engineering.py:171` - normalization (StandardScaler)
- `src/features/engineering.py:185` - interaction features
**Reason:** Already handled in create_all_features(). These are legacy stubs.

### Utils Config (4 TODOs)
- `src/utils/config.py:23` - config loading
- `src/utils/config.py:38` - config saving
- `src/utils/config.py:52` - feature column retrieval
- `src/utils/config.py:86` - deep merge
**Reason:** Config is managed via Python constants and environment variables. Complex config system not needed.

### Evaluation Comparison (4 TODOs)
- `src/evaluation/comparison.py:28` - model comparison
- `src/evaluation/comparison.py:46` - ranking
- `src/evaluation/comparison.py:63` - save logic
- `src/evaluation/comparison.py:77` - summary generation
**Reason:** Model comparison done in notebook. This module is redundant.

---

##  Category 2: IMPLEMENT NOW (7 TODOs)
**Action:** Implement these functions (critical path)

### Data Preprocessing (2 TODOs) - HIGH PRIORITY
- `src/data/preprocessing.py:23` - cleaning logic
  **Action:** Implement basic cleaning (remove nulls, validate dates)
- `src/data/preprocessing.py:50` - filtering logic
  **Action:** Implement date range and CVSS filtering

### Baselines (1 TODO) - HIGH PRIORITY
- `src/models/baselines.py:89` - EPSS baseline
  **Action:** Already implemented! Just remove TODO comment.

### Data Loader (1 TODO) - MEDIUM PRIORITY
- `src/data/loader.py:126` - date-based query
  **Action:** Implement SQL query with date filters

### Features Labeling (1 TODO) - LOW PRIORITY
- `src/features/labeling.py:240` - quality validation
  **Action:** Add label distribution checks

### Utils Temporal (2 TODOs) - LOW PRIORITY
- `src/utils/temporal.py:75` - leakage check
  **Action:** Add assertion to verify no future data in train
- `src/utils/temporal.py:91` - temporal feature engineering
  **Action:** Document that this is done in create_all_features()

---

##  Category 3: DEFER (6 TODOs)
**Action:** Keep TODO with detailed plan, implement post-production

### Temporal Utils (1 TODO)
- `src/utils/temporal.py:115` - grouping
  **Plan:** Implement weekly/monthly grouping for temporal cross-validation

### LTR (1 TODO)
- `src/models/ltr.py:178` - CV logic
  **Plan:** Implement temporal cross-validation for hyperparameter tuning

### Evaluation Metrics (2 TODOs)
- `src/evaluation/metrics.py:110` - temporal evaluation
  **Plan:** Compute metrics across multiple time periods
- `src/evaluation/metrics.py:133` - comprehensive metrics
  **Plan:** Add MRR, ERR, and other IR metrics

### Evaluation Significance (3 TODOs)
- `src/evaluation/significance.py:29` - Wilcoxon test
  **Plan:** Statistical significance testing for model comparison
- `src/evaluation/significance.py:45` - Bonferroni correction
  **Plan:** Multiple testing correction
- `src/evaluation/significance.py:68` - pairwise testing
  **Plan:** Pairwise model comparison with correction

---

## [STATS] Summary

| Category | Count | Action |
|----------|-------|--------|
| **REMOVE** | 15 | Delete stub functions |
| **IMPLEMENT NOW** | 7 | Critical for production |
| **DEFER** | 6 | Post-production enhancements |
| **Total** | 28 | |

---

## [TARGET] Execution Plan

### Step 1: Remove Unnecessary Stubs (30 min)
```bash
# Delete entire stub files
rm src/visualization/eda.py
rm src/utils/config.py
rm src/evaluation/comparison.py

# Update __init__.py files to remove imports
# Update any references in notebooks/scripts
```

### Step 2: Implement Critical TODOs (2 hours)
1. `data/preprocessing.py` - cleaning and filtering
2. `data/loader.py` - date-based queries
3. `features/labeling.py` - quality validation
4. `utils/temporal.py` - leakage check
5. `models/baselines.py` - remove TODO (already implemented)

### Step 3: Update Deferred TODOs (15 min)
Add detailed implementation plans to each TODO comment

### Step 4: Update Documentation (15 min)
- Remove deleted modules from README
- Update architecture diagram
- Document remaining TODOs with links to GitHub issues

---

## [OK] Acceptance Criteria
- [ ] 0 TODOs in critical path modules (core/, models/, features/)
- [ ] All stub files removed
- [ ] Remaining TODOs have detailed plans
- [ ] Documentation updated
- [ ] All tests passing
