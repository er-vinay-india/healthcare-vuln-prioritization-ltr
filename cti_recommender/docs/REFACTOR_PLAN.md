# Notebook Refactoring Plan: Phase 1 - Inventory & Mapping

**Date:** 2026-01-27  
**Status:** Phase 1 - Inventory Complete  
**Goal:** Consolidate two notebooks into one final notebook + Python modules

---

## Executive Summary

We have two notebooks with significant overlap and complementary content:
1. **healthcare_cve_prioritization_ltr.ipynb** (1,948 lines) - Original LTR implementation
2. **confidence_weighted_weak_supervision_ltr.ipynb** (2,425 lines) - Enhanced with comparison study

**Target:** Create ONE final notebook (~1,000 lines) + well-organized Python modules

---

## Current Notebook Inventory

### Notebook 1: healthcare_cve_prioritization_ltr.ipynb

**Major Sections:**
1. Setup & Environment (cells 1-6)
2. Data Loading from SQLite (cells 8, 10)
3. Data Quality Checks (cell 10)
4. EDA Visualizations (cells 13-17)
5. Feature Engineering (cell 20)
6. Train/Test Split (cell 22)
7. Model Training - LightGBM LambdaMART (cell 24)
8. Evaluation & Metrics (cells 26-34)
9. Ablation Study (cell 36)
10. Conclusions

**Key Functions Defined In-Notebook:**
- `build_healthcare_features()` - Feature extraction
- `prepare_ranking_data()` - LTR data preparation
- `train_lambdamart()` - Model training
- `evaluate_ranking()` - NDCG, Precision@K metrics
- `compute_baseline_scores()` - CVSS-only, heuristic baselines

**Data Flow:**
```
SQLite DB → Data Loading → Feature Engineering → Train/Test Split → 
LightGBM Training → Evaluation → Ablation Study → Results
```

---

### Notebook 2: confidence_weighted_weak_supervision_ltr.ipynb

**Major Sections:**
1. Setup & Configuration (cells 1-3)
2. Data Loading from CVEDatabase (cells 4-6)
3. Feature Engineering Pipeline (cells 7-8)
4. Weak Label Construction (cells 9-10) **[NEW - Not in NB1]**
5. Label Diagnostics (cells 11-12) **[NEW]**
6. Temporal Split (cells 13-14)
7. LTR Training Function (cells 15-16)
8. Baseline Rankers (cells 17-19)
9. Model Training - Confidence-Weighted LTR (cells 20-21)
10. Feature Importance & SHAP (cells 22-25)
11. Cross-Validation (cells 26-28) **[NEW]**
12. Temporal Evaluation (cells 29-31)
13. Baseline Comparison (cells 32-33)
14. **COMPARISON STUDY** (cells 34-54) **[NEW - MAJOR ADDITION]**
    - DiffusionRank Imputer (cells 36-38)
    - RGCN Relational Model (cells 39-41)
    - Bootstrap Ensemble (cells 42-44)
    - Comparison Training (cell 45)
    - Predictions (cell 46)
    - Evaluation (cell 47)
    - Statistical Significance (cell 48)
    - Explainability (cell 49-50)
    - Uncertainty Analysis (cell 51-52)
    - Final Summary (cell 53-54)

**Key Functions Defined In-Notebook:**
- `build_features()` - Feature engineering
- `build_weak_labels()` - Soft label + confidence construction **[NEW]**
- `print_label_diagnostics()` - Label distribution analysis
- `make_temporal_splits()` - Temporal train/val/test split
- `prepare_ranking_data()` - LTR data prep (similar to NB1)
- `train_lambdarank_with_conf()` - Confidence-weighted training **[NEW]**
- `compute_cvss_only_scores()` - Baseline 1
- `compute_heuristic_scores()` - Baseline 2
- `compute_legacy_label_scores()` - Baseline 3
- `evaluate_scores_by_week()` - Temporal evaluation **[NEW]**

**Comparison Study Classes (IN-NOTEBOOK):**
- `DenoisingMLP` - Neural network for DiffusionRank
- `DiffusionRankImputer` - Label imputation model
- `SimpleRGCN` - Graph neural network
- `RGCNRanker` - CVE-vendor graph ranker
- `BootstrapEnsemble` - Uncertainty-aware ensemble (wrapper for LightGBM)

**Data Flow:**
```
SQLite DB → Feature Engineering → Weak Label Construction → 
Temporal Split → Confidence-Weighted LTR + Comparison Models (DiffusionRank, RGCN, Ensemble) → 
Evaluation & Comparison → Statistical Tests → Results
```

---

## Overlap Analysis

### Shared Functionality
| Function | NB1 | NB2 | Notes |
|----------|-----|-----|-------|
| Data Loading | ✓ | ✓ | Same SQLite source, slightly different queries |
| Feature Engineering | ✓ | ✓ | Similar but NB2 more comprehensive |
| Train/Test Split | ✓ | ✓ | NB2 adds validation set |
| LTR Training | ✓ | ✓ | NB2 adds confidence weighting **[Key Innovation]** |
| Baseline Comparison | ✓ | ✓ | NB2 more comprehensive |
| Evaluation Metrics | ✓ | ✓ | Similar, NB2 adds temporal evaluation |

### Unique to NB1
- More detailed EDA visualizations (Plotly charts)
- Ablation study implementation
- SHAP explainability for single model

### Unique to NB2 (MAJOR ADDITIONS)
- **Weak supervision with confidence scores** (core innovation)
- **Label diagnostics and quality checks**
- **Comparison study: DiffusionRank, RGCN, Bootstrap Ensemble**
- **GPU device manager integration**
- **Statistical significance testing**
- **Uncertainty quantification**
- **Full-scale training (10K samples, GPU-accelerated)**

---

## GPU Usage Analysis

### Current State
- **NB1:** No GPU usage (CPU-only LightGBM)
- **NB2:** GPU-enabled for neural models via `device_manager`
  - DiffusionRank: PyTorch model on GPU (MPS/CUDA)
  - RGCN: PyTorch Geometric on GPU
  - LightGBM: CPU-only (no GPU support)

### GPU Configuration in NB2
```python
from src.utils.device_manager import get_device_manager
device_manager = get_device_manager()  # Auto-detects MPS/CUDA/CPU
# Models initialized with device=None (auto-detect)
```

---

## Proposed Module Structure

### Target Package Layout
```
src/
├── data/
│   ├── __init__.py
│   ├── loader.py              # CVE database loading, queries
│   └── preprocessing.py       # Data cleaning, filtering
├── features/
│   ├── __init__.py
│   ├── engineering.py         # Feature extraction (build_features)
│   └── labeling.py            # Weak label construction, diagnostics
├── models/
│   ├── __init__.py
│   ├── ltr.py                 # LambdaRank training (confidence-weighted)
│   ├── diffusion_imputer.py   # DiffusionRank (ALREADY EXISTS)
│   ├── rgcn_ranker.py         # RGCN (ALREADY EXISTS)
│   ├── bootstrap_ensemble.py  # Bootstrap ensemble (ALREADY EXISTS)
│   └── baselines.py           # CVSS-only, heuristic, legacy baselines
├── evaluation/
│   ├── __init__.py
│   ├── metrics.py             # NDCG, Precision@K, MAP
│   ├── comparison.py          # Model comparison, ranking
│   └── significance.py        # Statistical tests (Wilcoxon, etc.)
├── visualization/
│   ├── __init__.py
│   ├── eda.py                 # EDA plots (temporal, distributions)
│   └── explainability.py      # SHAP, feature importance
└── utils/
    ├── __init__.py
    ├── device_manager.py      # GPU device detection (ALREADY EXISTS)
    ├── temporal.py            # Temporal splitting, validation
    └── config.py              # Configuration management
```

### Functions → Modules Mapping

**src/data/loader.py:**
- `load_cves_from_db()` - Load CVEs with enrichments
- `get_data_summary()` - Data quality checks

**src/features/engineering.py:**
- `build_features()` - Extract all 12-14 features
- `normalize_features()` - Feature scaling
- `add_interaction_features()` - CVSS×EPSS, KEV×Healthcare, etc.

**src/features/labeling.py:**
- `build_weak_labels()` - Soft label + confidence construction
- `print_label_diagnostics()` - Distribution analysis
- `validate_label_quality()` - Quality metrics

**src/models/ltr.py:**
- `prepare_ranking_data()` - Format data for LambdaMART
- `train_lambdarank()` - Train with confidence weights
- `cross_validate()` - K-fold CV for hyperparameters
- `save_model()` / `load_model()` - Model persistence

**src/models/baselines.py:**
- `compute_cvss_only_scores()`
- `compute_heuristic_scores()`
- `compute_legacy_label_scores()`

**src/evaluation/metrics.py:**
- `evaluate_ranking()` - NDCG@K, Precision@K, MAP
- `evaluate_by_week()` - Temporal evaluation
- `compute_ranking_metrics()` - Comprehensive metrics

**src/evaluation/comparison.py:**
- `compare_models()` - Multi-model comparison table
- `rank_models()` - Sort by NDCG
- `save_comparison_results()` - Export to CSV

**src/evaluation/significance.py:**
- `wilcoxon_test()` - Pairwise significance testing
- `bonferroni_correction()` - Multiple testing correction

**src/visualization/eda.py:**
- `plot_temporal_trends()` - CVE publication over time
- `plot_cvss_distribution()` - CVSS histogram
- `plot_kev_analysis()` - KEV coverage
- `plot_feature_correlations()` - Correlation matrix

**src/visualization/explainability.py:**
- `plot_feature_importance()` - LightGBM importance
- `plot_shap_summary()` - SHAP values
- `analyze_top_predictions()` - Top-K CVE analysis

**src/utils/temporal.py:**
- `make_temporal_splits()` - Train/val/test split by date
- `validate_temporal_leakage()` - Check for data leakage

**src/utils/config.py:**
- `load_config()` - Load from YAML/JSON
- `get_feature_cols()` - Feature list management

---

## Final Notebook Structure

### Proposed: CVE_Prioritization_Final.ipynb

**Section 1: Setup & Configuration**
- Imports from refactored modules
- GPU device initialization
- Configuration loading

**Section 2: Data Loading & Quality**
- Load CVEs from database (via `src.data.loader`)
- Data quality summary

**Section 3: EDA (Streamlined)**
- Temporal trends
- CVSS/EPSS distributions
- KEV/Healthcare coverage
- (Use `src.visualization.eda`)

**Section 4: Feature Engineering & Labeling**
- Feature extraction (via `src.features.engineering`)
- Weak label construction (via `src.features.labeling`)
- Label diagnostics

**Section 5: Temporal Split**
- Train/val/test split (via `src.utils.temporal`)
- Split summary

**Section 6: Model Training**
- **6A: Confidence-Weighted LTR** (primary model)
- **6B: Comparison Models** (orchestration only)
  - DiffusionRank (via `src.models.diffusion_imputer`)
  - RGCN (via `src.models.rgcn_ranker`)
  - Bootstrap Ensemble (via `src.models.bootstrap_ensemble`)
- **6C: Baselines** (via `src.models.baselines`)

**Section 7: Evaluation & Comparison**
- Generate predictions for all models
- Compute metrics (via `src.evaluation.metrics`)
- Model comparison table (via `src.evaluation.comparison`)
- Statistical significance (via `src.evaluation.significance`)

**Section 8: Explainability**
- Feature importance (via `src.visualization.explainability`)
- SHAP analysis
- Top-K predictions analysis

**Section 9: Results & Conclusions**
- Summary statistics
- Key findings
- Recommendations

**Estimated Size:** ~600-800 lines (down from 2,425)

---

## Phase 2 Plan: Create Module Skeleton

### Step 2.1: Create Package Structure
```bash
mkdir -p src/data src/features src/evaluation src/visualization
touch src/data/__init__.py src/features/__init__.py 
touch src/evaluation/__init__.py src/visualization/__init__.py
```

### Step 2.2: Create Empty Module Files
```bash
touch src/data/loader.py src/data/preprocessing.py
touch src/features/engineering.py src/features/labeling.py
touch src/models/ltr.py src/models/baselines.py
touch src/evaluation/metrics.py src/evaluation/comparison.py src/evaluation/significance.py
touch src/visualization/eda.py src/visualization/explainability.py
touch src/utils/temporal.py src/utils/config.py
```

### Step 2.3: Add Module Docstrings
- Add comprehensive docstrings to each module
- Define function signatures (empty implementations)

---

## Phase 3 Plan: Incremental Function Migration

### Group 1: Data Loading (Low Risk)
**Priority:** High  
**Estimated Time:** 15 minutes

1. Move `load_cves_from_db()` from notebooks → `src/data/loader.py`
2. Move `get_data_summary()` → `src/data/loader.py`
3. Update imports in NB2
4. Run data loading cells in NB2
5. Verify identical output
6. **Git commit:** `refactor: Move data loading to src/data/loader`

### Group 2: Feature Engineering (Medium Risk)
**Priority:** High  
**Estimated Time:** 30 minutes

1. Move `build_features()` → `src/features/engineering.py`
2. Update imports in NB2
3. Run feature engineering cells
4. Verify feature matrix matches
5. **Git commit:** `refactor: Move feature engineering to src/features`

### Group 3: Weak Labeling (Medium Risk)
**Priority:** High (Core Innovation)  
**Estimated Time:** 30 minutes

1. Move `build_weak_labels()` → `src/features/labeling.py`
2. Move `print_label_diagnostics()` → `src/features/labeling.py`
3. Update imports
4. Run labeling cells
5. Verify label distributions match
6. **Git commit:** `refactor: Move weak labeling to src/features`

### Group 4: LTR Model Training (Medium Risk)
**Priority:** High  
**Estimated Time:** 45 minutes

1. Move `prepare_ranking_data()` → `src/models/ltr.py`
2. Move `train_lambdarank()` → `src/models/ltr.py`
3. Add cross-validation function
4. Update imports
5. Run training cells
6. Verify model performance matches
7. **Git commit:** `refactor: Move LTR training to src/models`

### Group 5: Baselines (Low Risk)
**Priority:** Medium  
**Estimated Time:** 15 minutes

1. Move baseline functions → `src/models/baselines.py`
2. Update imports
3. Run baseline cells
4. Verify scores match
5. **Git commit:** `refactor: Move baselines to src/models`

### Group 6: Evaluation (Medium Risk)
**Priority:** High  
**Estimated Time:** 30 minutes

1. Move `evaluate_ranking()` → `src/evaluation/metrics.py`
2. Move `evaluate_by_week()` → `src/evaluation/metrics.py`
3. Move comparison logic → `src/evaluation/comparison.py`
4. Move significance tests → `src/evaluation/significance.py`
5. Update imports
6. Run evaluation cells
7. Verify metrics match
8. **Git commit:** `refactor: Move evaluation to src/evaluation`

### Group 7: Visualization (Low Risk)
**Priority:** Low (can defer)  
**Estimated Time:** 45 minutes

1. Move EDA functions → `src/visualization/eda.py`
2. Move SHAP functions → `src/visualization/explainability.py`
3. Update imports
4. Run visualization cells
5. Verify plots render
6. **Git commit:** `refactor: Move visualization to src/visualization`

### Group 8: Utilities (Low Risk)
**Priority:** Medium  
**Estimated Time:** 15 minutes

1. Move `make_temporal_splits()` → `src/utils/temporal.py`
2. Create config management → `src/utils/config.py`
3. Update imports
4. Run utility cells
5. **Git commit:** `refactor: Move utilities to src/utils`

---

## Phase 4 Plan: Build Final Notebook

### Step 4.1: Create New Notebook
```bash
cp notebooks/confidence_weighted_weak_supervision_ltr.ipynb notebooks/CVE_Prioritization_Final.ipynb
```

### Step 4.2: Refactor Notebook Structure
1. Remove all in-notebook function definitions
2. Replace with module imports
3. Keep only orchestration cells
4. Add clear markdown sections
5. Ensure GPU configuration at top

### Step 4.3: End-to-End Validation
1. Restart kernel
2. Run all cells sequentially
3. Compare metrics with original NB2:
   - NDCG@10 for all models
   - Feature importance
   - Top-20 CVE rankings
4. Document any discrepancies
5. **Git commit:** `feat: Create final consolidated notebook`

---

## Phase 5 Plan: Cleanup

### Step 5.1: Archive Old Notebooks
```bash
mkdir -p archive/notebooks
mv notebooks/healthcare_cve_prioritization_ltr.ipynb archive/notebooks/
mv notebooks/confidence_weighted_weak_supervision_ltr.ipynb archive/notebooks/
```

### Step 5.2: Update Documentation
1. Update README.md with new notebook name
2. Update docs/ references
3. Add migration guide

### Step 5.3: Final Commit
```bash
git add .
git commit -m "refactor: Complete notebook consolidation - archive old notebooks"
git push
```

---

## Risk Mitigation

### Validation Checklist (After Each Phase)
- [ ] All imports resolve correctly
- [ ] No circular dependencies
- [ ] Functions produce identical outputs
- [ ] Model metrics match exactly
- [ ] Git commit created
- [ ] Tests pass (if applicable)

### Rollback Strategy
- Each phase has a git commit
- Can revert to any previous state
- Keep old notebooks until final validation

### Testing Strategy
- Compare outputs cell-by-cell during migration
- Run full notebook after each group migration
- Final end-to-end validation before archiving

---

## Success Criteria

1. **Single Final Notebook:** < 1,000 lines, orchestration only
2. **Modular Code:** All functions in appropriate Python modules
3. **No Information Loss:** All functionality preserved
4. **GPU Support:** Properly configured and documented
5. **Maintainability:** Clear module boundaries, no duplication
6. **Reproducibility:** Identical results to original notebooks
7. **Git History:** Clear incremental commits

---

## Estimated Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 1: Inventory | ✅ Complete | 1h |
| Phase 2: Module Skeleton | 30 min | 1.5h |
| Phase 3: Function Migration | 3-4 hours | 5h |
| Phase 4: Build Final Notebook | 1-2 hours | 7h |
| Phase 5: Cleanup | 30 min | 7.5h |
| **Total** | **~7.5 hours** | |

**Note:** Timeline assumes step-by-step validation. Can be faster with parallel work but higher risk.

---

## Next Steps

1. **Review and approve this plan**
2. **Proceed to Phase 2: Create module skeleton**
3. **Begin Phase 3 with Group 1 (Data Loading)**

---

**Plan Status:** Ready for execution  
**Approval Required:** Yes  
**Risk Level:** Medium (Mitigated by incremental approach)
