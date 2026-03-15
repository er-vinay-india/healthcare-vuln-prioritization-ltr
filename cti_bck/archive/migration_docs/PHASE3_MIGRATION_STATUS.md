# Phase 3 Migration Status

## Completed
- ✅ Data Loading (Group 1): `src/data/loader.py`
  - `load_cves_from_db()` - Complete
  - `get_data_summary()` - Complete
  
- ✅ Feature Engineering (Group 2): `src/features/engineering.py`  
  - `build_features()` - Complete

## In Progress - Functions to Migrate

### Group 3: Weak Labeling (src/features/labeling.py)
- [ ] `build_weak_labels()` - 100+ lines
- [ ] `print_label_diagnostics()` - 80+ lines

### Group 4: LTR Training (src/models/ltr.py)
- [ ] `prepare_ranking_data()` - 30 lines
- [ ] `train_lambdarank()` - 60 lines

### Group 5: Baselines (src/models/baselines.py)  
- [ ] `compute_cvss_only_scores()` - 5 lines
- [ ] `compute_heuristic_scores()` - 15 lines
- [ ] `compute_legacy_label_scores()` - 10 lines

### Group 6: Evaluation (src/evaluation/metrics.py)
- [ ] `compute_ndcg_at_k()` - 20 lines
- [ ] `compute_precision_at_k()` - 15 lines
- [ ] `compute_ap_at_k()` - 20 lines
- [ ] `evaluate_ranker()` - 40 lines

### Group 8: Temporal (src/utils/temporal.py)
- [ ] `make_temporal_splits()` - 40 lines

## Strategy
Given time constraints, will create working implementations for all critical functions and validate end-to-end workflow before proceeding to notebook consolidation.
