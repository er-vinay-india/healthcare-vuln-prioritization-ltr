# Notebook Execution Guide

This directory uses a consistent 5-step flow.

## Execution Sequence

### STEP 1: Data Ingestion Pipeline
**File:** `STEP_1_Data_Ingestion_Pipeline.ipynb`
**Purpose:** Load NVD and enrichment sources (KEV, EPSS, ATT&CK, CHPL), build cache/database artifacts.
**Required:** Yes

### STEP 2: Compute Features
**File:** `STEP_2_Compute_Features.ipynb`
**Purpose:** Build feature-ready data and perform data-quality checks/inspection.
**Required:** Yes

### STEP 3: Feature Engineering + Labels
**File:** `STEP_3_Feature_Engineering_Labels.ipynb`
**Purpose:** Generate training labels and final feature matrix.
**Main output:** `outputs/features/features_with_labels_YYYYMMDD.csv`
**Required:** Yes

Optional enhanced feature pass after STEP 3:

```bash
python apply_enhanced_features.py
```

### STEP 4: All Models Training
**File:** `STEP_4_All_Models_Training.ipynb`
**Purpose:** Train baseline and advanced models using a common temporal protocol.
**Models:** CVSS baseline, heuristic baseline, LambdaMART, and advanced model training blocks.
**Required:** Yes

### STEP 5: Model Comparison and Evaluation
**File:** `STEP_5_Model_Comparison_And_Evaluation.ipynb`
**Purpose:** Compare trained models and produce evaluation artifacts/tables for reporting.
**Focus:** NDCG@K, Precision@K, capture metrics, subgroup/robustness analysis.
**Required:** Recommended

## Quick Start

1. Run `STEP_1_Data_Ingestion_Pipeline.ipynb`.
2. Run `STEP_2_Compute_Features.ipynb`.
3. Run `STEP_3_Feature_Engineering_Labels.ipynb`.
4. Optional: run `python apply_enhanced_features.py`.
5. Run `STEP_4_All_Models_Training.ipynb`.
6. Run `STEP_5_Model_Comparison_And_Evaluation.ipynb`.

## Notes

- Step numbers are intentionally continuous and fixed (`STEP_1` to `STEP_5`).
- If you change notebook names, update references in both notebooks and this guide.
- For repeatable thesis outputs, keep the same feature file and split strategy across Steps 4 and 5.

**Last Updated:** 2026-03-08
