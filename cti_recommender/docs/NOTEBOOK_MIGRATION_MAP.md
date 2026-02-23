# Notebook Migration Mapping

**Date**: 2026-02-23
**Status**: Migration Plan

---

## Summary

- **CVE_Prioritization_Advanced.ipynb**: 52 cells (40 code, 12 markdown)
- **CVE_Prioritization_Final.ipynb**: 30 cells (15 code, 15 markdown)

---

## CVE_Prioritization_Advanced.ipynb → New Notebooks

| Cell # | Type | Purpose | Content | → Destination | Status |
|--------|------|---------|---------|---------------|--------|
| 1 | mark | documentation | # Advanced CVE Prioritization with Graph | 2_EDA_Analysis | ✅ |
| 2 | code | imports | # Core imports | 2_EDA_Analysis | ✅ |
| 3 | mark | section_header | ## 1. Data Loading & Preprocessing | 2_EDA_Analysis | ✅ |
| 4 | code | analysis | # Connect to database | 2_EDA_Analysis | ✅ |
| 5 | code | data_loading | # Load CVE data with enrichments | 2_EDA_Analysis | ✅ |
| 6 | code | analysis | # Extract CWE information | 2_EDA_Analysis | ✅ |
| 7 | code | model_training | # Temporal split for validation | 4_Model_Training | ✅ |
| 8 | mark | section_header | ## 2. Baseline: LambdaRank Model | 4_Model_Training | ✅ |
| 9 | code | imports | # Load pre-trained model | 2_EDA_Analysis | ✅ |
| 10 | code | model_training | # Feature engineering for baseline | 4_Model_Training | ✅ |
| 11 | code | imports | # Baseline predictions | 2_EDA_Analysis | ✅ |
| 12 | mark | section_header | ## 3. Graph Construction | 3_Feature_Engineering | ✅ |
| 13 | code | model_training | # 3.1: CVE-CWE Bipartite Graph | 4_Model_Training | ✅ |
| 14 | code | model_training | # 3.2: CVE Similarity Graph | 4_Model_Training | ✅ |
| 15 | mark | section_header | ## 4. DiffusionRank Algorithm | 2_EDA_Analysis | ✅ |
| 16 | code | function_defini | def diffusion_rank(G, seed_scores, alpha | → src/module (refactor) | ✅ |
| 17 | code | model_training | # Create seed scores from baseline model | 4_Model_Training | ✅ |
| 18 | code | visualization | # Visualize score distribution | 2_EDA_Analysis | ✅ |
| 19 | mark | section_header | ## 5. Model Comparison | 4_Model_Training | ✅ |
| 20 | code | evaluation | # Evaluate DiffusionRank on test set | 4_Model_Training | ✅ |
| 21 | code | visualization | # Visualize comparison | 2_EDA_Analysis | ✅ |
| 22 | mark | section_header | ## 6. Top-K Analysis | 4_Model_Training | ✅ |
| 23 | code | analysis | # Top-20 CVEs from each model | 2_EDA_Analysis | ✅ |
| 24 | code | analysis | # Overlap analysis | 2_EDA_Analysis | ✅ |
| 25 | mark | section_header | ## 7. Summary & Conclusions | 4_Model_Training | ✅ |
| 26 | code | model_training | # Summary statistics | 4_Model_Training | ✅ |
| 27 | mark | section_header | ## 7.5. RGCN (Relational Graph Convoluti | 4_Model_Training | ✅ |
| 28 | code | imports | # 7.5.1: Import SIMPLE RGCN (macOS-safe  | 2_EDA_Analysis | ✅ |
| 29 | code | model_training | # 7.5.2: Prepare features and labels for | 4_Model_Training | ✅ |
| 30 | code | model_training | # 7.5.3: Prepare CVE-CWE mapping for RGC | 4_Model_Training | ✅ |
| 31 | code | imports | # 7.5.4: Train SIMPLE RGCN (macOS-safe,  | 2_EDA_Analysis | ✅ |
| 32 | code | visualization | # 7.5.5: Visualize RGCN training curves | 2_EDA_Analysis | ✅ |
| 33 | code | model_training | # 7.5.6: Prepare features for RGCN predi | 4_Model_Training | ✅ |
| 34 | code | model_training | # 7.5.7: Build CVE-CWE mapping for predi | 4_Model_Training | ✅ |
| 35 | code | imports | # 7.5.8: Generate RGCN predictions (Simp | 2_EDA_Analysis | ✅ |
| 36 | code | evaluation | # 7.5.9: Evaluate RGCN model | 4_Model_Training | ✅ |
| 37 | mark | section_header | ## 8. Ensemble Methods | 2_EDA_Analysis | ✅ |
| 38 | code | imports | # Import ensemble module (force reload) | 2_EDA_Analysis | ✅ |
| 39 | code | model_training | # Prepare predictions for ensemble | 4_Model_Training | ✅ |
| 40 | code | evaluation | # Evaluate model diversity | 4_Model_Training | ✅ |
| 41 | code | model_training | # 1. Simple Average Ensemble | 4_Model_Training | ✅ |
| 42 | code | model_training | # 2. Weighted Average Ensemble (learns o | 4_Model_Training | ✅ |
| 43 | code | model_training | # 3. Meta-Learning Ensemble (Ridge regre | 4_Model_Training | ✅ |
| 44 | code | analysis | # 4. Rank Fusion Ensemble | 2_EDA_Analysis | ✅ |
| 45 | code | evaluation | # Evaluate all ensemble methods | 4_Model_Training | ✅ |
| 46 | code | visualization | # Visualize ensemble performance | 2_EDA_Analysis | ✅ |
| 47 | mark | section_header | ## 9. Bootstrap Ensemble with Uncertaint | 2_EDA_Analysis | ✅ |
| 48 | code | model_training | # Bootstrap ensemble for uncertainty qua | 4_Model_Training | ✅ |
| 49 | code | model_training | # Analyze high uncertainty CVEs | 4_Model_Training | ✅ |
| 50 | code | visualization | # Visualize uncertainty | 2_EDA_Analysis | ✅ |
| 51 | mark | section_header | ## 10. Final Summary & Recommendations | 2_EDA_Analysis | ✅ |
| 52 | code | model_training | # Final performance summary | 4_Model_Training | ✅ |


## CVE_Prioritization_Final.ipynb → New Notebooks

| Cell # | Type | Purpose | Content | → Destination | Status |
|--------|------|---------|---------|---------------|--------|
| 1 | mark | documentation | # CVE Prioritization with Confidence-Wei | 2_EDA_Analysis | ✅ |
| 2 | mark | section_header | ## 1. Setup & Configuration | 2_EDA_Analysis | ✅ |
| 3 | code | imports | """ | 2_EDA_Analysis | ✅ |
| 4 | mark | section_header | ## 2. Data Loading | 2_EDA_Analysis | ✅ |
| 5 | code | data_loading | # Load data from CVEDatabase | 2_EDA_Analysis | ✅ |
| 6 | mark | section_header | ## 3 Exploratory Data Analysis (EDA) | 2_EDA_Analysis | ✅ |
| 7 | code | imports | # Import EDA visualization functions | 2_EDA_Analysis | ✅ |
| 8 | mark | section_header | ## 4. Feature Engineering | 3_Feature_Engineering | ✅ |
| 9 | code | imports | # Feature Engineering using modular func | 2_EDA_Analysis | ✅ |
| 10 | code | model_training | # ====================================== | 4_Model_Training | ✅ |
| 11 | mark | section_header | ## 5. Weak Label Construction with Confi | 3_Feature_Engineering | ✅ |
| 12 | code | analysis | # Build weak labels using modular functi | 2_EDA_Analysis | ✅ |
| 13 | mark | section_header | ## 6. Temporal Split (Train/Val/Test) | 4_Model_Training | ✅ |
| 14 | code | imports | # Force reload temporal module to pick u | 2_EDA_Analysis | ✅ |
| 15 | mark | section_header | ## 7. Model Training | 4_Model_Training | ✅ |
| 16 | code | model_training | # Train LambdaRank using modular functio | 4_Model_Training | ✅ |
| 17 | mark | section_header | ### 7.2 Comparison Models (Optional - Fo | 3_Feature_Engineering | ✅ |
| 18 | code | imports | # Comparison models - only run if needed | 2_EDA_Analysis | ✅ |
| 19 | mark | section_header | ## 8. Evaluation on Test Set | 4_Model_Training | ✅ |
| 20 | code | feature_enginee | # Prepare test data | 3_Feature_Engineering | ✅ |
| 21 | mark | section_header | ### 8.2 Compute Ranking Metrics | 2_EDA_Analysis | ✅ |
| 22 | code | evaluation | # Evaluate all models | 4_Model_Training | ✅ |
| 23 | mark | section_header | ## 9. Explainability Analysis | 3_Feature_Engineering | ✅ |
| 24 | code | visualization | # Plot feature importance (both gain and | 2_EDA_Analysis | ✅ |
| 25 | mark | section_header | ### 9.2 SHAP Explainability | 2_EDA_Analysis | ✅ |
| 26 | code | visualization | # SHAP analysis on test set sample | 2_EDA_Analysis | ✅ |
| 27 | mark | section_header | ### 9.3 Individual CVE Explanations | 2_EDA_Analysis | ✅ |
| 28 | code | feature_enginee | # Show detailed explanations for diverse | 3_Feature_Engineering | ✅ |
| 29 | mark | section_header | ## 10. Results Summary & Conclusions | 2_EDA_Analysis | ✅ |
| 30 | code | model_training | print("\n" + "=" * 70) | 4_Model_Training | ✅ |


---

## Destination Notebooks

1. **Data_Ingestion_Pipeline.ipynb** ✅ Already created
2. **EDA_Analysis.ipynb** - Data loading, visualizations, quality checks
3. **Feature_Engineering.ipynb** - Feature extraction, label construction
4. **Model_Training_And_Evaluation.ipynb** - Training, evaluation, comparison

---

## Verification Checklist

- [ ] All cells accounted for in mapping
- [ ] All functions preserved (notebook or module)
- [ ] All imports present in new notebooks
- [ ] No duplicate content across notebooks
- [ ] Logical flow maintained
- [ ] External outputs configured for plots