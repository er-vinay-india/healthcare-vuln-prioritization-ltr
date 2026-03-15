NOTEBOOK NUMBERING STATUS
=========================

The notebook sequence is now aligned to a single continuous flow.

Current Execution Order
-----------------------
1. STEP_1_Data_Ingestion_Pipeline.ipynb
2. STEP_2_Compute_Features.ipynb
3. STEP_3_Feature_Engineering_Labels.ipynb
4. STEP_4_All_Models_Training.ipynb
5. STEP_5_Model_Comparison_And_Evaluation.ipynb

What Was Standardized
---------------------
- Removed legacy references to STEP_0 / STEP_6 / STEP_7 in sequence docs.
- Updated STEP 4 and STEP 5 notebook filenames to match the intended workflow:
  - STEP 4 = training all models.
  - STEP 5 = comparison and evaluation.
- Updated cross-references inside notebooks and notebook docs to use the new names.

Optional Enhanced Feature Pass
------------------------------
Run after STEP 3:

python apply_enhanced_features.py

Then continue with STEP 4 and STEP 5.

See `notebooks/README.md` for full usage details.
