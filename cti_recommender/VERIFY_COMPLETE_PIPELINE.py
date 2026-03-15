#!/usr/bin/env python3
"""
COMPLETE PIPELINE VERIFICATION
Systematically verify every step from data → features → labels → training → evaluation
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.metrics import ndcg_score
from datetime import datetime

print("="*80)
print("COMPLETE PIPELINE VERIFICATION")
print("="*80)

# Step 1: Load features file from Feature_Engineering notebook
print("\n[STEP 1] Loading Features from Feature_Engineering notebook output...")
features_file = Path("outputs/features/features_with_labels_20260226.csv")
df = pd.read_csv(features_file, low_memory=False)
df['published'] = pd.to_datetime(df['published'], format='ISO8601')

print(f"✓ Loaded: {len(df):,} CVEs")
print(f"  Date range: {df['published'].min().date()} to {df['published'].max().date()}")
print(f"  Columns: {len(df.columns)}")

# Step 2: Verify Features
print("\n[STEP 2] Verifying Feature Engineering...")
from src.features.engineering import get_default_feature_cols
feature_cols = get_default_feature_cols()

print(f"✓ Expected features: {len(feature_cols)}")
for i, feat in enumerate(feature_cols, 1):
    exists = feat in df.columns
    status = "✓" if exists else "✗"
    print(f"  {status} {i:2d}. {feat}")

# Check which features are missing
missing_feats = [f for f in feature_cols if f not in df.columns]
extra_feats = [f for f in df.columns if f in feature_cols]

if missing_feats:
    print(f"\n⚠️  Missing features: {missing_feats}")
else:
    print(f"\n✓ All {len(feature_cols)} features present!")

# Step 3: Verify Labels
print("\n[STEP 3] Verifying Weak Labels...")
print(f"  Label column: {'soft_label' if 'soft_label' in df.columns else 'MISSING'}")
print(f"  Confidence column: {'label_confidence' if 'label_confidence' in df.columns else 'MISSING'}")

if 'soft_label' in df.columns:
    print(f"\n  Label distribution:")
    label_dist = df['soft_label'].value_counts().sort_index()
    for label, count in label_dist.items():
        pct = (count / len(df)) * 100
        print(f"    Label {int(label)}: {count:,} ({pct:.2f}%)")
    
    print(f"\n  Confidence stats:")
    print(f"    Mean: {df['label_confidence'].mean():.3f}")
    print(f"    Median: {df['label_confidence'].median():.3f}")
    high_conf = (df['label_confidence'] >= 0.7).sum()
    print(f"    High confidence (≥0.7): {high_conf:,} ({high_conf/len(df)*100:.1f}%)")

# Step 4: Create Temporal Splits (2018-2024 train, 2025 test)
print("\n[STEP 4] Creating Temporal Splits (2024/2025)...")
df_train = df[df['published'].dt.year <= 2024].copy()
df_test = df[df['published'].dt.year == 2025].copy()

print(f"✓ Train (2018-2024): {len(df_train):,} CVEs")
print(f"✓ Test (2025):       {len(df_test):,} CVEs")

# Check for labels in test set
if 'soft_label' in df_test.columns:
    test_labels_dist = df_test['soft_label'].value_counts().sort_index()
    print(f"\n  Test set label distribution:")
    for label, count in test_labels_dist.items():
        print(f"    Label {int(label)}: {count:,}")

# Step 5: Train Model with 16 Features
print("\n[STEP 5] Training LambdaMART with 16 features...")

# Get available features
available_feats = [f for f in feature_cols if f in df.columns]
print(f"  Using {len(available_feats)} features")

X_train = df_train[available_feats].fillna(0).values
y_train = df_train['soft_label'].values if 'soft_label' in df_train.columns else df_train.get('label', 0).values
w_train = df_train['label_confidence'].values if 'label_confidence' in df_train.columns else np.ones(len(df_train))

X_test = df_test[available_feats].fillna(0).values
y_test = df_test['soft_label'].values if 'soft_label' in df_test.columns else df_test.get('label', 0).values

# Create query groups (weekly grouping for ranking)
df_train['week'] = df_train['published'].dt.to_period('W').astype(str)
df_test['week'] = df_test['published'].dt.to_period('W').astype(str)

train_groups = df_train.groupby('week').size().values
test_groups = df_test.groupby('week').size().values

print(f"  Train groups (weeks): {len(train_groups)}")
print(f"  Test groups (weeks):  {len(test_groups)}")

# Train LightGBM LambdaMART
params = {
    'objective': 'lambdarank',
    'metric': 'ndcg',
    'ndcg_eval_at': [5, 10, 20, 50],
    'boosting_type': 'gbdt',
    'num_leaves': 31,
    'learning_rate': 0.05,
    'feature_fraction': 0.8,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'min_data_in_leaf': 20,
    'max_depth': 6,
    'verbose': -1,
    'seed': 42
}

train_data = lgb.Dataset(
    X_train,
    label=y_train,
    group=train_groups,
    weight=w_train
)

test_data = lgb.Dataset(
    X_test,
    label=y_test,
    group=test_groups,
    reference=train_data
)

print("  Training...")
model = lgb.train(
    params,
    train_data,
    valid_sets=[test_data],
    num_boost_round=500,
    callbacks=[lgb.early_stopping(30, verbose=False)]
)

print(f"✓ Training complete!")
print(f"  Best iteration: {model.best_iteration}")
print(f"  Best score: {model.best_score}")

# Step 6: Evaluate on 2025 Test Set
print("\n[STEP 6] Evaluating on 2025 Test Set...")

# Generate predictions
y_pred = model.predict(X_test)

# Calculate NDCG scores
ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
ndcg_50 = ndcg_score([y_test], [y_pred], k=50)

print(f"\n✓ LambdaMART (16 features) - 2025 Test Set:")
print(f"  NDCG@5:  {ndcg_5:.4f}")
print(f"  NDCG@10: {ndcg_10:.4f}")
print(f"  NDCG@20: {ndcg_20:.4f}")
print(f"  NDCG@50: {ndcg_50:.4f}")

# CVSS Baseline
cvss_scores = df_test['cvss'].fillna(0).values
ndcg_cvss_5 = ndcg_score([y_test], [cvss_scores], k=5)
ndcg_cvss_10 = ndcg_score([y_test], [cvss_scores], k=10)
ndcg_cvss_20 = ndcg_score([y_test], [cvss_scores], k=20)
ndcg_cvss_50 = ndcg_score([y_test], [cvss_scores], k=50)

print(f"\n✓ CVSS Baseline:")
print(f"  NDCG@5:  {ndcg_cvss_5:.4f}")
print(f"  NDCG@10: {ndcg_cvss_10:.4f}")
print(f"  NDCG@20: {ndcg_cvss_20:.4f}")
print(f"  NDCG@50: {ndcg_cvss_50:.4f}")

# Calculate improvement
imp_5 = ((ndcg_5 - ndcg_cvss_5) / ndcg_cvss_5) * 100
imp_10 = ((ndcg_10 - ndcg_cvss_10) / ndcg_cvss_10) * 100
imp_20 = ((ndcg_20 - ndcg_cvss_20) / ndcg_cvss_20) * 100
imp_50 = ((ndcg_50 - ndcg_cvss_50) / ndcg_cvss_50) * 100

print(f"\n✓ Improvement:")
print(f"  NDCG@5:  {imp_5:+.1f}%")
print(f"  NDCG@10: {imp_10:+.1f}%")
print(f"  NDCG@20: {imp_20:+.1f}%")
print(f"  NDCG@50: {imp_50:+.1f}%")

# Step 7: Compare with README claims
print("\n[STEP 7] Comparing with README Claims...")
readme_claims = {
    "NDCG@5": 0.187,
    "NDCG@10": 0.203,
    "NDCG@20": 0.220,
    "NDCG@50": 0.251,
    "CVSS NDCG@20": 0.171
}

actual_results = {
    "NDCG@5": ndcg_5,
    "NDCG@10": ndcg_10,
    "NDCG@20": ndcg_20,
    "NDCG@50": ndcg_50,
    "CVSS NDCG@20": ndcg_cvss_20
}

print(f"\n{'Metric':<15} {'README':<10} {'Actual':<10} {'Diff':<10} {'Status'}")
print("-" * 60)
for metric in readme_claims:
    claimed = readme_claims[metric]
    actual = actual_results[metric]
    diff = actual - claimed
    status = "✓" if abs(diff) < 0.01 else "✗ MISMATCH"
    print(f"{metric:<15} {claimed:<10.3f} {actual:<10.3f} {diff:+.3f}     {status}")

print("\n" + "="*80)
print("VERIFICATION COMPLETE")
print("="*80)

# Step 8: Save model for comparison
print("\n[STEP 8] Saving verification model...")
model_path = Path("models/ltr_ranker_verification.model")
model.save_model(str(model_path))
print(f"✓ Model saved to: {model_path}")

# Save results
results_df = pd.DataFrame({
    'Metric': list(actual_results.keys()),
    'README_Claim': [readme_claims.get(m, 0) for m in actual_results.keys()],
    'Actual_Result': list(actual_results.values()),
    'Difference': [actual_results[m] - readme_claims.get(m, 0) for m in actual_results.keys()]
})
results_path = Path("outputs/README_VERIFICATION_RESULTS.csv")
results_df.to_csv(results_path, index=False)
print(f"✓ Results saved to: {results_path}")

print("\n✓✓✓ PIPELINE VERIFICATION COMPLETE ✓✓✓\n")
