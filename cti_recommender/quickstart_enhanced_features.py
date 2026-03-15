"""
Quick Start: Using Enhanced Features for Model Training
========================================================

This script shows how to use the enhanced features in your existing pipeline.
"""

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.model_selection import train_test_split
import sys
sys.path.append('.')

from src.features.enhanced_features import get_enhanced_feature_columns

print("="*80)
print("ENHANCED FEATURES - QUICK START GUIDE")
print("="*80)

# STEP 1: Load enhanced dataset
print("\n[STEP 1] Load Enhanced Dataset")
print("-" * 60)
df = pd.read_csv('outputs/features/features_enhanced_latest.csv')
print(f"✓ Loaded {len(df):,} CVEs")
print(f"✓ Total columns: {len(df.columns)}")

# STEP 2: Define feature sets
print("\n[STEP 2] Define Feature Sets")
print("-" * 60)

# Original 16 features (from engineering.py)
ORIGINAL_FEATURES = [
    'cvss_norm', 
    'epss_score',
    'kev_flag',  # OK to use as feature for testing methodology
    'has_attack',
    'attack_technique_count',
    'is_healthcare',
    'healthcare_score',
    'chpl_flag',
    'days_since_published',
    'recency_score',
    'cvss_epss_product',
    'kev_healthcare_interaction',
    'published_week',
    'cvss_missing_flag',
    'epss_missing_flag',
    'epss_percentile_missing_flag',
]

# New enhanced features (26 available)
ENHANCED_FEATURES = get_enhanced_feature_columns()
# Filter to only features present in dataset (exclude description NLP)
ENHANCED_AVAILABLE = [f for f in ENHANCED_FEATURES 
                      if f in df.columns 
                      and not f.startswith('desc_')
                      and f != 'description_cvss_risk']

print(f"Original features: {len(ORIGINAL_FEATURES)}")
print(f"Enhanced features available: {len(ENHANCED_AVAILABLE)}")
print(f"\nEnhanced features:")
for feat in ENHANCED_AVAILABLE:
    print(f"  - {feat}")

# STEP 3: Create combined feature set
print("\n[STEP 3] Create Combined Feature Set")
print("-" * 60)

# Option A: Original only
FEATURES_ORIGINAL_ONLY = [f for f in ORIGINAL_FEATURES if f in df.columns]

# Option B: Enhanced only (for comparison)
FEATURES_ENHANCED_ONLY = ENHANCED_AVAILABLE.copy()

# Option C: Combined (RECOMMENDED)
FEATURES_COMBINED = FEATURES_ORIGINAL_ONLY + ENHANCED_AVAILABLE

print(f"✓ Original only: {len(FEATURES_ORIGINAL_ONLY)} features")
print(f"✓ Enhanced only: {len(FEATURES_ENHANCED_ONLY)} features")
print(f"✓ Combined (RECOMMENDED): {len(FEATURES_COMBINED)} features")

# STEP 4: Prepare data for training
print("\n[STEP 4] Prepare Data for Training")
print("-" * 60)

# Remove rows without labels
df_labeled = df[df['soft_label'].notna()].copy()
print(f"✓ CVEs with labels: {len(df_labeled):,}")

# Prepare features and labels
X = df_labeled[FEATURES_COMBINED]
y = df_labeled['soft_label']
groups = df_labeled['published'].apply(lambda x: pd.to_datetime(x).year)

print(f"✓ Feature matrix: {X.shape}")
print(f"✓ Label distribution:")
for label in sorted(y.unique()):
    count = (y == label).sum()
    pct = 100 * count / len(y)
    print(f"    Label {int(label)}: {count:,} ({pct:.1f}%)")

# STEP 5: Feature importance preview
print("\n[STEP 5] Feature Categories")
print("-" * 60)

cvss_features = [f for f in FEATURES_COMBINED if f.startswith('cvss_')]
cwe_features = [f for f in FEATURES_COMBINED if f.startswith('cwe_')]
interaction_features = [f for f in FEATURES_COMBINED if any(x in f for x in ['healthcare', 'product', 'interaction', 'risk'])]

print(f"CVSS features: {len(cvss_features)}")
print(f"  {', '.join(cvss_features[:5])}...")
print(f"\nCWE features: {len(cwe_features)}")
print(f"  {', '.join(cwe_features)}")
print(f"\nInteraction features: {len(interaction_features)}")
print(f"  {', '.join(interaction_features)}")

# STEP 6: Sample training code
print("\n[STEP 6] Sample Training Code")
print("-" * 60)
print("""
# Temporal split (2018-2024 train, 2025 test)
df_train = df_labeled[df_labeled['published'] < '2025-01-01']
df_test = df_labeled[df_labeled['published'] >= '2025-01-01']

X_train = df_train[FEATURES_COMBINED]
y_train = df_train['soft_label']
X_test = df_test[FEATURES_COMBINED]
y_test = df_test['soft_label']

# Train LightGBM model
params = {
    'objective': 'lambdarank',
    'metric': 'ndcg',
    'ndcg_eval_at': [5, 10, 20],
    'learning_rate': 0.1,
    'num_leaves': 31,
    'min_data_in_leaf': 20,
}

# Create query groups
train_groups = df_train.groupby('published').size().values
test_groups = df_test.groupby('published').size().values

train_data = lgb.Dataset(X_train, y_train, group=train_groups)
test_data = lgb.Dataset(X_test, y_test, group=test_groups, reference=train_data)

model = lgb.train(
    params,
    train_data,
    num_boost_round=100,
    valid_sets=[test_data],
    callbacks=[lgb.early_stopping(10)]
)

# Evaluate
y_pred = model.predict(X_test)
# Calculate NDCG@20...
""")

print("\n" + "="*80)
print("✓ QUICK START GUIDE COMPLETE")
print("="*80)
print(f"\nYou now have {len(FEATURES_COMBINED)} features ready for training!")
print(f"\nDataset: outputs/features/features_enhanced_latest.csv")
print(f"Documentation: ENHANCED_FEATURES_SUMMARY.md")
