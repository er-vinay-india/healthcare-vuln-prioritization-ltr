#!/usr/bin/env python3
"""Verify README metrics by testing thesis model on 2025 data"""

import pandas as pd
import lightgbm as lgb
from src.core.cve_database import CVEDatabase
from src.features.engineering import get_default_feature_cols
from sklearn.metrics import ndcg_score
import numpy as np

print("="*70)
print("VERIFYING README METRICS")
print("="*70)

# Load database and model
print("\n1. Loading database and model...")
db = CVEDatabase()
model = lgb.Booster(model_file='models/ltr_ranker_thesis_70_30.model')

# Verify feature count
features = model.feature_name()
print(f"   Model features: {len(features)}")
print(f"   Features: {', '.join(features[:5])}...")

# Get 2025 test data
print("\n2. Loading 2025 test set...")
query = '''
SELECT c.*, e.* 
FROM cves c
LEFT JOIN enrichments e ON c.cve_id = e.cve_id
WHERE strftime('%Y', c.published) = '2025'
'''
test_df = pd.read_sql_query(query, db.conn)
print(f"   Test set (2025): {len(test_df):,} CVEs")

# Build features
print("\n3. Building features...")
feature_cols = get_default_feature_cols()
X_test = test_df[feature_cols].fillna(0)

# Predict
print("\n4. Running predictions...")
y_scores = model.predict(X_test)
y_true = test_df['label'].fillna(0).values

# Calculate NDCG scores
print("\n5. Calculating metrics...")
ndcg_5 = ndcg_score([y_true], [y_scores], k=5)
ndcg_10 = ndcg_score([y_true], [y_scores], k=10)
ndcg_20 = ndcg_score([y_true], [y_scores], k=20)
ndcg_50 = ndcg_score([y_true], [y_scores], k=50)

# CVSS baseline
cvss_scores = test_df['cvss'].fillna(0).values
ndcg_cvss_5 = ndcg_score([y_true], [cvss_scores], k=5)
ndcg_cvss_10 = ndcg_score([y_true], [cvss_scores], k=10)
ndcg_cvss_20 = ndcg_score([y_true], [cvss_scores], k=20)
ndcg_cvss_50 = ndcg_score([y_true], [cvss_scores], k=50)

# Print results
print("\n" + "="*70)
print("RESULTS")
print("="*70)

print("\nThesis Model (16 features) - 2025 Test Set:")
print(f"  NDCG@5:  {ndcg_5:.3f}")
print(f"  NDCG@10: {ndcg_10:.3f}")
print(f"  NDCG@20: {ndcg_20:.3f}")
print(f"  NDCG@50: {ndcg_50:.3f}")

print("\nCVSS Baseline:")
print(f"  NDCG@5:  {ndcg_cvss_5:.3f}")
print(f"  NDCG@10: {ndcg_cvss_10:.3f}")
print(f"  NDCG@20: {ndcg_cvss_20:.3f}")
print(f"  NDCG@50: {ndcg_cvss_50:.3f}")

print("\nImprovement:")
improvements = {
    5: ((ndcg_5 - ndcg_cvss_5) / ndcg_cvss_5) * 100,
    10: ((ndcg_10 - ndcg_cvss_10) / ndcg_cvss_10) * 100,
    20: ((ndcg_20 - ndcg_cvss_20) / ndcg_cvss_20) * 100,
    50: ((ndcg_50 - ndcg_cvss_50) / ndcg_cvss_50) * 100,
}
for k, imp in improvements.items():
    print(f"  NDCG@{k:2d}: +{imp:5.1f}%")

print("\n" + "="*70)
print("README VERIFICATION")
print("="*70)

# Check README claims
readme_claims = {
    "NDCG@5": (0.187, ndcg_5),
    "NDCG@10": (0.203, ndcg_10),
    "NDCG@20": (0.220, ndcg_20),
    "NDCG@50": (0.251, ndcg_50),
    "CVSS NDCG@20": (0.171, ndcg_cvss_20),
}

for metric, (claimed, actual) in readme_claims.items():
    diff = abs(claimed - actual)
    status = "✓" if diff < 0.01 else "✗"
    print(f"{status} {metric:15s}: README={claimed:.3f}, Actual={actual:.3f}, Diff={diff:.3f}")

db.close()
print("\n" + "="*70)
