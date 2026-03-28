"""
Test Enhanced Features - Phase 1 & 2
=====================================
Tests CVSS decomposition and CWE intelligence features.
"""

import pandas as pd
import sys
from pathlib import Path
sys.path.append('.')

from src.features.enhanced_features import extract_all_enhanced_features, get_enhanced_feature_columns

print("="*80)
print("TESTING ENHANCED FEATURES - PHASE 1 & 2")
print("="*80)


def _resolve_features_csv() -> Path:
    """Return the newest features_with_labels snapshot in outputs/features."""
    features_dir = Path('outputs/features')
    candidates = sorted(features_dir.glob('features_with_labels_*.csv'))
    if candidates:
        return candidates[-1]
    fallback = features_dir / 'features_with_labels_latest.csv'
    if fallback.exists():
        return fallback
    raise FileNotFoundError('No features_with_labels CSV found in outputs/features')

# Load sample data
print("\n[1] Loading sample data...")
features_csv = _resolve_features_csv()
print(f"  Using: {features_csv}")
df = pd.read_csv(features_csv, nrows=1000)
print(f"  Loaded {len(df)} CVEs for testing")
print(f"  Initial columns: {len(df.columns)}")

# Test feature extraction
print("\n[2] Extracting enhanced features...")
df_enhanced = extract_all_enhanced_features(df.copy())

# Verify features
print("\n[3] Feature Verification:")
print(f"  Final columns: {len(df_enhanced.columns)}")
print(f"  New features added: {len(df_enhanced.columns) - len(df.columns)}")

new_features = get_enhanced_feature_columns()
print(f"\n  Enhanced feature list ({len(new_features)} features):")
for feat in new_features:
    if feat in df_enhanced.columns:
        non_zero = (df_enhanced[feat] != 0).sum()
        print(f"    ✓ {feat}: {non_zero} non-zero ({100*non_zero/len(df_enhanced):.1f}%)")
    else:
        print(f"    ✗ {feat}: MISSING")

# Show sample
print("\n[4] Sample CVSS Decomposition:")
sample_cols = [
    'cve_id', 'cvss', 'cvss_vector', 'cvss_av', 'cvss_ac',
    'cvss_pr', 'cvss_ui', 'cvss_score_derived'
]
sample = df_enhanced[[c for c in sample_cols if c in df_enhanced.columns]].head(3)
print(sample.to_string())

print("\n[5] Sample CWE Features:")
sample_cols = [
    'cve_id', 'cwe', 'cwe_is_top25', 'cwe_is_injection',
    'cwe_is_memory_corruption', 'cwe_severity_score'
]
sample = df_enhanced[[c for c in sample_cols if c in df_enhanced.columns]].head(3)
print(sample.to_string())

# Statistics
print("\n[6] Feature Statistics:")
stats_cols = ['cvss_av', 'cvss_score_derived', 'cwe_is_top25', 'cwe_severity_score']
print(df_enhanced[stats_cols].describe())

print("\n" + "="*80)
print("✓ PHASE 1 & 2 TEST COMPLETE")
print("="*80)
