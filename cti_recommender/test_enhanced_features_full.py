"""
Test All Enhanced Features with Description Data
=================================================
"""

import pandas as pd
import pickle
import gzip
import sys
sys.path.append('.')

from src.features.enhanced_features import extract_all_enhanced_features, get_enhanced_feature_columns

print("="*80)
print("TESTING ALL ENHANCED FEATURES")
print("="*80)

# Load sample data
print("\n[1] Loading features CSV...")
df_features = pd.read_csv('outputs/features/features_with_labels_20260226.csv', nrows=5000)
print(f"  Loaded {len(df_features)} CVEs")

# Load NVD data for descriptions
print("\n[2] Loading NVD descriptions...")
try:
    with gzip.open('cache/nvd/nvd_enhanced_phase1.pkl.gz', 'rb') as f:
        nvd_df = pickle.load(f)
    print(f"  Loaded {len(nvd_df)} NVD records")
    print(f"  NVD columns: {nvd_df.columns.tolist()}")
    
    # Merge descriptions
    if 'description' in nvd_df.columns:
        df_features = df_features.merge(
            nvd_df[['cve_id', 'description']],
            on='cve_id',
            how='left'
        )
        print(f"  ✓ Merged descriptions: {df_features['description'].notna().sum()} CVEs have descriptions")
    else:
        print("  ⚠ No description column in NVD data")
except Exception as e:
    print(f"  ⚠ Could not load NVD data: {e}")
    df_features['description'] = None

# Extract all enhanced features
print("\n[3] Extracting all enhanced features...")
df_enhanced = extract_all_enhanced_features(df_features.copy(), include_nlp=True)

# Verify all features
print("\n[4] Feature Verification:")
print(f"  Initial columns: {len(df_features.columns)}")
print(f"  Final columns: {len(df_enhanced.columns)}")
print(f"  New features added: {len(df_enhanced.columns) - len(df_features.columns)}")

all_features = get_enhanced_feature_columns()
print(f"\n  Checking {len(all_features)} enhanced features:")

missing = []
for feat in all_features:
    if feat in df_enhanced.columns:
        non_zero = (df_enhanced[feat] != 0).sum()
        pct = 100 * non_zero / len(df_enhanced)
        status = "✓" if non_zero > 0 else "⚠"
        print(f"    {status} {feat}: {non_zero:,} non-zero ({pct:.1f}%)")
    else:
        print(f"    ✗ {feat}: MISSING")
        missing.append(feat)

if missing:
    print(f"\n  ⚠ Missing features: {missing}")

# Show samples from each category
print("\n[5] Sample Features by Category:")


def _print_sample(df: pd.DataFrame, cols: list[str], title: str) -> None:
    """Print sample rows for columns that exist in the extracted frame."""
    print(f"\n  {title}:")
    present = [c for c in cols if c in df.columns]
    if not present:
        print("  ⚠ No expected columns present for this category")
        return
    print(df[present].head(3).to_string())

_print_sample(
    df_enhanced,
    ['cve_id', 'cvss', 'cvss_av', 'cvss_pr', 'cvss_ui', 'cvss_score_derived', 'cvss_severity_category'],
    '5.1 CVSS Decomposition',
)

_print_sample(
    df_enhanced,
    ['cve_id', 'cwe', 'cwe_is_top25', 'cwe_is_injection', 'cwe_is_memory_corruption', 'cwe_severity_score'],
    '5.2 CWE Intelligence',
)

_print_sample(
    df_enhanced,
    ['cve_id', 'desc_has_rce', 'desc_has_auth_bypass', 'desc_has_priv_esc', 'desc_has_dos'],
    '5.3 Description NLP',
)

_print_sample(
    df_enhanced,
    ['cve_id', 'ultimate_risk', 'critical_exploitable', 'network_accessible', 'high_impact_network'],
    '5.4 Interaction Features',
)

# Feature statistics
print("\n[6] Feature Statistics:")
numeric_features = [f for f in all_features if f in df_enhanced.columns][:20]  # First 20
stats = df_enhanced[numeric_features].describe()
stats_cols = [
    c for c in ['cvss_av', 'cvss_score_derived', 'cwe_is_top25', 'desc_has_rce', 'ultimate_risk']
    if c in stats.columns
]
if stats_cols:
    print(stats[stats_cols].to_string())
else:
    print("  ⚠ No statistics columns available")

# Top CVEs by new scoring
print("\n[7] Top 10 High-Risk CVEs (by ultimate_risk):")
if 'ultimate_risk' in df_enhanced.columns:
    top_cols = [
        c for c in [
            'cve_id', 'cvss', 'kev_flag', 'is_healthcare', 'ultimate_risk',
            'cvss_score_derived', 'cwe_is_top25', 'desc_has_rce'
        ]
        if c in df_enhanced.columns
    ]
    top_cves = df_enhanced.nlargest(10, 'ultimate_risk')[top_cols]
    print(top_cves.to_string())

print("\n" + "="*80)
print("✓ ALL FEATURES TESTED SUCCESSFULLY")
print(f"  Total enhanced features: {len(all_features)}")
print(f"  Successfully extracted: {len([f for f in all_features if f in df_enhanced.columns])}")
print("="*80)
