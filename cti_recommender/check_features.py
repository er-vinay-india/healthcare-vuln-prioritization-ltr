#!/usr/bin/env python3
"""Quick script to check which enhanced features exist and have data."""

import pandas as pd
import numpy as np

# Load the latest features file
print("Loading CSV...")
df = pd.read_csv('outputs/features/features_with_labels_20260308.csv', nrows=5000)

# Enhanced features expected
enhanced_features = [
    # CVSS (10)
    'cvss_av', 'cvss_ac', 'cvss_pr', 'cvss_ui', 'cvss_s',
    'cvss_c', 'cvss_i', 'cvss_a', 'cvss_score_derived', 'cvss_severity_category',
    # CWE (8)
    'cwe_is_top25', 'cwe_is_injection', 'cwe_is_crypto',
    'cwe_is_access_control', 'cwe_is_input_validation',
    'cwe_is_memory_corruption', 'cwe_category', 'cwe_severity_score',
    # NLP (10)
    'desc_has_rce', 'desc_has_auth_bypass', 'desc_has_priv_esc',
    'desc_has_sqli', 'desc_has_xss', 'desc_has_dos',
    'desc_has_buffer_overflow', 'desc_has_path_traversal',
    'desc_has_csrf', 'desc_has_xxe',
    # Vendor (3)
    'vendor_is_high_risk', 'vendor_is_healthcare', 'vendor_risk_score',
    # Interaction (6)
    'ultimate_risk', 'critical_exploitable', 'network_accessible',
    'auth_not_required', 'high_impact_network', 'healthcare_critical'
]

print("\n" + "="*70)
print("ENHANCED FEATURES STATUS (first 5000 rows)")
print("="*70)

missing = []
all_null = []
all_zero = []
has_data = []

for col in enhanced_features:
    if col not in df.columns:
        missing.append(col)
    else:
        non_null = df[col].notna().sum()
        if non_null == 0:
            all_null.append(col)
        else:
            non_zero = (df[col] != 0).sum()
            if non_zero == 0:
                all_zero.append(col)
            else:
                has_data.append((col, non_null, non_zero))

print(f"\n✅ Features with data: {len(has_data)}")
for col, non_null, non_zero in has_data:
    print(f"   {col:35s}: {non_null:5d} non-null, {non_zero:5d} non-zero")

print(f"\n❌ Missing columns: {len(missing)}")
for col in missing[:10]:
    print(f"   {col}")
if len(missing) > 10:
    print(f"   ... and {len(missing)-10} more")

print(f"\n⚠️  All NULL: {len(all_null)}")
for col in all_null[:10]:
    print(f"   {col}")
if len(all_null) > 10:
    print(f"   ... and {len(all_null)-10} more")

print(f"\n⚠️  All ZERO: {len(all_zero)}")
for col in all_zero[:10]:
    print(f"   {col}")
if len(all_zero) > 10:
    print(f"   ... and {len(all_zero)-10} more")

print("\n" + "="*70)
print("DIAGNOSIS:")
print("="*70)
if len(missing) + len(all_null) + len(all_zero) > 30:
    print("❌ CRITICAL: Most enhanced features are missing or empty!")
    print("   ACTION: Run STEP_3_Compute_Features.ipynb to populate the database")
    print("   Then re-run STEP_4_Feature_Engineering_Labels.ipynb")
elif len(has_data) > 30:
    print("✅ Enhanced features populated successfully")
else:
    print("⚠️  Partial feature population - investigate data quality")

print("="*70)
