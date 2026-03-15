#!/usr/bin/env python3
"""Check enhanced feature data status"""

import pandas as pd
import numpy as np

# Load the latest CSV
features_file = 'outputs/features/features_with_labels_20260308.csv'
df = pd.read_csv(features_file)

# All 37 enhanced features
enhanced_features = [
    'cvss_av', 'cvss_ac', 'cvss_pr', 'cvss_ui', 'cvss_s',
    'cvss_c', 'cvss_i', 'cvss_a', 'cvss_score_derived', 'cvss_severity_category',
    'cwe_is_top25', 'cwe_is_injection', 'cwe_is_crypto',
    'cwe_is_access_control', 'cwe_is_input_validation',
    'cwe_is_memory_corruption', 'cwe_category', 'cwe_severity_score',
    'desc_has_rce', 'desc_has_auth_bypass', 'desc_has_priv_esc',
    'desc_has_sqli', 'desc_has_xss', 'desc_has_dos',
    'desc_has_buffer_overflow', 'desc_has_path_traversal',
    'desc_has_csrf', 'desc_has_xxe',
    'vendor_is_high_risk', 'vendor_is_healthcare', 'vendor_risk_score',
    'ultimate_risk', 'critical_exploitable', 'network_accessible',
    'auth_not_required', 'high_impact_network', 'healthcare_critical'
]

print('='*70)
print('ENHANCED FEATURE DATA STATUS')
print('='*70)

missing_cols = [f for f in enhanced_features if f not in df.columns]
if missing_cols:
    print(f'\n[ERROR] Missing columns: {len(missing_cols)}')
    for col in missing_cols[:10]:
        print(f'  - {col}')
else:
    print('\n[OK] All 37 enhanced feature columns exist in CSV')

print(f'\nData Status (checking all {len(df):,} rows):')
print('-'*70)

empty_features = []
populated_features = []

for feat in enhanced_features:
    if feat in df.columns:
        non_null = df[feat].notna().sum()
        non_zero = (df[feat].fillna(0) != 0).sum()
        
        if non_null == 0:
            empty_features.append(feat)
            print(f'  {feat:35s}: ❌ ALL NaN')
        elif non_zero == 0:
            empty_features.append(feat)
            print(f'  {feat:35s}: ❌ ALL ZEROS')
        else:
            populated_features.append(feat)
            unique = df[feat].nunique()
            print(f'  {feat:35s}: ✓ {non_zero:,}/{len(df):,} ({non_zero/len(df)*100:.1f}%) populated, {unique} unique')

print('\n' + '='*70)
print('SUMMARY')
print('='*70)
print(f'Total enhanced features: {len(enhanced_features)}')
print(f'  Populated with data: {len(populated_features)}')
print(f'  Empty (NaN or zeros): {len(empty_features)}')

if empty_features:
    print(f'\n[CRITICAL] {len(empty_features)} enhanced features are empty!')
    print('This explains why they have zero importance in the model.')
    print('\nROOT CAUSE: STEP_3_Compute_Features.ipynb was not executed')
    print('\nACTION REQUIRED:')
    print('  1. Run STEP_3_Compute_Features.ipynb to compute features')
    print('  2. Re-run STEP_4_Feature_Engineering_Labels.ipynb to regenerate CSV')
    print('  3. Re-run STEP_5_Model_Training_And_Evaluation.ipynb to retrain')
