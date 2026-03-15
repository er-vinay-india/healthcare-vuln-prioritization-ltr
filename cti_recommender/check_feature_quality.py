import pandas as pd

# Load the latest CSV
csv_file = 'outputs/features/features_with_labels_20260308.csv'
df = pd.read_csv(csv_file)

# All 47 features defined in STEP_5
all_features = [
    # Basic (10)
    'kev_flag', 'epss_score', 'epss_percentile', 
    'is_healthcare', 'healthcare_score',
    'attack_flag', 'attack_technique_count',
    'chpl_flag', 'is_curated', 'curated_severity',
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

print(f'CSV loaded: {len(df)} rows')
print('='*70)

# Check each feature
zero_variance = []
mostly_zero = []
has_data = []

for feat in all_features:
    if feat in df.columns:
        non_null = df[feat].notna().sum()
        non_zero = (df[feat].fillna(0) != 0).sum()
        unique = df[feat].nunique()
        
        pct_non_zero = (non_zero / len(df)) * 100
        
        if unique <= 1:
            zero_variance.append(f'{feat} (only {unique} unique value)')
        elif pct_non_zero < 1:
            mostly_zero.append(f'{feat} ({pct_non_zero:.2f}% non-zero)')
        else:
            has_data.append(f'{feat} ({pct_non_zero:.1f}% non-zero, {unique} unique)')
    else:
        print(f'MISSING: {feat}')

print(f'\n✓ Features with good data ({len(has_data)}):')
for f in has_data[:10]:
    print(f'  - {f}')
if len(has_data) > 10:
    print(f'  ... and {len(has_data)-10} more')

if zero_variance:
    print(f'\n⚠ Zero variance ({len(zero_variance)}):')
    for f in zero_variance:
        print(f'  - {f}')

if mostly_zero:
    print(f'\n⚠ Mostly zero (<1% non-zero) ({len(mostly_zero)}):')
    for f in mostly_zero:
        print(f'  - {f}')

print(f'\n📊 Summary:')
print(f'  Good data: {len(has_data)}/47')
print(f'  Zero variance: {len(zero_variance)}/47')
print(f'  Mostly zeros: {len(mostly_zero)}/47')

# Check a few enhanced features specifically
print(f'\n🔍 Enhanced feature sample:')
enhanced_checks = ['cvss_score_derived', 'cwe_is_crypto', 'desc_has_xss', 'ultimate_risk']
for feat in enhanced_checks:
    if feat in df.columns:
        non_null = df[feat].notna().sum()
        values = df[feat].value_counts().head(3).to_dict()
        print(f'  {feat}: {non_null} non-null, values={values}')
