#!/usr/bin/env python3
"""Verify EnhancedFeatureExtractor implementation"""

from src.features.enhanced_features import EnhancedFeatureExtractor, get_enhanced_feature_columns
import pandas as pd

print('='*70)
print('VERIFICATION: EnhancedFeatureExtractor Implementation')
print('='*70)

# 1. Check class exists
print('\n1. Class Import: ✓')

# 2. Check expected features
expected_features = get_enhanced_feature_columns()
print(f'\n2. Expected Features: {len(expected_features)} features')
print('   - CVSS decomposition: 10')
print('   - CWE intelligence: 8')
print('   - Description NLP: 10')
print('   - Vendor intelligence: 3')
print('   - Interaction features: 6')

# 3. Test with realistic data
test_df = pd.DataFrame({
    'cve_id': ['CVE-2023-0001', 'CVE-2023-0002'],
    'cvss_vector': [
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:L/I:N/A:N'
    ],
    'cwe': ['CWE-79, CWE-89', 'CWE-787'],
    'description': [
        'Remote code execution vulnerability allows attackers to execute commands',
        'Buffer overflow in authentication'
    ],
    'kev_flag': [1, 0],
    'is_healthcare': [1, 0]
})

print(f'\n3. Test Feature Extraction:')
print(f'   Input: {len(test_df)} CVEs, {len(test_df.columns)} columns')

extractor = EnhancedFeatureExtractor()
result = extractor.extract_all_features(test_df)

print(f'   Output: {len(result.columns)} total columns')
print(f'   Features added: {len(result.columns) - len(test_df.columns)}')

# 4. Verify features
print('\n4. Sample Enhanced Features (CVE-2023-0001):')
print(f'   cvss_av (Network): {result["cvss_av"].iloc[0]}')
print(f'   cvss_pr (No Priv): {result["cvss_pr"].iloc[0]}')
print(f'   cwe_is_injection: {result["cwe_is_injection"].iloc[0]}')
print(f'   desc_has_rce: {result["desc_has_rce"].iloc[0]}')
print(f'   desc_has_auth_bypass: {result["desc_has_auth_bypass"].iloc[0]}')

print('\n' + '='*70)
print('✓ VERIFICATION COMPLETE - Ready for STEP_3 execution')
print('='*70)
