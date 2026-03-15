#!/usr/bin/env python3
"""Debug: Check which features are actually created"""

import pandas as pd
from src.features.enhanced_features import EnhancedFeatureExtractor, get_enhanced_feature_columns

# Create test data
test_df = pd.DataFrame({
    'cve_id': ['CVE-2023-0001'],
    'cvss_vector': ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
    'cwe': ['CWE-79'],
    'description': ['SQL injection allows remote code execution'],
    'kev_flag': [1],
    'is_healthcare': [1]
})

print("Testing feature extraction...")
extractor = EnhancedFeatureExtractor()
result = extractor.extract_all_features(test_df)

# Check what was created
expected = get_enhanced_feature_columns()
present = [f for f in expected if f in result.columns]
missing = [f for f in expected if f not in result.columns]

print(f'\n✓ Result shape: {result.shape}')
print(f'✓ Present features: {len(present)}/{len(expected)}')
print(f'✗ Missing features: {len(missing)}/{len(expected)}')

if missing:
    print('\nMissing features:')
    for f in missing:
        print(f'  - {f}')
else:
    print('\n✓ All 37 features created successfully!')
    
# Show sample values
print('\nSample feature values:')
for f in present[:10]:
    print(f'  {f}: {result[f].iloc[0]}')
