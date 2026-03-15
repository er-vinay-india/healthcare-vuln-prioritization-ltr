#!/usr/bin/env python3
"""Check column mismatch"""

import pandas as pd
from src.features.enhanced_features import EnhancedFeatureExtractor

# Simulate STEP_3
df = pd.DataFrame({
    'cve_id': ['CVE-2023-0001'],
   'cvss_vector': ['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
    'cwe': ['CWE-79'],
    'description': ['test'],
    'kev_flag': [0],
    'is_healthcare': [0]
})

extractor = EnhancedFeatureExtractor()
result = extractor.extract_all_features(df)

# What STEP_3 expects
expected_by_step3 = [
    'cvss_av', 'cvss_ac', 'cvss_pr', 'cvss_ui', 'cvss_s', 
    'cvss_c', 'cvss_i', 'cvss_a', 'cvss_score_derived', 'cvss_severity_category',
    'cwe_is_top25', 'cwe_is_injection', 'cwe_is_crypto', 'cwe_is_access_control',
    'cwe_is_input_validation', 'cwe_is_memory_corruption', 'cwe_category', 'cwe_severity_score',
    'desc_has_rce', 'desc_has_auth_bypass', 'desc_has_priv_esc', 'desc_has_sqli',
    'desc_has_xss', 'desc_has_dos', 'desc_has_buffer_overflow', 'desc_has_path_traversal',
    'desc_has_csrf', 'desc_has_xxe',
    'vendor_is_high_risk', 'vendor_is_healthcare', 'vendor_risk_score',
    'ultimate_risk', 'critical_exploitable', 'network_accessible', 
    'auth_not_required', 'high_impact_network', 'healthcare_critical'
]

# What extractor actually created
created = [c for c in result.columns if c not in df.columns]

print(f"Expected by STEP_3: {len(expected_by_step3)}")
print(f"Created by extractor: {len(created)}")

# Find mismatches
in_expected_not_created = [f for f in expected_by_step3 if f not in result.columns]
in_created_not_expected = [f for f in created if f not in expected_by_step3]

if in_expected_not_created:
    print(f"\n✗ Expected but NOT created ({len(in_expected_not_created)}):")
    for f in in_expected_not_created:
        print(f"  - {f}")

if in_created_not_expected:
    print(f"\n! Created but NOT expected ({len(in_created_not_expected)}):")
    for f in in_created_not_expected:
        print(f"  - {f}")

if not in_expected_not_created and not in_created_not_expected:
    print("\n✓ Perfect match!")

print(f"\nAll enhanced columns in result:")
for c in sorted(created):
    print(f"  - {c}")
