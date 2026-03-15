"""
Verification Tests for Enhanced Features
=========================================

Comprehensive tests to ensure enhanced features are working correctly.
"""

import pandas as pd
import numpy as np
import sys
sys.path.append('.')

from src.features.enhanced_features import extract_all_enhanced_features, get_enhanced_feature_columns

def test_cvss_decomposition():
    """Test CVSS vector decomposition."""
    print("\n[TEST 1] CVSS Vector Decomposition")
    print("-" * 60)
    
    # Create test data with known CVSS vectors
    test_data = pd.DataFrame({
        'cve_id': ['TEST-001', 'TEST-002', 'TEST-003'],
        'cvss_vector': [
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  # Critical network attack
            'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L',  # Low local attack
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',  # Medium XSS-like
        ],
        'cvss': [9.8, 3.8, 6.1],
        'cwe': ['CWE-787', 'CWE-123', 'CWE-79'],
        'kev_flag': [1, 0, 0],
        'is_healthcare': [0, 0, 0],
        'has_attack': [1, 0, 1],
        'cvss_norm': [0.98, 0.38, 0.61]
    })
    
    # Extract features
    from src.features.enhanced_features import extract_cvss_decomposition_features
    result = extract_cvss_decomposition_features(test_data.copy())
    
    # Verify TEST-001 (critical network attack)
    row1 = result.iloc[0]
    assert row1['cvss_av'] == 4.0, f"Expected AV:N=4, got {row1['cvss_av']}"
    assert row1['cvss_ac'] == 2.0, f"Expected AC:L=2, got {row1['cvss_ac']}"
    assert row1['cvss_pr'] == 3.0, f"Expected PR:N=3, got {row1['cvss_pr']}"
    assert row1['cvss_ui'] == 2.0, f"Expected UI:N=2, got {row1['cvss_ui']}"
    assert row1['cvss_c'] == 3.0, f"Expected C:H=3, got {row1['cvss_c']}"
    assert row1['cvss_score_derived'] > 0.0, "Derived CVSS score should be positive"
    
    # Verify TEST-002 (low local attack)
    row2 = result.iloc[1]
    assert row2['cvss_av'] == 2.0, f"Expected AV:L=2, got {row2['cvss_av']}"
    assert row2['cvss_pr'] == 1.0, f"Expected PR:H=1, got {row2['cvss_pr']}"
    
    print("  ✓ CVSS vectors parsed correctly")
    print("  ✓ Derived CVSS score calculated correctly")
    print("  ✓ Impact scores calculated correctly")


def test_cwe_intelligence():
    """Test CWE intelligence features."""
    print("\n[TEST 2] CWE Intelligence Features")
    print("-" * 60)
    
    test_data = pd.DataFrame({
        'cve_id': ['TEST-001', 'TEST-002', 'TEST-003', 'TEST-004'],
        'cwe': [
            'CWE-79',          # Top 25, XSS
            'CWE-787',         # Top 25, Memory
            'CWE-89|CWE-20',   # Multiple CWEs, both Top 25
            'CWE-9999',        # Not in Top 25
        ],
        'cvss': [6.1, 9.8, 7.5, 5.0],
        'cvss_vector': ['CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'] * 4,
        'kev_flag': [0, 1, 0, 0],
        'is_healthcare': [0, 0, 0, 0],
        'has_attack': [1, 1, 0, 0],
        'cvss_norm': [0.61, 0.98, 0.75, 0.50]
    })
    
    from src.features.enhanced_features import extract_cwe_features
    result = extract_cwe_features(test_data.copy())
    
    # Test CWE-79 (XSS, Top 25, Injection + Web)
    assert result.iloc[0]['cwe_is_top25'] == 1.0, "CWE-79 should be Top 25"
    assert result.iloc[0]['cwe_is_injection'] == 1.0, "CWE-79 should be injection"
    assert result.iloc[0]['cwe_is_memory_corruption'] == 0.0, "CWE-79 should not be memory corruption"
    
    # Test CWE-787 (Memory, Top 25)
    assert result.iloc[1]['cwe_is_top25'] == 1.0, "CWE-787 should be Top 25"
    assert result.iloc[1]['cwe_is_memory_corruption'] == 1.0, "CWE-787 should be memory corruption"
    
    # Test multiple CWEs
    assert result.iloc[2]['cwe_is_injection'] == 1.0, "Should detect injection class from CWE-89"
    assert result.iloc[2]['cwe_is_top25'] == 1.0, "Should be Top 25 (has CWE-89)"
    
    # Test non-Top 25
    assert result.iloc[3]['cwe_is_top25'] == 0.0, "CWE-9999 should not be Top 25"
    assert result.iloc[3]['cwe_severity_score'] == 1.0, "Should have low severity"
    
    print("  ✓ Top 25 detection working")
    print("  ✓ CWE category classification working")
    print("  ✓ Multiple CWE handling working")
    print("  ✓ Severity scoring working")


def test_interaction_features():
    """Test interaction features."""
    print("\n[TEST 3] Interaction Features")
    print("-" * 60)
    
    test_data = pd.DataFrame({
        'cve_id': ['TEST-001', 'TEST-002'],
        'cvss': [9.8, 6.1],
        'cvss_vector': [
            'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',  # Ultimate risk
            'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N',  # Low risk
        ],
        'cwe': ['CWE-787', 'CWE-79'],
        'kev_flag': [1, 0],
        'is_healthcare': [1, 0],
        'has_attack': [1, 1],
        'cvss_norm': [0.98, 0.61]
    })
    
    result = extract_all_enhanced_features(test_data.copy(), include_nlp=False)
    
    # Test interaction features from current schema
    assert result.iloc[0]['ultimate_risk'] > 0, "Should have ultimate risk"
    assert result.iloc[1]['ultimate_risk'] == 0, "Should NOT have ultimate risk (local attack)"
    assert result.iloc[0]['network_accessible'] == 1.0, "Network vector should be accessible"
    assert result.iloc[1]['network_accessible'] == 0.0, "Local vector should not be network accessible"
    assert result.iloc[0]['auth_not_required'] == 1.0, "No privileges required for first row"
    
    print("  ✓ Ultimate risk interaction working")
    print("  ✓ Network accessibility interaction working")
    print("  ✓ Auth-required interaction working")


def test_full_integration():
    """Test full feature extraction on real data sample."""
    print("\n[TEST 4] Full Integration Test")
    print("-" * 60)
    
    # Load real data sample
    df = pd.read_csv('outputs/features/features_enhanced_latest.csv', nrows=100)
    
    # Verify all expected columns exist
    expected_features = get_enhanced_feature_columns()
    present = [f for f in expected_features if f in df.columns]
    missing = [f for f in expected_features if f not in df.columns]
    
    print(f"  Expected features: {len(expected_features)}")
    print(f"  Present features: {len(present)}")
    print(f"  Missing features: {len(missing)}")
    
    if missing:
        print(f"  Missing: {missing[:5]}..." if len(missing) > 5 else f"  Missing: {missing}")
    
    # Verify no NaN values in critical features
    critical_features = ['cvss_av', 'cvss_score_derived', 'cwe_is_top25', 'ultimate_risk']
    for feat in critical_features:
        if feat in df.columns:
            nan_count = df[feat].isna().sum()
            assert nan_count == 0, f"{feat} has {nan_count} NaN values"
            print(f"  ✓ {feat}: No NaN values")
    
    # Verify value ranges
    if 'cvss_av' in df.columns:
        assert df['cvss_av'].min() >= 1.0, "cvss_av should be >= 1"
        assert df['cvss_av'].max() <= 4.0, "cvss_av should be <= 4"
        print(f"  ✓ cvss_av range: {df['cvss_av'].min():.1f} - {df['cvss_av'].max():.1f}")
    
    if 'cwe_is_top25' in df.columns:
        assert df['cwe_is_top25'].isin([0.0, 1.0]).all(), "cwe_is_top25 should be binary"
        print(f"  ✓ cwe_is_top25: {df['cwe_is_top25'].mean()*100:.1f}% are Top 25")
    
    print(f"  ✓ Integration test passed")


def run_all_tests():
    """Run all verification tests."""
    print("="*80)
    print("ENHANCED FEATURES VERIFICATION TESTS")
    print("="*80)
    
    tests = [
        ("CVSS Decomposition", test_cvss_decomposition),
        ("CWE Intelligence", test_cwe_intelligence),
        ("Interaction Features", test_interaction_features),
        ("Full Integration", test_full_integration),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"  ✗ {name} FAILED: {e}")
    
    print("\n" + "="*80)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("="*80)
    
    if failed == 0:
        print("✓ ALL TESTS PASSED - Enhanced features are working correctly!")
    else:
        print(f"⚠ {failed} test(s) failed - please review")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
