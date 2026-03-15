"""
Comprehensive Test Suite for Production Features
=================================================

Tests all feature engineering functions with edge cases.

Author: AI-Enhanced Testing
Date: 2026-03-03
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from features.production_features import (
    ProductionFeatureEngineer,
    extract_production_features,
    CWE_TOP_25,
    HIGH_RISK_VENDORS,
    HEALTHCARE_VENDORS
)


@pytest.fixture
def sample_cve_data():
    """Create sample CVE data for testing."""
    return pd.DataFrame({
        'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],
        'published': [
            datetime(2024, 1, 15),
            datetime(2024, 6, 10),
            datetime(2023, 12, 1)
        ],
        'cvss': [9.8, 7.5, 4.3],
        'description': [
            'Microsoft Windows Remote Code Execution vulnerability allows attackers to execute arbitrary code',
            'Cisco IOS XE Cross-Site Scripting (XSS) vulnerability',
            'vendor_x product information disclosure issue'
        ],
        'cwe': ['CWE-787', 'CWE-79', 'CWE-200'],
        'is_healthcare': [0, 0, 0],
        'chpl_flag': [0, 0, 0],
        'attack_technique_count': [3, 1, 0]
    })


@pytest.fixture
def healthcare_cve_data():
    """Create healthcare-specific CVE data."""
    return pd.DataFrame({
        'cve_id': ['CVE-2024-MED-001', 'CVE-2024-MED-002'],
        'published': [datetime(2024, 2, 1), datetime(2024, 3, 15)],
        'cvss': [9.1, 6.5],
        'description': [
            'Philips IntelliVue patient monitor buffer overflow allows remote code execution',
            'GE Healthcare PACS system authentication bypass vulnerability'
        ],
        'cwe': ['CWE-787', 'CWE-287'],
        'is_healthcare': [1, 1],
        'chpl_flag': [0, 1],
        'attack_technique_count': [2, 1]
    })


@pytest.fixture
def historical_data():
    """Create historical data for risk score computation."""
    return pd.DataFrame({
        'cve_id': [f'CVE-2023-{i:04d}' for i in range(1, 101)],
        'description': ['microsoft vulnerability'] * 30 + ['cisco issue'] * 20 + ['other vendor'] * 50,
        'cwe': ['CWE-787'] * 25 + ['CWE-79'] * 25 + ['CWE-200'] * 50,
        'kev_flag': [1] * 20 + [0] * 10 + [1] * 5 + [0] * 15 + [1] * 5 + [0] * 45
    })


class TestBasicFeatureExtraction:
    """Test basic feature extraction functions."""
    
    def test_cvss_features(self, sample_cve_data):
        """Test CVSS feature extraction."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # Check critical CVE (9.8)
        assert result.loc[0, 'cvss_critical'] == 1
        assert result.loc[0, 'cvss_high'] == 1
        assert abs(result.loc[0, 'cvss_norm'] - 0.98) < 0.001  # Float precision
        
        # Check high CVE (7.5)
        assert result.loc[1, 'cvss_critical'] == 0
        assert result.loc[1, 'cvss_high'] == 1
        assert result.loc[1, 'cvss_medium'] == 0
        
        # Check medium CVE (4.3)
        assert result.loc[2, 'cvss_critical'] == 0
        assert result.loc[2, 'cvss_high'] == 0
        assert result.loc[2, 'cvss_medium'] == 1
    
    def test_cwe_top25_detection(self, sample_cve_data):
        """Test CWE Top 25 detection."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # CWE-787 is in Top 25
        assert result.loc[0, 'cwe_top25'] == 1
        
        # CWE-79 is in Top 25
        assert result.loc[1, 'cwe_top25'] == 1
        
        # CWE-200 is NOT in Top 25
        assert result.loc[2, 'cwe_top25'] == 0
    
    def test_vendor_detection(self, sample_cve_data):
        """Test high-risk vendor detection."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # Microsoft is high-risk vendor
        assert result.loc[0, 'is_high_risk_vendor'] == 1
        
        # Cisco is high-risk vendor
        assert result.loc[1, 'is_high_risk_vendor'] == 1
        
        # vendor_x is not high-risk
        assert result.loc[2, 'is_high_risk_vendor'] == 0
    
    def test_description_exploit_keywords(self, sample_cve_data):
        """Test exploit keyword detection in descriptions."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # "remote code execution" is high-severity keyword
        assert result.loc[0, 'has_exploit_keywords_high'] == 1
        assert result.loc[0, 'exploit_keyword_count'] >= 1
        
        # "cross-site scripting" is medium-severity keyword
        assert result.loc[1, 'has_exploit_keywords_med'] == 1
        
        # "information disclosure" is medium-severity keyword
        assert result.loc[2, 'has_exploit_keywords_med'] == 1
    
    def test_temporal_features(self, sample_cve_data):
        """Test temporal/recency feature calculation."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # Check temporal features exist
        assert 'days_since_published' in result.columns
        assert 'recency_score' in result.columns
        assert 'is_recent' in result.columns
        
        # Days since published should be positive
        assert (result['days_since_published'] >= 0).all()
        
        # Recency score should be between 0 and 1
        assert (result['recency_score'] >= 0).all()
        assert (result['recency_score'] <= 1).all()
    
    def test_attack_features(self, sample_cve_data):
        """Test ATT&CK mapping features."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # CVE with 3 attack techniques
        assert result.loc[0, 'has_attack'] == 1
        assert result.loc[0, 'attack_multi'] == 1
        assert result.loc[0, 'attack_technique_count'] == 3
        
        # CVE with 1 attack technique
        assert result.loc[1, 'has_attack'] == 1
        assert result.loc[1, 'attack_multi'] == 0
        
        # CVE with no attack mappings
        assert result.loc[2, 'has_attack'] == 0
        assert result.loc[2, 'attack_multi'] == 0


class TestHealthcareFeatures:
    """Test healthcare-specific features."""
    
    def test_healthcare_vendor_detection(self, healthcare_cve_data):
        """Test healthcare vendor detection."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(healthcare_cve_data)
        
        # Philips is healthcare vendor
        assert result.loc[0, 'is_healthcare_vendor'] == 1
        
        # GE Healthcare is healthcare vendor
        assert result.loc[1, 'is_healthcare_vendor'] == 1
    
    def test_healthcare_critical_interaction(self, healthcare_cve_data):
        """Test healthcare × critical interaction feature."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(healthcare_cve_data)
        
        # Healthcare CVE with critical CVSS
        assert result.loc[0, 'is_healthcare'] == 1
        assert result.loc[0, 'cvss_critical'] == 1
        assert result.loc[0, 'healthcare_critical'] == 1
        
        # Healthcare CVE with non-critical CVSS
        assert result.loc[1, 'is_healthcare'] == 1
        assert result.loc[1, 'cvss_critical'] == 0
        assert result.loc[1, 'healthcare_critical'] == 0
    
    def test_chpl_flag(self, healthcare_cve_data):
        """Test CHPL (Certified Health IT Product List) flag."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(healthcare_cve_data)
        
        # CVE affecting CHPL-certified product
        assert result.loc[1, 'chpl_flag'] == 1
        # CHPL CVE has CVSS 6.5 (medium, not critical)
        assert result.loc[1, 'chpl_critical'] == 0
    
    def test_attack_healthcare_interaction(self, healthcare_cve_data):
        """Test ATT&CK × healthcare interaction."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(healthcare_cve_data)
        
        # Healthcare CVE with ATT&CK mappings
        assert result.loc[0, 'has_attack'] == 1
        assert result.loc[0, 'is_healthcare'] == 1
        assert result.loc[0, 'attack_healthcare'] == 1


class TestEdgeCases:
    """Test edge cases and missing data handling."""
    
    def test_missing_cvss(self):
        """Test handling of missing CVSS scores."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-MISS'],
            'cvss': [None],
            'description': ['test vulnerability']
        })
        
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(df)
        
        # Should default to 5.0 (medium)
        assert result.loc[0, 'cvss'] == 5.0
        assert result.loc[0, 'cvss_norm'] == 0.5
        assert result.loc[0, 'cvss_medium'] == 1
    
    def test_missing_description(self):
        """Test handling of missing descriptions."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-NODESC'],
            'cvss': [7.5],
            'description': [None]
        })
        
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(df)
        
        # Should handle gracefully
        assert result.loc[0, 'desc_length'] == 0
        assert result.loc[0, 'has_exploit_keywords_high'] == 0
        assert result.loc[0, 'is_high_risk_vendor'] == 0
    
    def test_missing_cwe(self):
        """Test handling of missing CWE data."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-NOCWE'],
            'cvss': [8.0],
            'description': ['test'],
            'cwe': [None]
        })
        
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(df)
        
        # Should handle gracefully
        assert result.loc[0, 'cwe_top25'] == 0
        assert result.loc[0, 'cwe_count'] == 0
    
    def test_multiple_cwes(self):
        """Test handling of multiple CWEs."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-MULTI'],
            'cvss': [9.0],
            'description': ['test'],
            'cwe': ['CWE-787, CWE-79, CWE-89']
        })
        
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(df)
        
        # Should count all CWEs
        assert result.loc[0, 'cwe_count'] == 3
        
        # Should detect first CWE is Top 25
        assert result.loc[0, 'cwe_top25'] == 1
    
    def test_empty_dataframe(self):
        """Test handling of empty DataFrame."""
        df = pd.DataFrame()
        
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(df)
        
        # Should return empty DataFrame without errors
        assert len(result) == 0
    
    def test_missing_published_date(self):
        """Test handling of missing publication date."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-NODATE'],
            'cvss': [7.0],
            'description': ['test']
        })
        
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(df)
        
        # Should handle gracefully
        assert 'days_since_published' in result.columns
        assert 'recency_score' in result.columns


class TestHistoricalRiskScores:
    """Test historical risk score computation."""
    
    def test_vendor_risk_scores(self, historical_data, sample_cve_data):
        """Test vendor risk score calculation from historical data."""
        engineer = ProductionFeatureEngineer(historical_data=historical_data)
        result = engineer.extract_features(sample_cve_data)
        
        # Microsoft has 20/30 = 66.7% exploitation rate in historical data
        # CVE-2024-0001 mentions Microsoft
        assert result.loc[0, 'vendor_risk_score'] > 0.5
        
        # Cisco has 5/20 = 25% exploitation rate
        # CVE-2024-0002 mentions Cisco
        assert result.loc[1, 'vendor_risk_score'] > 0.0
        assert result.loc[1, 'vendor_risk_score'] < result.loc[0, 'vendor_risk_score']
    
    def test_cwe_risk_scores(self, historical_data, sample_cve_data):
        """Test CWE risk score calculation from historical data."""
        engineer = ProductionFeatureEngineer(historical_data=historical_data)
        result = engineer.extract_features(sample_cve_data)
        
        # CWE-787 has higher exploitation rate than CWE-200
        assert 'cwe_risk_score' in result.columns
        # CWE-787 should have risk score > 0
        assert result.loc[0, 'cwe_risk_score'] >= 0
    
    def test_no_historical_data(self, sample_cve_data):
        """Test feature extraction without historical data."""
        engineer = ProductionFeatureEngineer(historical_data=None)
        result = engineer.extract_features(sample_cve_data)
        
        # Should default to 0.0
        assert (result['vendor_risk_score'] == 0.0).all()
        assert (result['cwe_risk_score'] == 0.0).all()


class TestFeatureCompleteness:
    """Test that all expected features are generated."""
    
    def test_all_features_present(self, sample_cve_data):
        """Test that all expected feature columns are present."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        expected_features = engineer.get_feature_columns()
        
        for feature in expected_features:
            assert feature in result.columns, f"Missing feature: {feature}"
    
    def test_feature_count(self, sample_cve_data):
        """Test that we have expected number of features."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        feature_cols = engineer.get_feature_columns()
        
        # Should have 27 numeric features (cwe_low not included since we have top25)
        assert len(feature_cols) >= 27
    
    def test_no_leakage_features(self, sample_cve_data):
        """Test that NO leakage features (KEV, EPSS) are present."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        feature_cols = engineer.get_feature_columns()
        
        # Ensure NO temporal leakage
        assert 'kev_flag' not in feature_cols
        assert 'epss_score' not in feature_cols
        assert 'epss' not in feature_cols
        
        # Double-check against result columns
        assert 'kev_flag' not in result.columns or result['kev_flag'].isna().all()
        assert 'epss_score' not in result.columns or result['epss_score'].isna().all()
    
    def test_feature_importance_groups(self):
        """Test feature importance grouping for ablation studies."""
        engineer = ProductionFeatureEngineer()
        groups = engineer.get_feature_importance_groups()
        
        # Should have 7 groups
        assert len(groups) == 7
        
        # Check group names
        expected_groups = {'cvss', 'cwe', 'vendor', 'description', 'temporal', 'healthcare', 'attack'}
        assert set(groups.keys()) == expected_groups
        
        # Each group should have features
        for group_name, features in groups.items():
            assert len(features) > 0, f"Empty group: {group_name}"


class TestDataTypes:
    """Test data type consistency."""
    
    def test_feature_data_types(self, sample_cve_data):
        """Test that features have correct data types."""
        engineer = ProductionFeatureEngineer()
        result = engineer.extract_features(sample_cve_data)
        
        # Binary features should be 0 or 1
        binary_features = [
            'cvss_critical', 'cvss_high', 'cvss_medium', 'cvss_low',
            'cwe_top25', 'is_high_risk_vendor', 'is_healthcare_vendor',
            'has_exploit_keywords_high', 'has_exploit_keywords_med',
            'has_exploit_keywords_low', 'is_recent',
            'is_healthcare', 'chpl_flag', 'healthcare_critical',
            'chpl_critical', 'has_attack', 'attack_multi', 'attack_healthcare'
        ]
        
        for feature in binary_features:
            if feature in result.columns:
                assert result[feature].isin([0, 1]).all(), f"{feature} should be binary"
        
        # Normalized features should be in [0, 1]
        normalized_features = ['cvss_norm', 'recency_score', 'desc_length_norm']
        
        for feature in normalized_features:
            if feature in result.columns:
                assert (result[feature] >= 0).all(), f"{feature} should be >= 0"
                assert (result[feature] <= 1).all(), f"{feature} should be <= 1"
        
        # Count features should be non-negative integers
        count_features = ['cwe_count', 'exploit_keyword_count', 'attack_technique_count']
        
        for feature in count_features:
            if feature in result.columns:
                assert (result[feature] >= 0).all(), f"{feature} should be >= 0"


class TestConvenienceFunction:
    """Test convenience function."""
    
    def test_extract_production_features_function(self, sample_cve_data):
        """Test convenience function for feature extraction."""
        result = extract_production_features(sample_cve_data)
        
        # Should produce same result as class method
        engineer = ProductionFeatureEngineer()
        expected = engineer.extract_features(sample_cve_data)
        
        # Check feature columns match
        feature_cols = engineer.get_feature_columns()
        for col in feature_cols:
            assert col in result.columns
            assert col in expected.columns
    
    def test_with_historical_data(self, sample_cve_data, historical_data):
        """Test convenience function with historical data."""
        result = extract_production_features(
            sample_cve_data,
            historical_data=historical_data
        )
        
        # Should have risk scores
        assert 'vendor_risk_score' in result.columns
        assert 'cwe_risk_score' in result.columns
        assert result['vendor_risk_score'].max() > 0


class TestRealWorldScenarios:
    """Test realistic scenarios."""
    
    def test_high_priority_cve(self):
        """Test feature extraction for high-priority CVE (critical + Top 25 CWE + Microsoft)."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-CRITICAL'],
            'published': [datetime(2024, 1, 1)],
            'cvss': [9.8],
            'description': ['Microsoft Windows Remote Code Execution vulnerability allows unauthenticated attacker to execute arbitrary code'],
            'cwe': ['CWE-787'],  # Top 25
            'is_healthcare': [0],
            'chpl_flag': [0],
            'attack_technique_count': [5]
        })
        
        result = extract_production_features(df)
        
        # Should have HIGH signals
        assert result.loc[0, 'cvss_critical'] == 1
        assert result.loc[0, 'cwe_top25'] == 1
        assert result.loc[0, 'is_high_risk_vendor'] == 1
        assert result.loc[0, 'has_exploit_keywords_high'] == 1
        assert result.loc[0, 'has_attack'] == 1
        assert result.loc[0, 'attack_multi'] == 1
    
    def test_healthcare_critical_scenario(self):
        """Test healthcare critical CVE scenario."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-HEALTH-CRIT'],
            'published': [datetime(2024, 2, 1)],
            'cvss': [9.1],
            'description': ['Philips IntelliVue MX800 patient monitor allows remote attackers to execute code'],
            'cwe': ['CWE-416'],  # Use After Free - Top 25
            'is_healthcare': [1],
            'chpl_flag': [1],
            'attack_technique_count': [3]
        })
        
        result = extract_production_features(df)
        
        # Should trigger all healthcare + critical signals
        assert result.loc[0, 'is_healthcare'] == 1
        assert result.loc[0, 'chpl_flag'] == 1
        assert result.loc[0, 'cvss_critical'] == 1
        assert result.loc[0, 'healthcare_critical'] == 1
        assert result.loc[0, 'chpl_critical'] == 1
        assert result.loc[0, 'is_healthcare_vendor'] == 1
        assert result.loc[0, 'attack_healthcare'] == 1
    
    def test_low_priority_cve(self):
        """Test low-priority CVE (low CVSS, no Top 25 CWE, unknown vendor)."""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-LOW'],
            'published': [datetime(2024, 1, 1)],
            'cvss': [3.2],
            'description': ['Unknown vendor minor information disclosure'],
            'cwe': ['CWE-200'],  # Not Top 25
            'is_healthcare': [0],
            'chpl_flag': [0],
            'attack_technique_count': [0]
        })
        
        result = extract_production_features(df)
        
        # Should have LOW signals
        assert result.loc[0, 'cvss_critical'] == 0
        assert result.loc[0, 'cvss_high'] == 0
        assert result.loc[0, 'cwe_top25'] == 0
        assert result.loc[0, 'is_high_risk_vendor'] == 0
        assert result.loc[0, 'has_attack'] == 0
        assert result.loc[0, 'is_healthcare'] == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
