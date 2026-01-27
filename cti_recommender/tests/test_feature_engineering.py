"""Tests for feature engineering module"""
import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

from src.features.engineering import create_all_features


# Define feature columns that match production usage
FEATURE_COLS = [
    'cvss_norm', 'epss_score', 'epss_percentile', 'kev_flag',
    'recency_score', 'attack_technique_count', 'has_attack',
    'chpl_flag', 'is_healthcare', 'cvss_epss_product',
    'kev_healthcare_interaction'
]


class TestCreateAllFeatures:
    """Test suite for create_all_features function"""
    
    @pytest.fixture
    def sample_df(self):
        """Create sample DataFrame with required columns"""
        return pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],
            'cvss': [9.8, 7.5, 5.0],
            'epss_score': [0.85, 0.45, 0.12],
            'epss_percentile': [0.95, 0.75, 0.40],
            'kev_flag': [1, 0, 0],
            'is_healthcare': [1, 1, 0],
            'attack_flag': [1, 1, 0],
            'attack_technique_count': [3, 2, 0],
            'chpl_flag': [1, 0, 0],
            'published': [
                datetime.now() - timedelta(days=5),
                datetime.now() - timedelta(days=30),
                datetime.now() - timedelta(days=180)
            ]
        })
    
    def test_returns_dataframe(self, sample_df, capsys):
        """Test that function returns a DataFrame"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert isinstance(result, pd.DataFrame)
    
    def test_preserves_original_rows(self, sample_df, capsys):
        """Test that no rows are added or removed"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert len(result) == len(sample_df)
    
    def test_creates_cvss_norm(self, sample_df, capsys):
        """Test CVSS normalization feature"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert 'cvss_norm' in result.columns
        assert (result['cvss_norm'] >= 0).all()
        assert (result['cvss_norm'] <= 1).all()
    
    def test_creates_temporal_features(self, sample_df, capsys):
        """Test temporal feature creation"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert 'days_since_published' in result.columns
        assert 'recency_score' in result.columns
        assert (result['days_since_published'] >= 0).all()
        assert (result['recency_score'] >= 0).all()
        assert (result['recency_score'] <= 1).all()
    
    def test_creates_interaction_features(self, sample_df, capsys):
        """Test interaction feature creation"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert 'cvss_epss_product' in result.columns
        assert 'kev_healthcare_interaction' in result.columns
        assert (result['cvss_epss_product'] >= 0).all()
    
    def test_handles_missing_cvss(self, capsys):
        """Test handling of missing CVSS values"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002'],
            'cvss': [9.8, np.nan],
            'epss_score': [0.85, 0.45],
            'epss_percentile': [0.95, 0.75],
            'kev_flag': [1, 0],
            'is_healthcare': [0, 0],
            'attack_flag': [0, 0],
            'attack_technique_count': [0, 0],
            'chpl_flag': [0, 0],
            'published': [datetime.now(), datetime.now()]
        })
        
        result = create_all_features(df, FEATURE_COLS)
        assert len(result) == 2
        # Missing CVSS should be filled with 5.0
        assert result.loc[1, 'cvss_norm'] == 0.5
    
    def test_handles_empty_dataframe(self, capsys):
        """Test handling of empty DataFrame"""
        df = pd.DataFrame({
            'cve_id': [],
            'cvss': [],
            'epss_score': [],
            'epss_percentile': [],
            'kev_flag': [],
            'is_healthcare': [],
            'attack_flag': [],
            'attack_technique_count': [],
            'chpl_flag': [],
            'published': []
        })
        
        result = create_all_features(df, FEATURE_COLS)
        assert len(result) == 0
        assert 'cvss_norm' in result.columns
    
    def test_feature_value_ranges(self, sample_df, capsys):
        """Test that features are within expected value ranges"""
        result = create_all_features(sample_df, FEATURE_COLS)
        
        # Normalized features should be [0, 1]
        assert (result['cvss_norm'] >= 0).all() and (result['cvss_norm'] <= 1).all()
        assert (result['epss_score'] >= 0).all() and (result['epss_score'] <= 1).all()
        assert (result['recency_score'] >= 0).all() and (result['recency_score'] <= 1).all()
        
        # Binary flags should be 0 or 1
        assert set(result['kev_flag'].unique()).issubset({0, 1})
        assert set(result['is_healthcare'].unique()).issubset({0, 1})
        assert set(result['chpl_flag'].unique()).issubset({0, 1})
        
        # Counts should be non-negative
        assert (result['attack_technique_count'] >= 0).all()
        assert (result['days_since_published'] >= 0).all()

        
        # Check columns exist
        assert 'days_since_published' in result.columns
        assert 'temporal_score' in result.columns
        
        # Days should be positive
        assert (result['days_since_published'] >= 0).all()
        
        # Temporal score should decay over time
        assert (result['temporal_score'] >= 0).all()
        assert (result['temporal_score'] <= 1).all()
        
        # Recent CVEs should have higher temporal scores
        recent_idx = result['days_since_published'].idxmin()
        old_idx = result['days_since_published'].idxmax()
        assert result.loc[recent_idx, 'temporal_score'] > result.loc[old_idx, 'temporal_score']
    
    def test_creates_interaction_features(self, sample_df):
        """Test interaction feature creation"""
        result = create_all_features(sample_df)
        
        # Check interaction columns exist
        assert 'cvss_epss' in result.columns
        assert 'cvss_kev' in result.columns
        assert 'epss_kev' in result.columns
        
        # Check values are within expected ranges
        assert (result['cvss_epss'] >= 0).all()
        assert result['cvss_epss'].max() <= 10.0  # Max CVSS
        
        # Check KEV interactions
        kev_rows = result[result['kev_flag'] == 1]
        if len(kev_rows) > 0:
            assert (kev_rows['cvss_kev'] > 0).any()
            assert (kev_rows['epss_kev'] > 0).any()
    
    def test_creates_healthcare_boost(self, sample_df):
        """Test healthcare boost feature"""
        result = create_all_features(sample_df)
        
        assert 'healthcare_boost' in result.columns
        
        # Healthcare CVEs should have boost
        healthcare_rows = result[result['is_healthcare'] == 1]
        if len(healthcare_rows) > 0:
            assert (healthcare_rows['healthcare_boost'] > 0).all()
        
        # Non-healthcare CVEs should have 0 boost
        non_healthcare = result[result['is_healthcare'] == 0]
        if len(non_healthcare) > 0:
            assert (non_healthcare['healthcare_boost'] == 0).all()
    
    def test_creates_attack_boost(self, sample_df):
        """Test ATT&CK boost feature"""
        result = create_all_features(sample_df)
        
        assert 'attack_boost' in result.columns
        
        # ATT&CK-mapped CVEs should have boost
        attack_rows = result[result['attack_flag'] == 1]
        if len(attack_rows) > 0:
            assert (attack_rows['attack_boost'] > 0).all()
        
        # Check technique count is considered
        if len(attack_rows) > 1:
            sorted_by_techniques = attack_rows.sort_values('attack_technique_count')
            assert sorted_by_techniques['attack_boost'].is_monotonic_increasing
    
    def test_creates_chpl_boost(self, sample_df):
        """Test CHPL boost feature"""
        result = create_all_features(sample_df)
        
        assert 'chpl_boost' in result.columns
        
        # CHPL CVEs should have boost
        chpl_rows = result[result['chpl_flag'] == 1]
        if len(chpl_rows) > 0:
            assert (chpl_rows['chpl_boost'] > 0).all()
        
        # Non-CHPL CVEs should have 0 boost
        non_chpl = result[result['chpl_flag'] == 0]
        if len(non_chpl) > 0:
            assert (non_chpl['chpl_boost'] == 0).all()
    
    def test_creates_all_expected_features(self, sample_df):
        """Test that all 12 expected features are created"""
        result = create_all_features(sample_df)
        
        expected_features = [
            'cvss_norm',
            'epss_score',
            'kev_flag',
            'is_healthcare',
            'attack_flag',
            'attack_technique_count',
            'chpl_flag',
            'days_since_published',
            'temporal_score',
            'cvss_epss',
            'cvss_kev',
            'epss_kev',
            'healthcare_boost',
            'attack_boost',
            'chpl_boost'
        ]
        
        for feature in expected_features:
            assert feature in result.columns, f"Missing feature: {feature}"
    
    def test_handles_missing_cvss(self):
        """Test handling of missing CVSS values"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002'],
            'cvss': [9.8, np.nan],
            'epss_score': [0.85, 0.45],
            'kev_flag': [1, 0],
            'is_healthcare': [0, 0],
            'attack_flag': [0, 0],
            'attack_technique_count': [0, 0],
            'chpl_flag': [0, 0],
            'published': [datetime.now(), datetime.now()]
        })
        
        result = create_all_features(df)
        
        # Should handle NaN gracefully
        assert len(result) == 2
        # CVSS norm for NaN should be 0 or handled appropriately
        assert result.loc[1, 'cvss_norm'] >= 0
    
    def test_handles_missing_epss(self):
        """Test handling of missing EPSS values"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002'],
            'cvss': [9.8, 7.5],
            'epss_score': [0.85, np.nan],
            'kev_flag': [1, 0],
            'is_healthcare': [0, 0],
            'attack_flag': [0, 0],
            'attack_technique_count': [0, 0],
            'chpl_flag': [0, 0],
            'published': [datetime.now(), datetime.now()]
        })
        
        result = create_all_features(df)
        
        # Should handle NaN gracefully
        assert len(result) == 2
        # EPSS interactions should handle NaN
        assert not result['cvss_epss'].isna().all()
    
    def test_handles_edge_case_old_cve(self):
        """Test handling of very old CVEs (>5 years)"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2018-0001'],
            'cvss': [9.8],
            'epss_score': [0.85],
            'kev_flag': [1],
            'is_healthcare': [0],
            'attack_flag': [0],
            'attack_technique_count': [0],
            'chpl_flag': [0],
            'published': [datetime.now() - timedelta(days=2000)]  # ~5.5 years old
        })
        
        result = create_all_features(df)
        
        # Should handle old CVEs
        assert len(result) == 1
        assert result['days_since_published'].iloc[0] > 1800
        # Temporal score should be very low
        assert result['temporal_score'].iloc[0] < 0.1
    
    def test_handles_empty_dataframe(self):
        """Test handling of empty DataFrame"""
        df = pd.DataFrame({
            'cve_id': [],
            'cvss': [],
            'epss_score': [],
            'kev_flag': [],
            'is_healthcare': [],
            'attack_flag': [],
            'attack_technique_count': [],
            'chpl_flag': [],
            'published': []
        })
        
        result = create_all_features(df)
        
        # Should return empty DataFrame with correct columns
        assert len(result) == 0
        assert 'cvss_norm' in result.columns
    
    def test_preserves_original_columns(self, sample_df):
        """Test that original columns are preserved"""
        original_cols = set(sample_df.columns)
        result = create_all_features(sample_df)
        
        # All original columns should still exist
        for col in original_cols:
            assert col in result.columns
    
    def test_no_null_in_features(self, sample_df):
        """Test that feature columns don't have null values"""
        result = create_all_features(sample_df)
        
        feature_cols = [
            'cvss_norm', 'temporal_score', 'cvss_epss', 'cvss_kev',
            'epss_kev', 'healthcare_boost', 'attack_boost', 'chpl_boost'
        ]
        
        for col in feature_cols:
            assert not result[col].isna().any(), f"Feature {col} has null values"
    
    def test_feature_value_ranges(self, sample_df):
        """Test that features are within expected value ranges"""
        result = create_all_features(sample_df)
        
        # Normalized features should be [0, 1]
        assert (result['cvss_norm'] >= 0).all() and (result['cvss_norm'] <= 1).all()
        assert (result['epss_score'] >= 0).all() and (result['epss_score'] <= 1).all()
        assert (result['temporal_score'] >= 0).all() and (result['temporal_score'] <= 1).all()
        
        # Binary flags should be 0 or 1
        assert set(result['kev_flag'].unique()).issubset({0, 1})
        assert set(result['is_healthcare'].unique()).issubset({0, 1})
        assert set(result['attack_flag'].unique()).issubset({0, 1})
        assert set(result['chpl_flag'].unique()).issubset({0, 1})
        
        # Counts should be non-negative
        assert (result['attack_technique_count'] >= 0).all()
        assert (result['days_since_published'] >= 0).all()
    
    def test_consistent_output_for_same_input(self, sample_df):
        """Test that function produces consistent output for same input"""
        result1 = create_all_features(sample_df.copy())
        result2 = create_all_features(sample_df.copy())
        
        pd.testing.assert_frame_equal(result1, result2)
    
    def test_integration_with_model_training(self, sample_df):
        """Test that output can be used for model training"""
        result = create_all_features(sample_df)
        
        # Simulate selecting features for model
        feature_cols = [
            'cvss_norm', 'epss_score', 'kev_flag', 'temporal_score',
            'cvss_epss', 'healthcare_boost'
        ]
        
        X = result[feature_cols]
        
        # Should be able to convert to numpy array
        X_array = X.values
        assert X_array.shape[0] == len(sample_df)
        assert X_array.shape[1] == len(feature_cols)
        
        # Should not have NaN or inf
        assert not np.isnan(X_array).any()
        assert not np.isinf(X_array).any()
