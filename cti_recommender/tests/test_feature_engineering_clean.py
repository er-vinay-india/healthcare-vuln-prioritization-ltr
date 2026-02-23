"""Tests for feature engineering module - production focused"""
import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

from src.features.engineering import create_all_features


# Production feature columns
FEATURE_COLS = [
    'cvss_norm', 'epss_score', 'epss_percentile', 'kev_flag',
    'recency_score', 'attack_technique_count', 'has_attack',
    'chpl_flag', 'is_healthcare', 'cvss_epss_product',
    'kev_healthcare_interaction'
]


class TestFeatureEngineering:
    """Focused tests for feature engineering"""
    
    @pytest.fixture
    def sample_df(self):
        return pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002'],
            'cvss': [9.8, 7.5],
            'epss_score': [0.85, 0.45],
            'epss_percentile': [0.95, 0.75],
            'kev_flag': [1, 0],
            'is_healthcare': [1, 1],
            'attack_flag': [1, 1],
            'attack_technique_count': [3, 2],
            'chpl_flag': [1, 0],
            'published': [
                datetime.now() - timedelta(days=5),
                datetime.now() - timedelta(days=30)
            ]
        })
    
    def test_basic_functionality(self, sample_df, capsys):
        """Test basic execution and output"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert isinstance(result, pd.DataFrame)
        assert len(result) == 2
        assert 'cvss_norm' in result.columns
        assert 'recency_score' in result.columns
    
    def test_cvss_normalization(self, sample_df, capsys):
        """Test CVSS is properly normalized"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert (result['cvss_norm'] >= 0).all()
        assert (result['cvss_norm'] <= 1).all()
        assert np.isclose(result.loc[0, 'cvss_norm'], 0.98)
    
    def test_temporal_features(self, sample_df, capsys):
        """Test temporal feature creation"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert 'days_since_published' in result.columns
        assert 'recency_score' in result.columns
        assert (result['recency_score'] >= 0).all()
        assert (result['recency_score'] <= 1).all()
    
    def test_interaction_features(self, sample_df, capsys):
        """Test interaction features"""
        result = create_all_features(sample_df, FEATURE_COLS)
        assert 'cvss_epss_product' in result.columns
        assert 'kev_healthcare_interaction' in result.columns
        # KEV + Healthcare should = 1 for first row
        assert result.loc[0, 'kev_healthcare_interaction'] == 1
    
    def test_missing_value_handling(self, capsys):
        """Test NaN handling"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001'],
            'cvss': [np.nan],
            'epss_score': [np.nan],
            'epss_percentile': [np.nan],
            'kev_flag': [np.nan],
            'is_healthcare': [np.nan],
            'attack_flag': [0],
            'attack_technique_count': [np.nan],
            'chpl_flag': [np.nan],
            'published': [datetime.now()]
        })
        result = create_all_features(df, FEATURE_COLS)
        # Should fill missing values
        assert result.loc[0, 'cvss_norm'] == 0.5  # 5.0 / 10.0
        assert result.loc[0, 'epss_score'] == 0.0
        assert result.loc[0, 'kev_flag'] == 0
