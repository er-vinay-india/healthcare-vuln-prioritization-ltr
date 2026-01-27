"""Tests for data preprocessing module"""
import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta

from src.data.preprocessing import clean_cve_data, filter_cves


class TestCleanCVEData:
    """Test suite for clean_cve_data function"""
    
    @pytest.fixture
    def dirty_df(self):
        """Create DataFrame with data quality issues"""
        return pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0004'],
            'cvss': [9.8, np.nan, -1.0, 11.5],  # Missing, negative, out of range
            'epss_score': [0.85, 0.45, np.nan, 1.5],  # Missing, out of range
            'published': [
                '2024-01-15',
                'invalid-date',
                '2024-01-17',
                '2024-01-18'
            ],
            'kev_flag': [1, 0, np.nan, 1],  # Missing
            'is_healthcare': [1, np.nan, 0, 1],  # Missing
            'description': [
                'Valid description',
                '',
                'Another valid one',
                None
            ]
        })
    
    def test_returns_dataframe(self, dirty_df):
        """Test that function returns a DataFrame"""
        result = clean_cve_data(dirty_df)
        assert isinstance(result, pd.DataFrame)
    
    def test_fills_missing_cvss_with_zero(self, dirty_df):
        """Test that missing CVSS values are filled with 0"""
        result = clean_cve_data(dirty_df)
        assert not result['cvss'].isna().any()
        assert result.loc[1, 'cvss'] == 0.0
    
    def test_clips_cvss_to_valid_range(self, dirty_df):
        """Test that CVSS values are clipped to [0, 10]"""
        result = clean_cve_data(dirty_df)
        assert (result['cvss'] >= 0).all()
        assert (result['cvss'] <= 10).all()
        # Check specific clipping
        assert result.loc[2, 'cvss'] == 0.0  # Was -1.0
        assert result.loc[3, 'cvss'] == 10.0  # Was 11.5
    
    def test_fills_missing_epss_with_zero(self, dirty_df):
        """Test that missing EPSS values are filled with 0"""
        result = clean_cve_data(dirty_df)
        assert not result['epss_score'].isna().any()
        assert result.loc[2, 'epss_score'] == 0.0
    
    def test_clips_epss_to_valid_range(self, dirty_df):
        """Test that EPSS scores are clipped to [0, 1]"""
        result = clean_cve_data(dirty_df)
        assert (result['epss_score'] >= 0).all()
        assert (result['epss_score'] <= 1).all()
        assert result.loc[3, 'epss_score'] == 1.0  # Was 1.5
    
    def test_parses_date_strings(self, dirty_df):
        """Test that date strings are converted to datetime"""
        result = clean_cve_data(dirty_df)
        assert pd.api.types.is_datetime64_any_dtype(result['published'])
        assert isinstance(result.loc[0, 'published'], pd.Timestamp)
    
    def test_handles_invalid_dates(self, dirty_df):
        """Test that invalid dates are handled gracefully"""
        result = clean_cve_data(dirty_df)
        # Invalid date should be set to NaT or a default value
        invalid_date = result.loc[1, 'published']
        assert pd.isna(invalid_date) or isinstance(invalid_date, pd.Timestamp)
    
    def test_fills_missing_binary_flags(self, dirty_df):
        """Test that missing binary flags are filled with 0"""
        result = clean_cve_data(dirty_df)
        assert not result['kev_flag'].isna().any()
        assert not result['is_healthcare'].isna().any()
        assert result.loc[2, 'kev_flag'] == 0
        assert result.loc[1, 'is_healthcare'] == 0
    
    def test_handles_missing_descriptions(self, dirty_df):
        """Test that missing descriptions are handled"""
        result = clean_cve_data(dirty_df)
        # Empty and None descriptions should be filled or flagged
        assert result.loc[1, 'description'] in ['', 'No description available']
        assert result.loc[3, 'description'] in ['', 'No description available', None]
    
    def test_preserves_valid_data(self):
        """Test that valid data is not modified"""
        clean_df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001'],
            'cvss': [9.8],
            'epss_score': [0.85],
            'published': [datetime(2024, 1, 15)],
            'kev_flag': [1],
            'is_healthcare': [1],
            'description': ['Valid description']
        })
        
        result = clean_cve_data(clean_df)
        
        assert result.loc[0, 'cvss'] == 9.8
        assert result.loc[0, 'epss_score'] == 0.85
        assert result.loc[0, 'kev_flag'] == 1
        assert result.loc[0, 'is_healthcare'] == 1
    
    def test_handles_empty_dataframe(self):
        """Test handling of empty DataFrame"""
        empty_df = pd.DataFrame(columns=['cve_id', 'cvss', 'epss_score', 'published'])
        result = clean_cve_data(empty_df)
        assert len(result) == 0
        assert list(result.columns) == list(empty_df.columns)
    
    def test_removes_duplicate_cve_ids(self):
        """Test that duplicate CVE IDs are handled"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0001', 'CVE-2024-0002'],
            'cvss': [9.8, 7.5, 6.0],
            'epss_score': [0.85, 0.45, 0.30],
            'published': [datetime.now()] * 3
        })
        
        result = clean_cve_data(df)
        
        # Should keep only unique CVE IDs (first occurrence or most recent)
        assert len(result) <= 2
        assert result['cve_id'].is_unique


class TestFilterCVEs:
    """Test suite for filter_cves function"""
    
    @pytest.fixture
    def sample_df(self):
        """Create sample DataFrame for filtering"""
        return pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003', 'CVE-2024-0004', 'CVE-2024-0005'],
            'cvss': [9.8, 7.5, 5.0, 3.0, 8.5],
            'epss_score': [0.85, 0.45, 0.12, 0.05, 0.65],
            'kev_flag': [1, 0, 0, 0, 1],
            'is_healthcare': [1, 1, 0, 0, 1],
            'published': [
                datetime(2024, 1, 15),
                datetime(2024, 1, 10),
                datetime(2023, 12, 20),
                datetime(2023, 11, 5),
                datetime(2024, 1, 20)
            ]
        })
    
    def test_returns_dataframe(self, sample_df):
        """Test that function returns a DataFrame"""
        result = filter_cves(sample_df)
        assert isinstance(result, pd.DataFrame)
    
    def test_no_filters_returns_all(self, sample_df):
        """Test that no filters returns all rows"""
        result = filter_cves(sample_df)
        assert len(result) == len(sample_df)
    
    def test_min_cvss_filter(self, sample_df):
        """Test filtering by minimum CVSS score"""
        result = filter_cves(sample_df, min_cvss=7.0)
        assert len(result) == 3  # CVEs with CVSS >= 7.0
        assert (result['cvss'] >= 7.0).all()
        assert set(result['cve_id']) == {'CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0005'}
    
    def test_max_cvss_filter(self, sample_df):
        """Test filtering by maximum CVSS score"""
        result = filter_cves(sample_df, max_cvss=7.0)
        assert len(result) == 3  # CVEs with CVSS <= 7.0
        assert (result['cvss'] <= 7.0).all()
    
    def test_cvss_range_filter(self, sample_df):
        """Test filtering by CVSS range"""
        result = filter_cves(sample_df, min_cvss=5.0, max_cvss=8.0)
        assert len(result) == 2  # CVEs with 5.0 <= CVSS <= 8.0
        assert (result['cvss'] >= 5.0).all()
        assert (result['cvss'] <= 8.0).all()
    
    def test_kev_only_filter(self, sample_df):
        """Test filtering for KEV-listed CVEs only"""
        result = filter_cves(sample_df, kev_only=True)
        assert len(result) == 2  # Only KEV CVEs
        assert (result['kev_flag'] == 1).all()
        assert set(result['cve_id']) == {'CVE-2024-0001', 'CVE-2024-0005'}
    
    def test_healthcare_only_filter(self, sample_df):
        """Test filtering for healthcare-relevant CVEs only"""
        result = filter_cves(sample_df, healthcare_only=True)
        assert len(result) == 3  # Only healthcare CVEs
        assert (result['is_healthcare'] == 1).all()
    
    def test_date_range_filter(self, sample_df):
        """Test filtering by date range"""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        result = filter_cves(sample_df, start_date=start_date, end_date=end_date)
        assert len(result) == 3  # CVEs published in January 2024
        assert (result['published'] >= start_date).all()
        assert (result['published'] <= end_date).all()
    
    def test_start_date_only_filter(self, sample_df):
        """Test filtering by start date only"""
        start_date = datetime(2024, 1, 1)
        result = filter_cves(sample_df, start_date=start_date)
        assert len(result) == 3  # CVEs from 2024
        assert (result['published'] >= start_date).all()
    
    def test_end_date_only_filter(self, sample_df):
        """Test filtering by end date only"""
        end_date = datetime(2023, 12, 31)
        result = filter_cves(sample_df, end_date=end_date)
        assert len(result) == 2  # CVEs before 2024
        assert (result['published'] <= end_date).all()
    
    def test_combined_filters(self, sample_df):
        """Test combining multiple filters"""
        result = filter_cves(
            sample_df,
            min_cvss=7.0,
            kev_only=True,
            start_date=datetime(2024, 1, 1)
        )
        
        # Should have high CVSS, KEV-listed, and from 2024
        assert len(result) == 2
        assert (result['cvss'] >= 7.0).all()
        assert (result['kev_flag'] == 1).all()
        assert (result['published'] >= datetime(2024, 1, 1)).all()
    
    def test_filter_returns_empty_when_no_matches(self, sample_df):
        """Test that filter returns empty DataFrame when no matches"""
        result = filter_cves(sample_df, min_cvss=10.0)  # No CVE has exactly 10.0
        assert len(result) == 0
        assert list(result.columns) == list(sample_df.columns)
    
    def test_preserves_column_order(self, sample_df):
        """Test that column order is preserved"""
        result = filter_cves(sample_df, min_cvss=5.0)
        assert list(result.columns) == list(sample_df.columns)
    
    def test_handles_string_dates(self, sample_df):
        """Test that string dates are handled"""
        result = filter_cves(
            sample_df,
            start_date='2024-01-01',
            end_date='2024-01-31'
        )
        assert len(result) == 3
    
    def test_invalid_date_format_raises_error(self, sample_df):
        """Test that invalid date format raises appropriate error"""
        with pytest.raises((ValueError, TypeError)):
            filter_cves(sample_df, start_date='invalid-date')
    
    def test_min_cvss_greater_than_max_returns_empty(self, sample_df):
        """Test that min_cvss > max_cvss returns empty"""
        result = filter_cves(sample_df, min_cvss=9.0, max_cvss=5.0)
        assert len(result) == 0
    
    def test_filter_with_missing_columns_raises_error(self):
        """Test that filtering on missing columns raises error"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001'],
            'cvss': [9.8]
            # Missing kev_flag
        })
        
        with pytest.raises(KeyError):
            filter_cves(df, kev_only=True)
    
    def test_empty_dataframe_returns_empty(self):
        """Test that empty input returns empty output"""
        empty_df = pd.DataFrame(columns=['cve_id', 'cvss', 'kev_flag', 'published'])
        result = filter_cves(empty_df, min_cvss=7.0)
        assert len(result) == 0


class TestPreprocessingIntegration:
    """Integration tests for preprocessing pipeline"""
    
    def test_clean_then_filter_pipeline(self):
        """Test full preprocessing pipeline: clean → filter"""
        # Create dirty data
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],
            'cvss': [9.8, np.nan, 7.5],
            'epss_score': [0.85, 0.45, np.nan],
            'kev_flag': [1, 0, 1],
            'is_healthcare': [1, np.nan, 0],
            'published': ['2024-01-15', '2024-01-10', '2024-01-20']
        })
        
        # Clean first
        cleaned = clean_cve_data(df)
        
        # Then filter
        filtered = filter_cves(cleaned, min_cvss=7.0, kev_only=True)
        
        # Should have 2 CVEs (high CVSS + KEV)
        assert len(filtered) == 2
        assert set(filtered['cve_id']) == {'CVE-2024-0001', 'CVE-2024-0003'}
        
        # All values should be valid
        assert not filtered['cvss'].isna().any()
        assert (filtered['cvss'] >= 7.0).all()
        assert (filtered['kev_flag'] == 1).all()
    
    def test_handles_real_world_messy_data(self):
        """Test with realistic messy data"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'],  # Duplicate
            'cvss': [9.8, 9.8, -5.0, 15.0],  # Duplicate, negative, out of range
            'epss_score': [0.85, 0.85, np.nan, 2.5],  # Missing, out of range
            'kev_flag': [1, 1, np.nan, 1],
            'is_healthcare': [1, 1, 0, np.nan],
            'published': ['2024-01-15', '2024-01-15', 'bad-date', '2024-01-20']
        })
        
        # Clean
        cleaned = clean_cve_data(df)
        
        # Should handle all issues
        assert len(cleaned) <= 3  # Duplicates removed
        assert (cleaned['cvss'] >= 0).all() and (cleaned['cvss'] <= 10).all()
        assert (cleaned['epss_score'] >= 0).all() and (cleaned['epss_score'] <= 1).all()
        assert not cleaned['kev_flag'].isna().any()
        assert not cleaned['is_healthcare'].isna().any()
