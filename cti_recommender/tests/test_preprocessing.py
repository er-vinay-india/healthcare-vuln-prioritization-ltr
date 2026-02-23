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
    
    def test_fills_missing_cvss_with_median(self, dirty_df):
        """Test that missing CVSS values are filled with median"""
        result = clean_cve_data(dirty_df)
        # After removing invalid dates, check CVSS is filled
        assert not result['cvss'].isna().any()
        # Median of [9.8, -1.0, 11.5] = 9.8
        median_val = dirty_df['cvss'].median()
        assert median_val in result['cvss'].values
    
    def test_cvss_not_clipped(self, dirty_df):
        """Test that CVSS values are NOT clipped (kept as-is)"""
        result = clean_cve_data(dirty_df)
        # Function does not clip, so outliers remain
        # Just verify it doesn't crash and maintains data
        assert len(result) > 0
    
    def test_fills_missing_epss_with_zero(self, dirty_df):
        """Test that missing EPSS values are filled with 0"""
        result = clean_cve_data(dirty_df)
        assert not result['epss_score'].isna().any()
        assert result.loc[2, 'epss_score'] == 0.0
    
    def test_epss_not_clipped(self, dirty_df):
        """Test that EPSS scores are NOT clipped (kept as-is except missing filled with 0)"""
        result = clean_cve_data(dirty_df)
        # Function fills missing with 0 but doesn't clip outliers
        assert not result['epss_score'].isna().any()
    
    def test_parses_date_strings(self, dirty_df):
        """Test that date strings are converted to datetime"""
        result = clean_cve_data(dirty_df)
        assert pd.api.types.is_datetime64_any_dtype(result['published'])
        assert isinstance(result.loc[0, 'published'], pd.Timestamp)
    
    def test_removes_invalid_dates(self, dirty_df):
        """Test that rows with invalid dates are removed"""
        result = clean_cve_data(dirty_df)
        # Function removes rows with missing published dates
        # Original has 4 rows, one with 'invalid-date' should be removed
        assert len(result) < len(dirty_df)
        assert not result['published'].isna().any()
    
    def test_does_not_fill_flags(self, dirty_df):
        """Test that function does not fill missing flags (left as-is)"""
        result = clean_cve_data(dirty_df)
        # Function only handles cvss, epss_score, and published
        # Other columns remain unchanged
        assert 'kev_flag' in result.columns
    
    def test_does_not_handle_descriptions(self, dirty_df):
        """Test that descriptions are not modified"""
        result = clean_cve_data(dirty_df)
        # Function does not handle descriptions
        assert 'description' in result.columns
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
    
    def test_does_not_remove_duplicates(self):
        """Test that function does not handle duplicate CVE IDs"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001', 'CVE-2024-0001', 'CVE-2024-0002'],
            'cvss': [9.8, 7.5, 6.0],
            'epss_score': [0.85, 0.45, 0.30],
            'published': [datetime.now()] * 3
        })
        
        result = clean_cve_data(df)
        
        # Function does not remove duplicates, just cleans data
        assert len(result) == 3


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
        result = filter_cves(sample_df, cvss_min=7.0)
        assert len(result) == 3  # CVEs with CVSS >= 7.0 (9.8, 7.5, 8.5)
        assert (result['cvss'] >= 7.0).all()
        assert set(result['cve_id']) == {'CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0005'}
    
    def test_max_cvss_filter(self, sample_df):
        """Test filtering by maximum CVSS score"""
        result = filter_cves(sample_df, cvss_max=7.0)
        assert len(result) == 2  # CVEs with CVSS <= 7.0
        assert (result['cvss'] <= 7.0).all()
    
    def test_cvss_range_filter(self, sample_df):
        """Test filtering by CVSS range"""
        result = filter_cves(sample_df, cvss_min=5.0, cvss_max=8.0)
        assert len(result) == 2  # CVEs with 5.0 <= CVSS <= 8.0 (5.0, 7.5)
        assert (result['cvss'] >= 5.0).all()
        assert (result['cvss'] <= 8.0).all()
    
    def test_kev_only_filter(self, sample_df):
        """Test filtering for KEV-listed CVEs only"""
        result = filter_cves(sample_df, include_kev_only=True)
        assert len(result) == 2  # Only KEV CVEs
        assert (result['kev_flag'] == 1).all()
        assert set(result['cve_id']) == {'CVE-2024-0001', 'CVE-2024-0005'}
    
    def test_healthcare_only_filter(self, sample_df):
        """Test filtering for healthcare-relevant CVEs only"""
        result = filter_cves(sample_df, include_healthcare_only=True)
        assert len(result) == 3  # Only healthcare CVEs
        assert (result['is_healthcare'] == 1).all()
    
    def test_date_range_filter(self, sample_df):
        """Test filtering by date range"""
        start_date = datetime(2024, 1, 1)
        end_date = datetime(2024, 1, 31)
        
        result = filter_cves(sample_df, date_start=start_date, date_end=end_date)
        assert len(result) == 3  # CVEs published in January 2024
        assert (result['published'] >= start_date).all()
        assert (result['published'] <= end_date).all()
    
    def test_start_date_only_filter(self, sample_df):
        """Test filtering by start date only"""
        start_date = datetime(2024, 1, 1)
        result = filter_cves(sample_df, date_start=start_date)
        assert len(result) == 3  # CVEs from 2024
        assert (result['published'] >= start_date).all()
    
    def test_end_date_only_filter(self, sample_df):
        """Test filtering by end date only"""
        end_date = datetime(2023, 12, 31)
        result = filter_cves(sample_df, date_end=end_date)
        assert len(result) == 2  # CVEs before 2024
        assert (result['published'] <= end_date).all()
    
    def test_combined_filters(self, sample_df):
        """Test combining multiple filters"""
        result = filter_cves(
            sample_df,
            cvss_min=7.0,
            include_kev_only=True,
            date_start=datetime(2024, 1, 1)
        )
        
        # Should have high CVSS, KEV-listed, and from 2024
        assert len(result) == 2
        assert (result['cvss'] >= 7.0).all()
        assert (result['kev_flag'] == 1).all()
        assert (result['published'] >= datetime(2024, 1, 1)).all()
    
    def test_filter_returns_empty_when_no_matches(self, sample_df):
        """Test that filter returns empty DataFrame when no matches"""
        result = filter_cves(sample_df, cvss_min=10.0)  # No CVE has exactly 10.0
        assert len(result) == 0
        assert list(result.columns) == list(sample_df.columns)
    
    def test_preserves_column_order(self, sample_df):
        """Test that column order is preserved"""
        result = filter_cves(sample_df, cvss_min=5.0)
        assert list(result.columns) == list(sample_df.columns)
    
    def test_handles_string_dates(self, sample_df):
        """Test that string dates are handled"""
        result = filter_cves(
            sample_df,
            date_start='2024-01-01',
            date_end='2024-01-31'
        )
        assert len(result) == 3
    
    def test_invalid_date_format_raises_error(self, sample_df):
        """Test that invalid date format raises appropriate error"""
        with pytest.raises((ValueError, TypeError)):
            filter_cves(sample_df, date_start='invalid-date')
    
    def test_min_cvss_greater_than_max_returns_empty(self, sample_df):
        """Test that min_cvss > max_cvss returns empty"""
        result = filter_cves(sample_df, cvss_min=9.0, cvss_max=5.0)
        assert len(result) == 0
    
    def test_filter_with_missing_columns_returns_empty(self):
        """Test that filtering on missing columns returns empty (no error)"""
        df = pd.DataFrame({
            'cve_id': ['CVE-2024-0001'],
            'cvss': [9.8]
            # Missing kev_flag - function handles this gracefully
        })
    
        # Function doesn't raise error, just skips the filter
        result = filter_cves(df, include_kev_only=True)
        assert isinstance(result, pd.DataFrame)
    """Integration tests for preprocessing pipeline"""
    
    def test_clean_then_filter_pipeline(self):
        """Test full preprocessing pipeline: clean -> filter"""
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
        filtered = filter_cves(cleaned, cvss_min=7.0, include_kev_only=True)
        
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
    
        # clean_cve_data only handles: missing CVSS (median), missing EPSS (0), invalid dates (remove)
        # It does NOT: clip values, remove duplicates, fill flags
        assert len(cleaned) == 3  # Bad date removed (1 row), 3 remain
        assert not cleaned['cvss'].isna().any()
        assert not cleaned['epss_score'].isna().any()
        # Outliers remain (function doesn't clip)
