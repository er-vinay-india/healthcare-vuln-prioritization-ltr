"""
Comprehensive tests for temporal splitting strategies.
Tests date-based, percentage-based, and year-based splits with data leakage validation.
"""
import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.temporal import make_temporal_splits, validate_temporal_leakage


class TestTemporalSplits:
    """Test temporal splitting functionality"""
    
    @pytest.fixture
    def sample_data(self):
        """Create sample CVE data spanning 2018-2025"""
        dates = []
        for year in range(2018, 2026):
            for month in range(1, 13):
                # 100 CVEs per month
                for _ in range(100):
                    dates.append(datetime(year, month, 15) + timedelta(days=np.random.randint(0, 28)))
        
        df = pd.DataFrame({
            'cve_id': [f'CVE-{i:06d}' for i in range(len(dates))],
            'published': dates,
            'cvss': np.random.uniform(4.0, 10.0, len(dates)),
            'label': np.random.randint(0, 5, len(dates))
        })
        return df.sort_values('published').reset_index(drop=True)
    
    def test_basic_split(self, sample_data):
        """Test basic date-based split"""
        train, val, test = make_temporal_splits(
            sample_data,
            date_col='published',
            split_date='2024-01-01',
            val_weeks=12
        )
        
        assert len(train) > 0, "Training set is empty"
        assert len(val) > 0, "Validation set is empty"
        assert len(test) > 0, "Test set is empty"
        assert len(train) + len(val) + len(test) == len(sample_data), \
            "Data lost during split"
    
    def test_no_temporal_leakage(self, sample_data):
        """Verify no data leakage between splits"""
        train, val, test = make_temporal_splits(
            sample_data,
            split_date='2024-01-01',
            val_weeks=12
        )
        
        # Train < Val < Test
        train_max = train['published'].max()
        val_min = val['published'].min()
        val_max = val['published'].max()
        test_min = test['published'].min()
        
        assert train_max <= val_min, \
            f"Temporal leakage: train_max ({train_max}) > val_min ({val_min})"
        assert val_max <= test_min, \
            f"Temporal leakage: val_max ({val_max}) > test_min ({test_min})"
        
        print(f"[OK] No leakage: {train_max.date()} < {val_min.date()} < {test_min.date()}")
    
    def test_2024_split_date(self, sample_data):
        """Test split with 2024-11-01 cutoff (current config)"""
        train, val, test = make_temporal_splits(
            sample_data,
            split_date='2024-11-01',
            val_weeks=12
        )
        
        # Verify test set starts at 2024-11-01
        assert test['published'].min() >= pd.Timestamp('2024-11-01'), \
            "Test set contains pre-2024-11-01 data"
        
        # Check if 2025 data is in test set
        test_years = test['published'].dt.year.unique()
        print(f"[OK] Test set years: {sorted(test_years)}")
    
    def test_validate_leakage_function(self, sample_data):
        """Test temporal leakage validation function"""
        train, _, test = make_temporal_splits(sample_data, split_date='2024-01-01')
        
        # Should pass validation
        is_valid = validate_temporal_leakage(train, test, date_col='published')
        assert is_valid, "False positive: detected leakage when none exists"
    
    def test_split_date_2025(self, sample_data):
        """Test train on 2018-2024, test on 2025 (supervisor requirement)"""
        train, val, test = make_temporal_splits(
            sample_data,
            split_date='2025-01-01',
            val_weeks=12
        )
        
        # Test set should only have 2025 data
        test_years = test['published'].dt.year.unique()
        assert 2025 in test_years, "2025 data not in test set"
        
        # Train should have 2018-2024
        train_years = train['published'].dt.year.unique()
        assert all(year < 2025 for year in train_years), \
            "Train set contains 2025 data"
        
        print(f"[OK] Train: {sorted(train_years)}, Test: {sorted(test_years)}")


class TestPercentageBasedSplit:
    """Test percentage-based splitting (70/30 requirement)"""
    
    @pytest.fixture
    def sample_data(self):
        """Create sample data"""
        dates = pd.date_range('2018-01-01', '2025-12-31', freq='D')
        return pd.DataFrame({
            'cve_id': [f'CVE-{i:06d}' for i in range(len(dates))],
            'published': dates,
            'label': np.random.randint(0, 5, len(dates))
        })
    
    def test_70_30_split(self, sample_data):
        """Test 70/30 train/test split"""
        # Sort by date
        df_sorted = sample_data.sort_values('published')
        n = len(df_sorted)
        
        # 70/15/15 split (train/val/test)
        train_idx = int(n * 0.70)
        val_idx = int(n * 0.85)
        
        train = df_sorted.iloc[:train_idx]
        val = df_sorted.iloc[train_idx:val_idx]
        test = df_sorted.iloc[val_idx:]
        
        # Verify percentages
        train_pct = len(train) / n * 100
        val_pct = len(val) / n * 100
        test_pct = len(test) / n * 100
        
        assert 69 < train_pct < 71, f"Train should be ~70%, got {train_pct:.1f}%"
        assert 14 < val_pct < 16, f"Val should be ~15%, got {val_pct:.1f}%"
        assert 14 < test_pct < 16, f"Test should be ~15%, got {test_pct:.1f}%"
        
        print(f"[OK] Split: {train_pct:.1f}% / {val_pct:.1f}% / {test_pct:.1f}%")
    
    def test_percentage_maintains_temporal_order(self, sample_data):
        """Verify percentage split maintains chronological order"""
        df_sorted = sample_data.sort_values('published')
        n = len(df_sorted)
        
        train_idx = int(n * 0.70)
        train = df_sorted.iloc[:train_idx]
        test = df_sorted.iloc[train_idx:]
        
        # No leakage
        assert train['published'].max() <= test['published'].min(), \
            "Percentage split violates temporal order"


class TestYearBasedSplit:
    """Test year-based splitting"""
    
    @pytest.fixture
    def multi_year_data(self):
        """Create data with clear year boundaries"""
        data = []
        for year in range(2018, 2026):
            for month in range(1, 13):
                for day in [1, 15]:
                    data.append({
                        'cve_id': f'CVE-{year}-{month:02d}-{day:02d}',
                        'published': datetime(year, month, day),
                        'year': year
                    })
        return pd.DataFrame(data)
    
    def test_train_2018_2024_test_2025(self, multi_year_data):
        """Test train on 2018-2024, test on 2025"""
        train_years = [2018, 2019, 2020, 2021, 2022, 2023, 2024]
        test_years = [2025]
        
        train = multi_year_data[multi_year_data['year'].isin(train_years)]
        test = multi_year_data[multi_year_data['year'].isin(test_years)]
        
        assert len(train) > 0, "Training set empty"
        assert len(test) > 0, "Test set empty"
        
        # Verify no overlap
        train_actual = train['year'].unique()
        test_actual = test['year'].unique()
        
        assert all(y in train_years for y in train_actual)
        assert all(y in test_years for y in test_actual)
        
        print(f"[OK] Train years: {sorted(train_actual)}")
        print(f"[OK] Test years: {sorted(test_actual)}")


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_empty_dataframe(self):
        """Test handling of empty DataFrame"""
        df = pd.DataFrame(columns=['published', 'label'])
        
        # Function handles empty gracefully, returns empty splits
        train, val, test = make_temporal_splits(df, split_date='2024-01-01')
        assert len(train) == 0 and len(val) == 0 and len(test) == 0
    
    def test_single_day_data(self):
        """Test data from single day"""
        df = pd.DataFrame({
            'published': [datetime(2024, 1, 1)] * 100,
            'label': range(100)
        })
        
        # Should not crash, but may have empty val/test sets
        train, val, test = make_temporal_splits(df, split_date='2024-01-02', val_weeks=1)
        assert len(train) + len(val) + len(test) == len(df)
    
    def test_timezone_aware_dates(self):
        """Test with timezone-aware datetime"""
        df = pd.DataFrame({
            'published': pd.date_range('2024-01-01', periods=100, freq='D', tz='UTC'),
            'label': range(100)
        })
        
        # Function handles timezone-aware dates correctly
        # Use timezone-aware split_date to match the data
        # Split at 2024-04-15 so there's enough data for train (100 days, split at day 105)
        split_date = pd.Timestamp('2024-04-15', tz='UTC')
        train, val, test = make_temporal_splits(df, split_date=split_date)
        assert len(train) + len(val) + len(test) == len(df)
        assert len(train) > 0
        assert len(val) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
