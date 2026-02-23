"""
Temporal Utilities Module

This module handles temporal splitting, validation, and time-based operations.
"""

from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
from datetime import datetime, timedelta


def make_temporal_splits(
    df: pd.DataFrame,
    date_col: str = 'published',
    split_date: str = '2024-01-01',
    val_weeks: int = 12
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Create temporal train/validation/test splits.
    
    This simulates real-world deployment where we train on historical data
    and predict future vulnerabilities.
    
    Args:
        df: DataFrame with date column
        date_col: Name of date column (default: 'published')
        split_date: Cutoff date for test set (YYYY-MM-DD)
        val_weeks: Number of weeks before split_date for validation
        
    Returns:
        Tuple of (train_df, val_df, test_df)
    """
    # Ensure date column is datetime
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col])
    
    # Check if date column is timezone-aware and match split timestamps accordingly
    is_tz_aware = df[date_col].dt.tz is not None
    
    # Convert split_date to Timestamp, handling timezone correctly
    if isinstance(split_date, pd.Timestamp) and split_date.tz is not None:
        # Already timezone-aware
        split_dt = split_date
    elif is_tz_aware:
        # Make split_date timezone-aware to match data
        split_dt = pd.Timestamp(split_date).tz_localize('UTC')
    else:
        split_dt = pd.Timestamp(split_date)
    
    val_start = split_dt - timedelta(weeks=val_weeks)
    
    # Create splits
    train_df = df[df[date_col] < val_start].copy()
    val_df = df[(df[date_col] >= val_start) & (df[date_col] < split_dt)].copy()
    test_df = df[df[date_col] >= split_dt].copy()
    
    print(f"Temporal Split Summary:")
    print(f"  Train:      {len(train_df):>8,} samples (< {val_start.date()})")
    print(f"  Validation: {len(val_df):>8,} samples ({val_start.date()} to {split_dt.date()})")
    print(f"  Test:       {len(test_df):>8,} samples (>= {split_dt.date()})")
    print(f"  Total:      {len(train_df) + len(val_df) + len(test_df):>8,}")
    
    # Verify no data leakage
    if len(train_df) > 0 and len(test_df) > 0:
        assert train_df[date_col].max() < test_df[date_col].min(), "Data leakage detected!"
    
    return train_df, val_df, test_df


def make_temporal_splits_flexible(
    df: pd.DataFrame,
    config,  # Can be dict or TemporalSplitsConfig dataclass
    date_col: str = 'published'
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Flexible temporal splitting with multiple strategies.
    
    Supports three strategies:
    1. date: Traditional date-based split (current default)
    2. percentage: 70/30 or custom percentage splits
    3. year_based: Train on specific years, test on others
    
    Args:
        df: DataFrame with date column
        config: temporal_splits config from YAML (dict) or TemporalSplitsConfig dataclass
        date_col: Name of date column
    
    Returns:
        Tuple of (train_df, val_df, test_df)
    """
    # Convert dataclass to dict if needed
    from dataclasses import is_dataclass, asdict
    if is_dataclass(config):
        config = asdict(config)
    
    strategy = config.get('strategy', 'date')
    
    if strategy == 'date':
        # Use existing date-based split
        date_config = config.get('date_split', {})
        return make_temporal_splits(
            df, 
            date_col=date_col,
            split_date=date_config.get('split_date', '2024-11-01'),
            val_weeks=date_config.get('validation_weeks', 12)
        )
    
    elif strategy == 'percentage':
        # Percentage-based split (maintains temporal order)
        pct_config = config.get('percentage_split', {})
        train_pct = pct_config.get('train', 0.70)
        val_pct = pct_config.get('val', 0.15)
        test_pct = pct_config.get('test', 0.15)
        
        # Sort by date to maintain temporal order
        df_sorted = df.sort_values(date_col).reset_index(drop=True)
        n = len(df_sorted)
        
        train_idx = int(n * train_pct)
        val_idx = int(n * (train_pct + val_pct))
        
        train_df = df_sorted.iloc[:train_idx].copy()
        val_df = df_sorted.iloc[train_idx:val_idx].copy()
        test_df = df_sorted.iloc[val_idx:].copy()
        
        print(f"Percentage-based Temporal Split:")
        print(f"  Train:      {len(train_df):>8,} samples ({len(train_df)/n*100:.1f}%)")
        print(f"  Validation: {len(val_df):>8,} samples ({len(val_df)/n*100:.1f}%)")
        print(f"  Test:       {len(test_df):>8,} samples ({len(test_df)/n*100:.1f}%)")
        print(f"  Total:      {n:>8,}")
        
        return train_df, val_df, test_df
    
    elif strategy == 'year_based':
        # Year-based split
        year_config = config.get('year_split', {})
        train_years = year_config.get('train_years', [2018, 2019, 2020, 2021, 2022, 2023, 2024])
        test_years = year_config.get('test_years', [2025])
        val_weeks = year_config.get('validation_weeks', 12)
        
        # Ensure date column is datetime
        df = df.copy()
        df[date_col] = pd.to_datetime(df[date_col])
        df['year'] = df[date_col].dt.year
        
        # Split by year
        train_df = df[df['year'].isin(train_years)].copy()
        test_df = df[df['year'].isin(test_years)].copy()
        
        # Validation: last N weeks of training data
        if len(train_df) > 0:
            val_start = train_df[date_col].max() - timedelta(weeks=val_weeks)
            val_df = train_df[train_df[date_col] >= val_start].copy()
            train_df = train_df[train_df[date_col] < val_start].copy()
        else:
            val_df = pd.DataFrame()
        
        # Clean up temporary year column
        train_df = train_df.drop('year', axis=1)
        val_df = val_df.drop('year', axis=1) if len(val_df) > 0 else val_df
        test_df = test_df.drop('year', axis=1)
        
        print(f"Year-based Temporal Split:")
        print(f"  Train years: {train_years}")
        print(f"  Test years:  {test_years}")
        print(f"  Train:      {len(train_df):>8,} samples")
        print(f"  Validation: {len(val_df):>8,} samples (last {val_weeks} weeks)")
        print(f"  Test:       {len(test_df):>8,} samples")
        
        return train_df, val_df, test_df
    
    else:
        raise ValueError(f"Unknown temporal split strategy: {strategy}. Use 'date', 'percentage', or 'year_based'")


def validate_temporal_leakage(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    date_col: str = 'published_date'
) -> bool:
    """
    Validate that there's no temporal leakage (test dates >= train dates).
    
    Args:
        train_df: Training DataFrame
        test_df: Test DataFrame
        date_col: Date column name
    
    Returns:
        True if no leakage, False otherwise
    """
    train_max = train_df[date_col].max()
    test_min = test_df[date_col].min()
    
    if test_min < train_max:
        print(f"⚠️  TEMPORAL LEAKAGE DETECTED!")
        print(f"   Train max date: {train_max}")
        print(f"   Test min date: {test_min}")
        print(f"   Overlap: {(train_max - test_min).days} days")
        return False
    
    print(f"✓ No temporal leakage detected")
    print(f"   Train ends: {train_max}")
    print(f"   Test starts: {test_min}")
    return True


def add_temporal_features(df: pd.DataFrame, date_col: str = 'published_date') -> pd.DataFrame:
    """
    Add temporal features (age, recency, day of week, etc.).
    
    NOTE: This functionality is now in src/features/engineering.py (create_all_features)
    This function is kept for backward compatibility.
    
    Args:
        df: DataFrame with date column
        date_col: Date column name
    
    Returns:
        DataFrame with added temporal features (unchanged - use create_all_features instead)
    """
    print("Note: Temporal features should be added via create_all_features() from src/features/engineering")
    return df


def group_by_time_period(
    df: pd.DataFrame,
    date_col: str = 'published_date',
    freq: str = 'W'
) -> pd.DataFrame:
    """
    Group data by time period (week, month, etc.).
    
    Args:
        df: DataFrame with date column
        date_col: Date column name
        freq: Pandas frequency string ('D', 'W', 'M', etc.)
    
    Returns:
        DataFrame with time period column added
    """
    # TODO: Implement grouping
    raise NotImplementedError("To be implemented")
