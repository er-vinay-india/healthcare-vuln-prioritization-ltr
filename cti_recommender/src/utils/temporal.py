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
    split_dt = pd.Timestamp(split_date)
    val_start = split_dt - timedelta(weeks=val_weeks)
    
    # Ensure date column is datetime
    df = df.copy()
    df[date_col] = pd.to_datetime(df[date_col])
    
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
