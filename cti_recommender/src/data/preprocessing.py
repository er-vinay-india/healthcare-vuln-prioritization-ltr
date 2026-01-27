"""
Data Preprocessing Module

This module handles data cleaning, filtering, and preprocessing
before feature engineering.
"""

from typing import List, Optional
import pandas as pd
import numpy as np


def clean_cve_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Clean CVE data (handle missing values, fix data types).
    
    Args:
        df: Raw CVE DataFrame
    
    Returns:
        Cleaned DataFrame
    """
    cleaned = df.copy()
    
    # Handle missing CVSS scores (use median if missing)
    if 'cvss' in cleaned.columns:
        cleaned['cvss'] = cleaned['cvss'].fillna(cleaned['cvss'].median())
    
    # Ensure dates are datetime
    if 'published' in cleaned.columns:
        cleaned['published'] = pd.to_datetime(cleaned['published'], errors='coerce')
    if 'modified' in cleaned.columns:
        cleaned['modified'] = pd.to_datetime(cleaned['modified'], errors='coerce')
    
    # Remove rows with missing published dates (critical for temporal features)
    if 'published' in cleaned.columns:
        cleaned = cleaned[cleaned['published'].notna()]
    
    # Handle missing EPSS scores (default to 0)
    if 'epss_score' in cleaned.columns:
        cleaned['epss_score'] = cleaned['epss_score'].fillna(0.0)
    
    return cleaned


def filter_cves(
    df: pd.DataFrame,
    cvss_min: Optional[float] = None,
    cvss_max: Optional[float] = None,
    date_start: Optional[str] = None,
    date_end: Optional[str] = None,
    include_kev_only: bool = False,
    include_healthcare_only: bool = False
) -> pd.DataFrame:
    """
    Filter CVEs based on criteria.
    
    Args:
        df: CVE DataFrame
        cvss_min: Minimum CVSS score (inclusive)
        cvss_max: Maximum CVSS score (inclusive)
        date_start: Start date (YYYY-MM-DD)
        date_end: End date (YYYY-MM-DD)
        include_kev_only: Only include KEV CVEs
        include_healthcare_only: Only include healthcare-relevant CVEs
    
    Returns:
        Filtered DataFrame
    """
    filtered = df.copy()
    
    # CVSS filtering
    if cvss_min is not None and 'cvss' in filtered.columns:
        filtered = filtered[filtered['cvss'] >= cvss_min]
    if cvss_max is not None and 'cvss' in filtered.columns:
        filtered = filtered[filtered['cvss'] <= cvss_max]
    
    # Date filtering
    if date_start is not None and 'published' in filtered.columns:
        filtered = filtered[filtered['published'] >= pd.Timestamp(date_start)]
    if date_end is not None and 'published' in filtered.columns:
        filtered = filtered[filtered['published'] <= pd.Timestamp(date_end)]
    
    # KEV filtering
    if include_kev_only and 'kev_flag' in filtered.columns:
        filtered = filtered[filtered['kev_flag'] == 1]
    
    # Healthcare filtering
    if include_healthcare_only and 'is_healthcare' in filtered.columns:
        filtered = filtered[filtered['is_healthcare'] == 1]
    
    return filtered
