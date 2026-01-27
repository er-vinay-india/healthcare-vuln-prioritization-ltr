"""
Feature Engineering Module

This module handles feature extraction and transformation for CVE prioritization.
Includes CVSS, EPSS, KEV, ATT&CK, CHPL, and healthcare-related features.
"""

from typing import List, Optional, Tuple
import pandas as pd
import numpy as np


def build_features(df: pd.DataFrame, feature_cols: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Build comprehensive feature set for CVE ranking.
    
    Features include:
    - CVSS base score, exploitability, impact subscores
    - EPSS score and percentile
    - KEV presence (binary)
    - ATT&CK technique count
    - CHPL healthcare device mappings (binary)
    - Healthcare breach relevance (binary)
    - Temporal features (age, recency)
    - Interaction features (CVSS×EPSS, KEV×Healthcare, etc.)
    
    Args:
        df: DataFrame with raw CVE data and enrichments
        feature_cols: Optional list of feature column names to use
    
    Returns:
        DataFrame with engineered features
    """
    # TODO: Implement feature engineering logic
    # - Extract CVSS subscores
    # - Add EPSS features
    # - Binary indicators (KEV, CHPL, healthcare)
    # - Temporal features (CVE age, time since publication)
    # - Interaction features
    raise NotImplementedError("To be migrated from notebook")


def normalize_features(df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    """
    Normalize/scale features for model training.
    
    Args:
        df: DataFrame with raw features
        feature_cols: List of feature columns to normalize
    
    Returns:
        DataFrame with normalized features
    """
    # TODO: Implement normalization (StandardScaler or MinMaxScaler)
    raise NotImplementedError("To be implemented")


def add_interaction_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add interaction features (e.g., CVSS×EPSS, KEV×Healthcare).
    
    Args:
        df: DataFrame with base features
    
    Returns:
        DataFrame with added interaction features
    """
    # TODO: Implement interaction features
    # - cvss_base * epss_score
    # - kev_flag * healthcare_flag
    # - attack_count * cvss_exploitability
    raise NotImplementedError("To be implemented")


def get_default_feature_cols() -> List[str]:
    """
    Return default list of feature columns for training.
    
    Returns:
        List of feature column names
    """
    return [
        'cvss_base_score',
        'cvss_exploitability_subscore',
        'cvss_impact_subscore',
        'epss_score',
        'epss_percentile',
        'kev_flag',
        'attack_technique_count',
        'chpl_healthcare_flag',
        'healthcare_breach_flag',
        'cve_age_days',
        'cvss_epss_interaction',
        'kev_healthcare_interaction',
    ]
