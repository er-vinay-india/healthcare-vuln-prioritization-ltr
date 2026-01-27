"""
Feature Engineering Module

This module handles feature extraction and transformation for CVE prioritization.
Includes CVSS, EPSS, KEV, ATT&CK, CHPL, and healthcare-related features.
"""

from typing import List, Optional, Tuple
from datetime import datetime
import pandas as pd
import numpy as np


def create_all_features(df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    """
    Create all features for CVE prioritization (production-ready, simple version).
    
    This function performs inline feature engineering matching the notebook implementation.
    Features created:
    - cvss_norm: Normalized CVSS score [0,1]
    - epss_score, epss_percentile: EPSS features (filled)
    - kev_flag: Binary KEV membership
    - days_since_published, recency_score: Temporal features
    - attack_technique_count, has_attack: ATT&CK features
    - chpl_flag, is_healthcare: Healthcare flags
    - cvss_epss_product, kev_healthcare_interaction: Interaction features
    - published_week: Week grouping for ranking
    
    Args:
        df: DataFrame with raw CVE data (must have 'published' and 'cvss' columns)
        feature_cols: List of feature column names to validate
    
    Returns:
        DataFrame with all engineered features
    """
    # CVSS normalization
    df['cvss_norm'] = df['cvss'].fillna(5.0) / 10.0

    # EPSS handling
    df['epss_score'] = df['epss_score'].fillna(0.0)
    df['epss_percentile'] = df['epss_percentile'].fillna(0.0)

    # KEV flag
    df['kev_flag'] = df['kev_flag'].fillna(0).astype(int)

    # Temporal features
    df['days_since_published'] = (datetime.now() - df['published']).dt.days
    max_days = df['days_since_published'].max()
    df['recency_score'] = 1.0 - (df['days_since_published'] / max_days) if max_days > 0 else 1.0

    # ATT&CK features
    df['attack_technique_count'] = df['attack_technique_count'].fillna(0).astype(int)
    df['has_attack'] = (df['attack_technique_count'] > 0).astype(int)
    if 'attack_flag' in df.columns:
        df['has_attack'] = ((df['attack_technique_count'] > 0) | (df['attack_flag'] == 1)).astype(int)

    # CHPL and healthcare flags
    df['chpl_flag'] = df['chpl_flag'].fillna(0).astype(int)
    df['is_healthcare'] = df['is_healthcare'].fillna(0).astype(int)

    # Interaction features
    df['cvss_epss_product'] = df['cvss_norm'] * df['epss_score']
    df['kev_healthcare_interaction'] = df['kev_flag'] * df['is_healthcare']

    # Week grouping for ranking
    df['published_week'] = df['published'].dt.strftime('%Y-%U')

    print(f"Feature engineering complete: {len(df):,} rows, {len(feature_cols)} features")
    print("\nFeature statistics:")
    print(df[feature_cols].describe().T[['mean', 'std', 'min', 'max']].round(4))
    
    return df


def build_features(df: pd.DataFrame, reference_date: str = '2025-01-01') -> pd.DataFrame:
    """
    Build comprehensive feature set for CVE ranking.
    
    Features include:
    - cvss_norm: Normalized CVSS score [0,1]
    - epss_score: EPSS probability [0,1]
    - epss_percentile: EPSS percentile [0,1]
    - kev_flag: Binary KEV membership
    - days_since_published: Age in days
    - recency_score: Inverted normalized age [0,1]
    - attack_technique_count: Number of ATT&CK techniques
    - has_attack: Binary ATT&CK mapping flag
    - chpl_flag: Binary CHPL product match
    - is_healthcare: Binary healthcare relevance
    - cvss_epss_product: Interaction feature
    - kev_healthcare_interaction: Interaction feature
    - published_week: Week identifier for grouping
    
    Args:
        df: DataFrame with raw CVE data and enrichments
        reference_date: Reference date for recency calculation (YYYY-MM-DD)
    
    Returns:
        DataFrame with engineered features
    """
    features = df.copy()
    
    # Reference date for recency calculation
    ref_date = pd.Timestamp(reference_date)
    
    # === Core features with defensive handling ===
    
    # CVSS normalized (handle missing)
    if 'cvss' in features.columns:
        features['cvss_norm'] = features['cvss'].fillna(5.0) / 10.0
    else:
        print("WARNING: 'cvss' column missing, defaulting cvss_norm to 0.5")
        features['cvss_norm'] = 0.5
    
    # EPSS score (already [0,1])
    features['epss_score'] = features.get('epss_score', pd.Series(0.0, index=features.index)).fillna(0.0)
    
    # EPSS percentile (already [0,1])
    features['epss_percentile'] = features.get('epss_percentile', pd.Series(0.0, index=features.index)).fillna(0.0)
    
    # KEV flag (binary)
    features['kev_flag'] = features.get('kev_flag', pd.Series(0, index=features.index)).fillna(0).astype(int)
    
    # Days since published
    features['days_since_published'] = (ref_date - features['published']).dt.days.clip(lower=0)
    
    # Recency score: newer = higher score
    max_days = features['days_since_published'].max()
    if max_days > 0:
        features['recency_score'] = 1.0 - (features['days_since_published'] / max_days)
    else:
        features['recency_score'] = 1.0
    
    # ATT&CK features
    features['attack_technique_count'] = features.get('attack_technique_count', pd.Series(0, index=features.index)).fillna(0).astype(int)
    features['has_attack'] = (features['attack_technique_count'] > 0).astype(int)
    
    # Handle attack_flag if present (legacy column)
    if 'attack_flag' in features.columns:
        features['has_attack'] = ((features['attack_technique_count'] > 0) | (features['attack_flag'] == 1)).astype(int)
    
    # CHPL flag
    features['chpl_flag'] = features.get('chpl_flag', pd.Series(0, index=features.index)).fillna(0).astype(int)
    
    # Healthcare relevance
    features['is_healthcare'] = features.get('is_healthcare', pd.Series(0, index=features.index)).fillna(0).astype(int)
    
    # === Interaction features ===
    features['cvss_epss_product'] = features['cvss_norm'] * features['epss_score']
    features['kev_healthcare_interaction'] = features['kev_flag'] * features['is_healthcare']
    
    # === Published week for grouping ===
    features['published_week'] = features['published'].dt.strftime('%Y-%U')
    
    print(f"Feature engineering complete: {len(features):,} rows")
    
    return features


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
