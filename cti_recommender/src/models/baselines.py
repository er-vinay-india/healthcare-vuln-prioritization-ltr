"""
Baseline Models Module

This module implements baseline scoring methods for comparison:
- CVSS-only ranking
- Heuristic scoring
- Legacy label-based scoring
"""

from typing import Optional
import pandas as pd
import numpy as np


def compute_cvss_only_scores(df: pd.DataFrame) -> np.ndarray:
    """
    Baseline 1: CVSS-only ranking.
    
    Simply uses the normalized CVSS base score as the ranking score.
    
    Args:
        df: DataFrame with cvss_norm column
    
    Returns:
        Array of CVSS-based scores
    """
    return df['cvss_norm'].fillna(0.5).values


def compute_heuristic_scores(df: pd.DataFrame) -> np.ndarray:
    """
    Baseline 2: Weighted heuristic score (no ML).
    
    Hand-tuned weighted combination:
    score = 0.35*cvss_norm + 0.30*epss_score + 0.20*kev_flag + 0.10*recency_score + 0.05*has_attack
    
    Args:
        df: DataFrame with features
    
    Returns:
        Array of heuristic scores
    """
    cvss = df['cvss_norm'].fillna(0.5).values
    epss = df['epss_score'].fillna(0.0).values
    kev = df['kev_flag'].fillna(0).values
    recency = df.get('recency_score', pd.Series(0.5, index=df.index)).fillna(0.5).values
    attack = df.get('has_attack', pd.Series(0, index=df.index)).fillna(0).values
    
    score = (0.35 * cvss + 
             0.30 * epss + 
             0.20 * kev + 
             0.10 * recency + 
             0.05 * attack)
    
    return score


def compute_legacy_label_scores(df: pd.DataFrame, label_col: str = 'soft_label') -> np.ndarray:
    """
    Baseline 3: Use weak labels directly as scores (no training).
    
    Args:
        df: DataFrame with weak labels
        label_col: Label column name (default: 'soft_label')
    
    Returns:
        Array of label-based scores
    """
    if label_col not in df.columns:
        # Fallback to label if available
        if 'label' in df.columns:
            return df['label'].fillna(0).values
        else:
            raise ValueError(f"Column '{label_col}' not found in DataFrame")
    
    return df[label_col].fillna(0).values


def compute_epss_only_scores(df: pd.DataFrame) -> pd.Series:
    """
    Compute baseline scores using EPSS only.
    
    Args:
        df: DataFrame with EPSS scores
    
    Returns:
        Series of EPSS-based scores
    """
    # TODO: Implement EPSS baseline
    raise NotImplementedError("To be implemented")
