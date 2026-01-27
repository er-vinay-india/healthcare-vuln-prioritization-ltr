"""
Statistical Significance Testing Module

This module implements statistical tests for comparing model performance.
"""

from typing import Dict, List, Tuple
import pandas as pd
import numpy as np
from scipy import stats


def wilcoxon_test(
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    alternative: str = 'two-sided'
) -> Tuple[float, float]:
    """
    Perform Wilcoxon signed-rank test for paired samples.
    
    Args:
        scores_a: Metric scores for model A
        scores_b: Metric scores for model B
        alternative: 'two-sided', 'less', or 'greater'
    
    Returns:
        Tuple of (statistic, p_value)
    """
    # TODO: Implement Wilcoxon test
    # Use scipy.stats.wilcoxon
    raise NotImplementedError("To be migrated from notebook")


def bonferroni_correction(p_values: List[float], alpha: float = 0.05) -> List[bool]:
    """
    Apply Bonferroni correction for multiple hypothesis testing.
    
    Args:
        p_values: List of p-values
        alpha: Significance level
    
    Returns:
        List of booleans indicating significance after correction
    """
    # TODO: Implement Bonferroni correction
    # Corrected alpha = alpha / n_tests
    raise NotImplementedError("To be migrated from notebook")


def pairwise_significance_test(
    predictions: Dict[str, pd.Series],
    labels: pd.Series,
    metric_func: callable,
    alpha: float = 0.05
) -> pd.DataFrame:
    """
    Perform pairwise significance tests between all models.
    
    Args:
        predictions: Dict mapping model names to predictions
        labels: True labels
        metric_func: Function to compute metric per sample
        alpha: Significance level
    
    Returns:
        DataFrame with pairwise p-values
    """
    # TODO: Implement pairwise testing
    # - Compute metrics for each model
    # - Test all pairs with Wilcoxon
    # - Return matrix of p-values
    raise NotImplementedError("To be implemented")
