"""
Model Comparison Module

This module handles multi-model comparison, ranking, and result export.
"""

from typing import Dict, List, Optional
import pandas as pd
import numpy as np


def compare_models(
    predictions: Dict[str, pd.Series],
    labels: pd.Series,
    k_values: List[int] = [5, 10, 20]
) -> pd.DataFrame:
    """
    Compare multiple models on ranking metrics.
    
    Args:
        predictions: Dict mapping model names to predicted scores
        labels: True labels
        k_values: List of K values for evaluation
    
    Returns:
        DataFrame with comparison results (rows=models, cols=metrics)
    """
    # TODO: Implement model comparison
    # - For each model, compute metrics
    # - Create comparison DataFrame
    # - Sort by primary metric (e.g., NDCG@10)
    raise NotImplementedError("To be migrated from notebook")


def rank_models(comparison_df: pd.DataFrame, metric: str = 'NDCG@10') -> pd.DataFrame:
    """
    Rank models by a specific metric.
    
    Args:
        comparison_df: DataFrame from compare_models()
        metric: Metric to rank by
    
    Returns:
        Sorted DataFrame (best model first)
    """
    # TODO: Implement ranking
    return comparison_df.sort_values(metric, ascending=False)


def save_comparison_results(
    comparison_df: pd.DataFrame,
    output_path: str,
    include_timestamp: bool = True
) -> None:
    """
    Save comparison results to CSV.
    
    Args:
        comparison_df: Comparison DataFrame
        output_path: Output file path
        include_timestamp: Whether to add timestamp to filename
    """
    # TODO: Implement save logic
    raise NotImplementedError("To be implemented")


def create_comparison_summary(comparison_df: pd.DataFrame) -> str:
    """
    Create a text summary of model comparison.
    
    Args:
        comparison_df: Comparison DataFrame
    
    Returns:
        Formatted text summary
    """
    # TODO: Implement summary generation
    raise NotImplementedError("To be implemented")
