"""
Evaluation Metrics Module

This module implements ranking metrics (NDCG, Precision@K, MAP)
and temporal evaluation methods.
"""

from typing import Dict, List, Optional
import pandas as pd
import numpy as np


def evaluate_ranking(
    df: pd.DataFrame,
    score_col: str,
    label_col: str = 'soft_label',
    group_col: str = 'published_week',
    k_values: List[int] = [5, 10, 20]
) -> Dict[str, float]:
    """
    Evaluate ranking performance using grouped metrics.
    
    Computes NDCG@K, Precision@K, and MAP@K across all groups.
    
    Args:
        df: DataFrame with labels and scores
        score_col: Column name for predicted scores
        label_col: Column name for true labels (default: 'soft_label')
        group_col: Column to group by for evaluation (default: 'published_week')
        k_values: List of K values for evaluation (default: [5, 10, 20])
    
    Returns:
        Dict with metric names and values
    """
    df = df.copy()
    
    # Collect metrics per group
    metrics_by_k = {k: {'ndcg': [], 'precision': [], 'map': []} for k in k_values}
    
    for group, group_df in df.groupby(group_col):
        if len(group_df) < 2:
            continue
        
        y_true = group_df[label_col].values
        y_score = group_df[score_col].values
        
        for k in k_values:
            # NDCG@K
            metrics_by_k[k]['ndcg'].append(ndcg_at_k(y_true, y_score, k))
            
            # Precision@K
            metrics_by_k[k]['precision'].append(precision_at_k(y_true, y_score, k))
            
            # MAP@K (Average Precision)
            ap = compute_ap_at_k(y_true, y_score, k)
            metrics_by_k[k]['map'].append(ap)
    
    # Aggregate results
    results = {}
    for k in k_values:
        results[f'NDCG@{k}'] = np.mean(metrics_by_k[k]['ndcg']) if metrics_by_k[k]['ndcg'] else 0.0
        results[f'P@{k}'] = np.mean(metrics_by_k[k]['precision']) if metrics_by_k[k]['precision'] else 0.0
        results[f'MAP@{k}'] = np.mean(metrics_by_k[k]['map']) if metrics_by_k[k]['map'] else 0.0
    
    return results


def compute_ap_at_k(y_true: np.ndarray, y_score: np.ndarray, k: int, threshold: int = 2) -> float:
    """Compute Average Precision@K."""
    if len(y_true) == 0:
        return 0.0
    
    k = min(k, len(y_true))
    sorted_idx = np.argsort(y_score)[::-1][:k]
    
    relevant_count = 0
    precision_sum = 0.0
    
    for i, idx in enumerate(sorted_idx):
        if y_true[idx] >= threshold:
            relevant_count += 1
            precision_sum += relevant_count / (i + 1)
    
    if relevant_count == 0:
        return 0.0
    
    return precision_sum / relevant_count


def evaluate_by_week(
    df: pd.DataFrame,
    score_col: str,
    label_col: str,
    date_col: str,
    k: int = 10
) -> pd.DataFrame:
    """
    Evaluate ranking performance week-by-week (temporal evaluation).
    
    Args:
        df: DataFrame with scores, labels, dates
        score_col: Column name for predicted scores
        label_col: Column name for true labels
        date_col: Column name for dates
        k: K value for NDCG@K
    
    Returns:
        DataFrame with weekly metrics
    """
    # TODO: Implement temporal evaluation
    # - Group by week
    # - Compute NDCG@K per week
    # - Return time series of metrics
    raise NotImplementedError("To be migrated from notebook")


def compute_ranking_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    k: int = 10
) -> Dict[str, float]:
    """
    Compute comprehensive ranking metrics for a single K.
    
    Args:
        y_true: True labels
        y_pred: Predicted scores
        k: K value for evaluation
    
    Returns:
        Dict with NDCG@K, Precision@K, Recall@K, MAP
    """
    # TODO: Implement comprehensive metrics
    raise NotImplementedError("To be implemented")


def ndcg_at_k(y_true: np.ndarray, y_pred: np.ndarray, k: int) -> float:
    """
    Compute NDCG@K for a single query group.
    
    Args:
        y_true: True relevance scores
        y_pred: Predicted scores
        k: K value
    
    Returns:
        NDCG@K score
    """
    if len(y_true) == 0:
        return 0.0
    
    # Get top-k indices by score
    k = min(k, len(y_true))
    top_k_idx = np.argsort(y_pred)[::-1][:k]
    
    # DCG@K
    dcg = 0.0
    for i, idx in enumerate(top_k_idx):
        dcg += (2**y_true[idx] - 1) / np.log2(i + 2)
    
    # Ideal DCG@K
    ideal_order = np.argsort(y_true)[::-1][:k]
    idcg = 0.0
    for i, idx in enumerate(ideal_order):
        idcg += (2**y_true[idx] - 1) / np.log2(i + 2)
    
    if idcg == 0:
        return 0.0
    
    return dcg / idcg


def precision_at_k(y_true: np.ndarray, y_pred: np.ndarray, k: int, threshold: int = 2) -> float:
    """
    Compute Precision@K (fraction of top-K with label >= threshold).
    
    Args:
        y_true: Binary or graded labels
        y_pred: Predicted scores
        k: K value
        threshold: Minimum label value to consider relevant (default: 2)
    
    Returns:
        Precision@K score
    """
    if len(y_true) == 0:
        return 0.0
    
    k = min(k, len(y_true))
    top_k_idx = np.argsort(y_pred)[::-1][:k]
    relevant = sum(y_true[idx] >= threshold for idx in top_k_idx)
    
    return relevant / k
