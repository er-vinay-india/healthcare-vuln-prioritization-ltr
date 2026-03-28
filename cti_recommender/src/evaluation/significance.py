"""
Statistical Significance Testing Module

This module implements statistical tests for comparing model performance,
including Wilcoxon signed-rank test and Bonferroni correction for multiple
hypothesis testing.
"""

from typing import Dict, List, Tuple, Optional
import pandas as pd
import numpy as np
from scipy import stats
from itertools import combinations


def wilcoxon_test(
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    alternative: str = 'two-sided'
) -> Tuple[float, float]:
    """
    Perform Wilcoxon signed-rank test for paired samples.
    
    The Wilcoxon signed-rank test is a non-parametric test for comparing
    two related samples. It's appropriate for ranking metrics where the
    distribution may not be normal.
    
    Args:
        scores_a: Metric scores for model A (per-group or per-sample)
        scores_b: Metric scores for model B (per-group or per-sample)
        alternative: 'two-sided', 'less', or 'greater'
    
    Returns:
        Tuple of (statistic, p_value)
    """
    scores_a = np.asarray(scores_a)
    scores_b = np.asarray(scores_b)
    
    # Filter out pairs where both are identical (no information)
    diff = scores_a - scores_b
    non_zero_mask = diff != 0
    
    if non_zero_mask.sum() < 5:
        # Not enough non-zero differences for reliable test
        return np.nan, 1.0
    
    try:
        statistic, p_value = stats.wilcoxon(
            scores_a[non_zero_mask],
            scores_b[non_zero_mask],
            alternative=alternative,
            zero_method='wilcox'
        )
        return float(statistic), float(p_value)
    except Exception as e:
        print(f"Warning: Wilcoxon test failed: {e}")
        return np.nan, 1.0


def paired_t_test(
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    alternative: str = 'two-sided'
) -> Tuple[float, float]:
    """
    Perform paired t-test for comparing two models.
    
    Args:
        scores_a: Metric scores for model A
        scores_b: Metric scores for model B
        alternative: 'two-sided', 'less', or 'greater'
    
    Returns:
        Tuple of (statistic, p_value)
    """
    scores_a = np.asarray(scores_a)
    scores_b = np.asarray(scores_b)
    
    if len(scores_a) < 5:
        return np.nan, 1.0
    
    try:
        statistic, p_value = stats.ttest_rel(scores_a, scores_b, alternative=alternative)
        return float(statistic), float(p_value)
    except Exception as e:
        print(f"Warning: Paired t-test failed: {e}")
        return np.nan, 1.0


def bonferroni_correction(
    p_values: List[float],
    alpha: float = 0.05
) -> Tuple[List[bool], float]:
    """
    Apply Bonferroni correction for multiple hypothesis testing.
    
    The Bonferroni correction is conservative but controls the family-wise
    error rate (FWER) by dividing alpha by the number of tests.
    
    Args:
        p_values: List of p-values from multiple tests
        alpha: Significance level (default: 0.05)
    
    Returns:
        Tuple of (list of booleans indicating significance, corrected alpha)
    """
    n_tests = len(p_values)
    if n_tests == 0:
        return [], alpha
    
    corrected_alpha = alpha / n_tests
    significant = [p <= corrected_alpha for p in p_values]
    
    return significant, corrected_alpha


def holm_bonferroni_correction(
    p_values: List[float],
    alpha: float = 0.05
) -> Tuple[List[bool], List[float]]:
    """
    Apply Holm-Bonferroni step-down correction.
    
    Less conservative than Bonferroni while still controlling FWER.
    
    Args:
        p_values: List of p-values
        alpha: Significance level
    
    Returns:
        Tuple of (list of significance flags, adjusted p-values)
    """
    n = len(p_values)
    if n == 0:
        return [], []
    
    # Sort p-values and keep track of original indices
    sorted_indices = np.argsort(p_values)
    sorted_p = np.array(p_values)[sorted_indices]
    
    # Compute adjusted p-values
    adjusted_p = np.zeros(n)
    significant = [False] * n
    
    for i, idx in enumerate(sorted_indices):
        # Holm-Bonferroni threshold: alpha / (n - i)
        threshold = alpha / (n - i)
        if sorted_p[i] <= threshold:
            significant[idx] = True
            adjusted_p[idx] = sorted_p[i] * (n - i)
        else:
            adjusted_p[idx] = min(sorted_p[i] * (n - i), 1.0)
    
    return significant, adjusted_p.tolist()


def compute_per_group_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    groups: np.ndarray,
    k: int = 10
) -> np.ndarray:
    """
    Compute NDCG@k for each group separately.
    
    Args:
        y_true: True relevance labels
        y_pred: Predicted scores
        groups: Group identifiers (e.g., week)
        k: Cutoff for NDCG
    
    Returns:
        Array of NDCG@k scores, one per group
    """
    from sklearn.metrics import ndcg_score
    
    unique_groups = np.unique(groups)
    group_metrics = []
    
    for group in unique_groups:
        mask = groups == group
        group_true = y_true[mask]
        group_pred = y_pred[mask]
        
        if len(group_true) < 2:
            continue
        
        try:
            # Reshape for sklearn ndcg_score
            ndcg = ndcg_score([group_true], [group_pred], k=k)
            group_metrics.append(ndcg)
        except Exception:
            continue
    
    return np.array(group_metrics)


def pairwise_significance_test(
    model_predictions: Dict[str, np.ndarray],
    y_true: np.ndarray,
    groups: np.ndarray,
    k: int = 10,
    alpha: float = 0.05,
    test: str = 'wilcoxon'
) -> pd.DataFrame:
    """
    Perform pairwise significance tests between all models.
    
    Computes per-group NDCG@k for each model, then performs pairwise
    statistical tests with multiple testing correction.
    
    Args:
        model_predictions: Dict mapping model names to prediction arrays
        y_true: True relevance labels
        groups: Group identifiers for per-group evaluation
        k: Cutoff for NDCG
        alpha: Significance level
        test: 'wilcoxon' or 'ttest'
    
    Returns:
        DataFrame with pairwise p-values and significance flags
    """
    model_names = list(model_predictions.keys())
    n_models = len(model_names)
    
    # Compute per-group metrics for each model
    group_metrics = {}
    for name, preds in model_predictions.items():
        group_metrics[name] = compute_per_group_metrics(y_true, preds, groups, k)
    
    # Ensure all models have same number of groups
    min_groups = min(len(m) for m in group_metrics.values())
    for name in group_metrics:
        group_metrics[name] = group_metrics[name][:min_groups]
    
    # Perform pairwise tests
    results = []
    p_values = []
    
    for model_a, model_b in combinations(model_names, 2):
        scores_a = group_metrics[model_a]
        scores_b = group_metrics[model_b]
        
        if test == 'wilcoxon':
            stat, p_val = wilcoxon_test(scores_a, scores_b)
        else:
            stat, p_val = paired_t_test(scores_a, scores_b)
        
        mean_diff = np.mean(scores_a) - np.mean(scores_b)
        
        results.append({
            'model_a': model_a,
            'model_b': model_b,
            'mean_a': np.mean(scores_a),
            'mean_b': np.mean(scores_b),
            'mean_diff': mean_diff,
            'statistic': stat,
            'p_value': p_val
        })
        p_values.append(p_val)
    
    # Apply multiple testing correction
    significant, corrected_alpha = bonferroni_correction(p_values, alpha)
    
    for i, result in enumerate(results):
        result['significant'] = significant[i]
        result['corrected_alpha'] = corrected_alpha
    
    return pd.DataFrame(results)


def cliffs_delta(a: np.ndarray, b: np.ndarray) -> float:
    """Compute Cliff's delta (non-parametric effect size) between two samples.

    Returns a value in [-1, 1].  |delta| < 0.147 is negligible,
    0.147–0.33 is small, 0.33–0.474 is medium, >= 0.474 is large.

    Args:
        a: First sample (e.g. scores of model A).
        b: Second sample (e.g. scores of model B).

    Returns:
        Cliff's delta as a float.
    """
    a = np.asarray(a)
    b = np.asarray(b)
    m, n = len(a), len(b)
    if m == 0 or n == 0:
        return 0.0
    dominance = sum(1 if ai > bi else (-1 if ai < bi else 0) for ai in a for bi in b)
    return dominance / (m * n)


def create_comparison_table(
    model_results: Dict[str, Dict[str, float]],
    baseline_name: str = None,
    significance_df: pd.DataFrame = None
) -> pd.DataFrame:
    """
    Create a formatted comparison table with metrics and p-values.
    
    Args:
        model_results: Dict of {model_name: {metric_name: value}}
        baseline_name: Name of baseline model for comparison
        significance_df: DataFrame from pairwise_significance_test
    
    Returns:
        Formatted comparison DataFrame
    """
    # Create base table
    df = pd.DataFrame(model_results).T
    df.index.name = 'Model'
    
    # Add improvement over baseline if specified
    if baseline_name and baseline_name in df.index:
        baseline_values = df.loc[baseline_name]
        for col in df.columns:
            if col.startswith('NDCG') or col.startswith('P@') or col.startswith('MAP'):
                improvement_col = f'{col}_vs_baseline'
                df[improvement_col] = ((df[col] - baseline_values[col]) / baseline_values[col] * 100).round(2)
    
    # Add p-values if significance test results provided
    if significance_df is not None and baseline_name:
        p_value_map = {}
        for _, row in significance_df.iterrows():
            if row['model_a'] == baseline_name:
                p_value_map[row['model_b']] = row['p_value']
            elif row['model_b'] == baseline_name:
                p_value_map[row['model_a']] = row['p_value']
        
        df['p_value_vs_baseline'] = df.index.map(lambda x: p_value_map.get(x, np.nan))
        df['significant'] = df['p_value_vs_baseline'] < 0.05 / len(p_value_map)  # Bonferroni
    
    return df


def print_significance_report(
    significance_df: pd.DataFrame,
    model_results: Dict[str, Dict[str, float]] = None
) -> None:
    """
    Print a formatted significance test report.
    
    Args:
        significance_df: DataFrame from pairwise_significance_test
        model_results: Optional model metrics for context
    """
    print("\n" + "=" * 80)
    print("STATISTICAL SIGNIFICANCE REPORT")
    print("=" * 80)
    
    if model_results:
        print("\nModel Performance Summary:")
        print("-" * 60)
        for model, metrics in model_results.items():
            ndcg = metrics.get('NDCG@10', metrics.get('ndcg_10', 'N/A'))
            print(f"  {model:30s}: NDCG@10 = {ndcg:.4f}" if isinstance(ndcg, float) else f"  {model:30s}: {ndcg}")
    
    print("\nPairwise Significance Tests (Wilcoxon signed-rank):")
    print("-" * 60)
    
    corrected_alpha = significance_df['corrected_alpha'].iloc[0] if 'corrected_alpha' in significance_df.columns else 0.05
    print(f"Bonferroni-corrected α = {corrected_alpha:.4f}")
    print()
    
    for _, row in significance_df.iterrows():
        sig_marker = "[OK]" if row.get('significant', False) else "[X]"
        p_str = f"{row['p_value']:.4f}" if not np.isnan(row['p_value']) else "N/A"
        diff_sign = "+" if row['mean_diff'] > 0 else ""
        
        print(f"  {row['model_a']:20s} vs {row['model_b']:20s}")
        print(f"    Mean diff: {diff_sign}{row['mean_diff']:.4f}")
        print(f"    p-value:   {p_str} {sig_marker}")
        print()
    
    # Summary
    n_significant = significance_df['significant'].sum() if 'significant' in significance_df.columns else 0
    n_tests = len(significance_df)
    print("-" * 60)
    print(f"Summary: {n_significant}/{n_tests} comparisons significant after Bonferroni correction")
    print("=" * 80)
