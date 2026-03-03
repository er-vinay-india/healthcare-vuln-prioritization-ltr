"""Model evaluation and comparison modules."""

from .metrics import evaluate_ranking, ndcg_at_k, precision_at_k, recall_at_k, compute_ranking_metrics
from .significance import (
    wilcoxon_test, 
    bonferroni_correction,
    pairwise_significance_test,
    create_comparison_table,
    print_significance_report
)

# Try to import comparison module if it exists
try:
    from .comparison import compare_models, rank_models, save_comparison_results
    __all__ = [
        'evaluate_ranking',
        'ndcg_at_k',
        'precision_at_k',
        'recall_at_k',
        'compute_ranking_metrics',
        'compare_models',
        'rank_models',
        'save_comparison_results',
        'wilcoxon_test',
        'bonferroni_correction',
        'pairwise_significance_test',
        'create_comparison_table',
        'print_significance_report',
    ]
except ImportError:
    __all__ = [
        'evaluate_ranking',
        'ndcg_at_k',
        'precision_at_k',
        'recall_at_k',
        'compute_ranking_metrics',
        'wilcoxon_test',
        'bonferroni_correction',
        'pairwise_significance_test',
        'create_comparison_table',
        'print_significance_report',
    ]

