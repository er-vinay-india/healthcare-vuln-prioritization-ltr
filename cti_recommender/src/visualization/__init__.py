"""Visualization modules for EDA and explainability."""

# EDA visualizations
from .eda import (
    plot_temporal_trends,
    plot_cvss_distribution,
    plot_kev_analysis,
    plot_attack_coverage,
    plot_label_distribution,
    plot_all_eda
)

# Model explainability
from .explainability import (
    plot_feature_importance,
    plot_feature_importance_comparison,
    plot_shap_summary,
    analyze_top_predictions,
    explain_individual_predictions
)

__all__ = [
    # EDA
    'plot_temporal_trends',
    'plot_cvss_distribution',
    'plot_kev_analysis',
    'plot_attack_coverage',
    'plot_label_distribution',
    'plot_all_eda',
    # Explainability
    'plot_feature_importance',
    'plot_feature_importance_comparison',
    'plot_shap_summary',
    'analyze_top_predictions',
    'explain_individual_predictions',
]
