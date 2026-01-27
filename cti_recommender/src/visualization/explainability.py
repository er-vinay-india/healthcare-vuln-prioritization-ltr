"""
Explainability Visualization Module

This module creates visualizations for model explainability,
including feature importance and SHAP analysis.
"""

from typing import List, Optional, Tuple
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import lightgbm as lgb


def plot_feature_importance(
    model: lgb.Booster,
    feature_names: Optional[List[str]] = None,
    importance_type: str = 'gain',
    max_features: int = 20,
    figsize: tuple = (10, 8)
) -> None:
    """
    Plot LightGBM feature importance.
    
    Args:
        model: Trained LightGBM model
        feature_names: Optional list of feature names
        importance_type: 'gain' or 'split'
        max_features: Maximum number of features to show
        figsize: Figure size
    """
    # Get feature importance
    importance = model.feature_importance(importance_type=importance_type)
    
    if feature_names is None:
        feature_names = [f"feature_{i}" for i in range(len(importance))]
    
    # Create DataFrame and sort
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importance
    }).sort_values('importance', ascending=False).head(max_features)
    
    # Plot
    plt.figure(figsize=figsize)
    importance_sorted = importance_df.sort_values('importance', ascending=True)
    plt.barh(importance_sorted['feature'], importance_sorted['importance'], 
             color='steelblue' if importance_type == 'gain' else 'forestgreen')
    plt.xlabel(f'Importance ({importance_type})')
    plt.title(f'Top {max_features} Features by {importance_type.capitalize()}')
    plt.tight_layout()
    plt.show()
    
    # Print text summary
    print(f"\nTop {min(15, max_features)} Features by {importance_type.capitalize()}:")
    print("-" * 50)
    for _, row in importance_df.head(15).iterrows():
        bar = "#" * int(row['importance'] / importance_df['importance'].max() * 30)
        print(f"  {row['feature']:30s} {row['importance']:>10.1f} {bar}")


def plot_feature_importance_comparison(
    model: lgb.Booster,
    feature_names: List[str],
    figsize: tuple = (14, 6)
) -> None:
    """
    Plot feature importance by both gain and split count side-by-side.
    
    Args:
        model: Trained LightGBM model
        feature_names: List of feature names
        figsize: Figure size
    """
    # Get both importance types
    importance_gain = model.feature_importance(importance_type='gain')
    importance_split = model.feature_importance(importance_type='split')
    
    # Create DataFrame
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'gain': importance_gain,
        'split': importance_split
    }).sort_values('gain', ascending=False)
    
    # Create subplots
    fig, axes = plt.subplots(1, 2, figsize=figsize)
    
    # Gain importance
    ax1 = axes[0]
    importance_df_sorted = importance_df.sort_values('gain', ascending=True)
    ax1.barh(importance_df_sorted['feature'], importance_df_sorted['gain'], color='steelblue')
    ax1.set_xlabel('Gain')
    ax1.set_title('Feature Importance by Gain')
    
    # Split importance
    ax2 = axes[1]
    importance_by_split = importance_df.sort_values('split', ascending=True)
    ax2.barh(importance_by_split['feature'], importance_by_split['split'], color='forestgreen')
    ax2.set_xlabel('Split Count')
    ax2.set_title('Feature Importance by Split Count')
    
    plt.tight_layout()
    plt.show()


def plot_shap_summary(
    model: lgb.Booster,
    X: pd.DataFrame,
    feature_names: Optional[List[str]] = None,
    max_display: int = 20,
    sample_size: int = 5000,
    random_seed: int = 42,
    figsize: tuple = (10, 8)
) -> Optional[np.ndarray]:
    """
    Plot SHAP summary (requires shap library).
    
    Args:
        model: Trained LightGBM model
        X: Feature matrix (DataFrame or numpy array)
        feature_names: Optional list of feature names
        max_display: Max features to display
        sample_size: Number of samples to use for SHAP (for performance)
        random_seed: Random seed for sampling
        figsize: Figure size
    
    Returns:
        SHAP values array if successful, None if SHAP not available
    """
    try:
        import shap
    except ImportError:
        print("SHAP library not installed. Skipping SHAP analysis.")
        print("To enable SHAP, run: pip install shap")
        return None
    
    # Sample data if needed
    if len(X) > sample_size:
        print(f"Sampling {sample_size} from {len(X)} samples for SHAP computation...")
        sample_idx = np.random.RandomState(random_seed).choice(len(X), sample_size, replace=False)
        X_sample = X.iloc[sample_idx] if isinstance(X, pd.DataFrame) else X[sample_idx]
    else:
        X_sample = X
    
    print(f"Computing SHAP values on {len(X_sample)} samples...")
    
    # Create SHAP explainer
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    
    # Get feature names
    if feature_names is None:
        if isinstance(X_sample, pd.DataFrame):
            feature_names = X_sample.columns.tolist()
        else:
            feature_names = [f"feature_{i}" for i in range(X_sample.shape[1])]
    
    # Summary plot
    print("\nSHAP Summary Plot:")
    plt.figure(figsize=figsize)
    shap.summary_plot(shap_values, X_sample, feature_names=feature_names, 
                     max_display=max_display, show=False)
    plt.tight_layout()
    plt.show()
    
    # Mean absolute SHAP values (text)
    mean_shap = np.abs(shap_values).mean(axis=0)
    shap_importance = pd.DataFrame({
        'feature': feature_names,
        'mean_abs_shap': mean_shap
    }).sort_values('mean_abs_shap', ascending=False)
    
    print("\nMean Absolute SHAP Values:")
    print("-" * 50)
    for _, row in shap_importance.iterrows():
        bar = "#" * int(row['mean_abs_shap'] / shap_importance['mean_abs_shap'].max() * 30)
        print(f"  {row['feature']:30s} {row['mean_abs_shap']:>8.4f} {bar}")
    
    return shap_values


def analyze_top_predictions(
    df: pd.DataFrame,
    score_col: str,
    top_k: int = 20,
    feature_cols: Optional[List[str]] = None,
    label_col: Optional[str] = 'soft_label'
) -> pd.DataFrame:
    """
    Analyze characteristics of top-K predictions.
    
    Args:
        df: DataFrame with scores and features
        score_col: Predicted score column
        top_k: Number of top predictions to analyze
        feature_cols: Optional list of features to include
        label_col: Optional label column name
    
    Returns:
        DataFrame with top-K CVEs and their features
    """
    # Sort by score and get top K
    top_k_df = df.nlargest(top_k, score_col).copy()
    
    # Select columns to display
    display_cols = ['cve_id', 'published', score_col]
    if label_col and label_col in df.columns:
        display_cols.append(label_col)
    
    if feature_cols:
        display_cols.extend([c for c in feature_cols if c in df.columns])
    else:
        # Include all numeric columns
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        display_cols.extend([c for c in numeric_cols if c not in display_cols])
    
    # Filter to available columns
    display_cols = [c for c in display_cols if c in top_k_df.columns]
    
    return top_k_df[display_cols]


def explain_individual_predictions(
    df: pd.DataFrame,
    score_col: str,
    feature_cols: List[str],
    label_col: str = 'soft_label',
    confidence_col: str = 'label_confidence',
    label_source_col: str = 'label_source',
    model: Optional[lgb.Booster] = None,
    n_examples: int = 5,
    random_seed: int = 42
) -> None:
    """
    Print detailed explanations for individual CVE predictions.
    
    Selects diverse examples (one from each label if possible) and shows
    their features, predictions, and SHAP contributions (if model provided).
    
    Args:
        df: DataFrame with predictions and features
        score_col: Predicted score column
        feature_cols: List of feature columns
        label_col: Label column name
        confidence_col: Confidence column name
        label_source_col: Label source column name
        model: Optional LightGBM model for SHAP explanations
        n_examples: Number of examples to show
        random_seed: Random seed for reproducibility
    """
    print("\n" + "=" * 70)
    print(f"EXAMPLE CVE EXPLANATIONS ({n_examples} diverse examples)")
    print("=" * 70)
    
    # Select diverse examples (one from each label if possible)
    examples = []
    unique_labels = sorted(df[label_col].unique(), reverse=True)
    
    for label in unique_labels:
        label_df = df[df[label_col] == label]
        if len(label_df) > 0:
            # Get highest-scored example for this label
            example = label_df.nlargest(1, score_col).iloc[0]
            examples.append(example)
            if len(examples) >= n_examples:
                break
    
    # If we don't have enough examples yet, add more from top predictions
    if len(examples) < n_examples:
        remaining = df.nlargest(20, score_col)
        for _, row in remaining.iterrows():
            if len(examples) >= n_examples:
                break
            if row['cve_id'] not in [e['cve_id'] for e in examples]:
                examples.append(row)
    
    # SHAP explainer if model provided
    explainer = None
    if model is not None:
        try:
            import shap
            explainer = shap.TreeExplainer(model)
        except ImportError:
            print("Note: SHAP library not available for detailed feature contributions\n")
    
    # Print each example
    for i, example in enumerate(examples, 1):
        print(f"\n[Example {i}]")
        print(f"  CVE ID:          {example['cve_id']}")
        
        if 'published' in example.index:
            pub_date = example['published']
            print(f"  Published:       {pub_date.date() if hasattr(pub_date, 'date') else pub_date}")
        
        print(f"  Soft Label:      {example[label_col]}")
        
        if confidence_col in example.index:
            print(f"  Confidence:      {example[confidence_col]:.3f}")
        
        print(f"  Predicted Score: {example[score_col]:.4f}")
        
        if label_source_col in example.index:
            print(f"  Label Source:    {example[label_source_col]}")
        
        # Show key feature values
        print("  Key Features:")
        key_features = ['kev_flag', 'epss_score', 'cvss_norm', 'is_healthcare', 'has_attack']
        for feat in key_features:
            if feat in example.index:
                val = example[feat]
                if isinstance(val, float):
                    print(f"    - {feat:15s}: {val:.4f}")
                else:
                    print(f"    - {feat:15s}: {val}")
        
        # SHAP contributions if available
        if explainer is not None:
            example_features = example[feature_cols].values.reshape(1, -1)
            example_shap = explainer.shap_values(example_features)[0]
            
            # Get top 3 contributing features
            feature_contrib = list(zip(feature_cols, example_shap))
            feature_contrib.sort(key=lambda x: abs(x[1]), reverse=True)
            
            print("  Top SHAP Contributors:")
            for fname, fshap in feature_contrib[:3]:
                direction = "+" if fshap > 0 else ""
                print(f"    - {fname}: {direction}{fshap:.4f}")
    
    print("\n" + "=" * 70)
