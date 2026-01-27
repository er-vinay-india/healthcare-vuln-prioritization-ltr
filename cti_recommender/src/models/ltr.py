"""
Learning-to-Rank (LTR) Model Training Module

This module implements LambdaMART training with confidence weighting
for CVE prioritization.
"""

from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
import lightgbm as lgb


def prepare_ranking_data(
    df: pd.DataFrame,
    feature_cols: List[str],
    label_col: str = 'soft_label',
    confidence_col: str = 'label_confidence',
    group_col: str = 'published_week'
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[int], pd.DataFrame]:
    """
    Prepare data for LightGBM ranking with proper group handling.
    
    Within each group, samples are sorted by label descending to ensure
    high-relevance items come first (important for LambdaRank).
    
    Args:
        df: DataFrame with features and labels
        feature_cols: List of feature column names
        label_col: Label column name (default: 'soft_label')
        confidence_col: Confidence weights column (default: 'label_confidence')
        group_col: Grouping column for ranking (default: 'published_week')
    
    Returns:
        Tuple of (X, y, weights, group_sizes, df_sorted)
    """
    # Sort by group and then by label descending within each group
    df_sorted = df.sort_values([group_col, label_col], ascending=[True, False]).copy()
    
    # Extract features, labels, weights
    X = df_sorted[feature_cols].values
    y = df_sorted[label_col].values
    weights = df_sorted[confidence_col].values
    
    # Compute group sizes
    group_sizes = df_sorted.groupby(group_col).size().tolist()
    
    # Verify alignment
    assert len(X) == len(y) == len(weights) == sum(group_sizes), \
        f"Mismatch: X={len(X)}, y={len(y)}, w={len(weights)}, groups={sum(group_sizes)}"
    
    return X, y, weights, group_sizes, df_sorted


def train_lambdarank(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: List[str],
    params: Optional[Dict] = None,
    random_seed: int = 42
) -> lgb.Booster:
    """
    Train LightGBM LambdaRank with confidence-weighted labels.
    
    The key innovation: using label_confidence as sample weights.
    LightGBM's LambdaRank will give more importance to pairs involving high-confidence labels.
    
    Args:
        train_df: Training data with soft_label and label_confidence
        val_df: Validation data for early stopping
        feature_cols: List of feature column names
        params: Optional LightGBM parameters override
        random_seed: Random seed for reproducibility
        
    Returns:
        Trained LightGBM Booster
    """
    print("\n" + "=" * 70)
    print("TRAINING CONFIDENCE-WEIGHTED LAMBDARANK")
    print("=" * 70)
    
    # Default parameters
    default_params = {
        'objective': 'lambdarank',
        'metric': 'ndcg',
        'ndcg_eval_at': [5, 10, 20],
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.8,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'min_data_in_leaf': 20,
        'max_depth': 6,
        'verbose': -1,
        'seed': random_seed,
        'force_row_wise': True,
    }
    
    if params:
        default_params.update(params)
    
    # Prepare training data
    print("\nPreparing training data...")
    X_train, y_train, w_train, group_train, train_sorted = prepare_ranking_data(
        train_df, feature_cols
    )
    print(f"  Train: {len(X_train):,} samples, {len(group_train):,} groups")
    print(f"  Confidence weights: min={w_train.min():.3f}, mean={w_train.mean():.3f}, max={w_train.max():.3f}")
    
    # Prepare validation data
    print("\nPreparing validation data...")
    X_val, y_val, w_val, group_val, val_sorted = prepare_ranking_data(
        val_df, feature_cols
    )
    print(f"  Val: {len(X_val):,} samples, {len(group_val):,} groups")
    
    # Create LightGBM datasets
    train_data = lgb.Dataset(
        X_train, label=y_train, weight=w_train, group=group_train,
        feature_name=feature_cols
    )
    val_data = lgb.Dataset(
        X_val, label=y_val, weight=w_val, group=group_val,
        reference=train_data, feature_name=feature_cols
    )
    
    # Training callbacks
    callbacks = [
        lgb.early_stopping(stopping_rounds=30, verbose=True),
        lgb.log_evaluation(period=50)
    ]
    
    # Train model
    print("\nTraining LambdaRank model...")
    print(f"Parameters: {default_params}")
    
    model = lgb.train(
        default_params,
        train_data,
        num_boost_round=500,
        valid_sets=[train_data, val_data],
        valid_names=['train', 'valid'],
        callbacks=callbacks
    )
    
    print(f"\nTraining complete!")
    print(f"  Best iteration: {model.best_iteration}")
    print(f"  Best validation NDCG@10: {model.best_score['valid']['ndcg@10']:.4f}")
    
    return model


def cross_validate(
    df: pd.DataFrame,
    feature_cols: List[str],
    label_col: str,
    confidence_col: Optional[str],
    group_col: str,
    n_folds: int = 5,
    params: Optional[Dict] = None
) -> List[Dict]:
    """
    Perform k-fold cross-validation for LambdaMART.
    
    Args:
        df: Full DataFrame
        feature_cols: Feature columns
        label_col: Label column
        confidence_col: Confidence column
        group_col: Group column
        n_folds: Number of CV folds
        params: Model parameters
    
    Returns:
        List of result dicts (one per fold)
    """
    # TODO: Implement CV logic
    raise NotImplementedError("To be implemented")


def save_model(model: lgb.Booster, path: str) -> None:
    """Save trained model to disk."""
    model.save_model(path)


def load_model(path: str) -> lgb.Booster:
    """Load trained model from disk."""
    return lgb.Booster(model_file=path)


def get_default_ltr_params() -> Dict:
    """
    Return default LightGBM LambdaMART parameters.
    
    Returns:
        Dict of LightGBM parameters
    """
    return {
        'objective': 'lambdarank',
        'metric': 'ndcg',
        'ndcg_eval_at': [5, 10, 20],
        'boosting_type': 'gbdt',
        'num_leaves': 31,
        'learning_rate': 0.05,
        'feature_fraction': 0.9,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': -1,
        'max_depth': 6,
        'min_data_in_leaf': 50,
    }
