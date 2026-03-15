"""
Learning-to-Rank (LTR) Model Training Module

This module implements LambdaMART training with confidence weighting
for CVE prioritization.
"""

from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
import lightgbm as lgb


def diagnose_feature_matrix(df: pd.DataFrame, feature_cols: List[str], *, label: str = "train") -> Dict[str, List[str]]:
    """Print lightweight feature quality diagnostics before model training."""
    missing_cols = [c for c in feature_cols if c not in df.columns]
    if missing_cols:
        raise KeyError(f"Missing feature columns in {label} data: {missing_cols}")

    stats = df[feature_cols]
    nunique = stats.nunique(dropna=False)
    zero_variance = nunique[nunique <= 1].index.tolist()

    # Use non-null denominator to avoid penalizing sparse columns with nulls.
    non_zero_rate = {}
    for col in feature_cols:
        s = stats[col].fillna(0)
        non_zero_rate[col] = float((s != 0).mean())
    mostly_zero = [c for c in feature_cols if non_zero_rate[c] < 0.01]

    print(f"\nFeature diagnostics ({label}):")
    print(f"  Total configured features: {len(feature_cols)}")
    print(f"  Zero-variance features: {len(zero_variance)}")
    print(f"  Mostly-zero (<1% non-zero): {len(mostly_zero)}")
    if zero_variance:
        print(f"  [WARN] Zero-variance: {zero_variance[:10]}{' ...' if len(zero_variance) > 10 else ''}")
    if mostly_zero:
        print(f"  [INFO] Mostly-zero: {mostly_zero[:10]}{' ...' if len(mostly_zero) > 10 else ''}")

    return {
        'zero_variance': zero_variance,
        'mostly_zero': mostly_zero,
    }


def _coerce_pair_to_numeric(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: List[str],
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Coerce feature columns to numeric values consistently for LightGBM.

    This prevents notebook-only preprocessing drift (e.g., string categories).
    """
    train_out = train_df.copy()
    val_out = val_df.copy()

    for col in feature_cols:
        t = train_out[col]
        v = val_out[col]

        if pd.api.types.is_numeric_dtype(t):
            train_out[col] = pd.to_numeric(t, errors='coerce')
            val_out[col] = pd.to_numeric(v, errors='coerce')
            continue

        # Try numeric conversion first (handles numeric strings cleanly).
        t_num = pd.to_numeric(t, errors='coerce')
        v_num = pd.to_numeric(v, errors='coerce')
        if t_num.notna().mean() > 0.95 and v_num.notna().mean() > 0.95:
            train_out[col] = t_num
            val_out[col] = v_num
            continue

        # Fallback: shared categorical encoding over train+val to keep mapping stable.
        combined = pd.concat([t.astype(str), v.astype(str)], ignore_index=True).fillna('nan')
        categories = pd.Index(combined.unique())
        mapping = {cat: idx for idx, cat in enumerate(categories)}

        train_out[col] = t.astype(str).map(mapping).astype(float)
        val_out[col] = v.astype(str).map(mapping).astype(float)

    train_out[feature_cols] = train_out[feature_cols].fillna(0.0)
    val_out[feature_cols] = val_out[feature_cols].fillna(0.0)
    return train_out, val_out


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

    # Ensure all feature columns are numeric in both splits.
    train_df, val_df = _coerce_pair_to_numeric(train_df, val_df, feature_cols)

    diagnose_feature_matrix(train_df, feature_cols, label='train')
    diagnose_feature_matrix(val_df, feature_cols, label='validation')
    
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
        # Slightly higher capacity + lower split threshold helps sparse but useful signals compete.
        'num_leaves': 63,
        'learning_rate': 0.05,
        'feature_fraction': 1.0,
        'bagging_fraction': 0.8,
        'bagging_freq': 5,
        'verbose': -1,
        'max_depth': 6,
        'min_data_in_leaf': 10,
        'min_gain_to_split': 0.0,
    }
