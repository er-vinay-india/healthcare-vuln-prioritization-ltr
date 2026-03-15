#!/usr/bin/env python3
"""
Temporal Validation for Pruned Model
Train on 2018-2024, test on 2025 with pruned features and strong regularization.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.metrics import ndcg_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def load_temporal_data():
    """Load data split by publication year."""
    logger.info("Loading temporal data from database...")
    db = CVEDatabase()

    import sqlite3
    sqlite3.register_adapter(type(None), lambda x: None)

    query = """
    SELECT 
        e.cve_id,
        e.kev_flag,
        e.epss_score,
        e.is_healthcare,
        e.is_curated,
        e.attack_technique_count,
        e.label,
        c.cvss,
        CAST(c.published AS TEXT) as published,
        c.description
    FROM enrichments e
    LEFT JOIN cves c ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    """

    try:
        df = pd.read_sql_query(query, db.conn)
    except Exception:
        logger.exception("Failed to load temporal data from database")
        raise
    finally:
        db.close()

    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    df['year'] = df['published'].dt.year

    train_df = df[df['year'] < 2025].copy()
    test_df = df[df['year'] == 2025].copy()

    logger.info("Temporal Split:")
    logger.info(f"  Train (2018-2024): {len(train_df):,} CVEs")
    logger.info(f"  Test (2025):       {len(test_df):,} CVEs")

    return train_df, test_df

def prepare_pruned_features(df, scaler=None):
    """Extract pruned features (14 features)."""
    features = pd.DataFrame({
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
        'cvss': df['cvss'].fillna(0.0),
    })
    
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    features['attack_multi'] = (features['attack_technique_count'] > 1).astype(int)
    features['attack_count_x_healthcare'] = features['attack_technique_count'] * features['is_healthcare']
    
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    continuous_cols = ['cvss', 'epss_score', 'attack_technique_count', 
                       'attack_count_x_healthcare', 'days_since_2018']
    
    if scaler is None:
        scaler = StandardScaler()
        features[continuous_cols] = scaler.fit_transform(features[continuous_cols])
    else:
        features[continuous_cols] = scaler.transform(features[continuous_cols])
    
    return features, df['label'], scaler

def train_pruned_model(X_train, y_train, X_test, y_test):
    """Train with pruned features and strong regularization."""
    logger.info("Training pruned model with strong regularization...")
    
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.05,
        'max_depth': 5,
        'min_child_weight': 5,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'alpha': 0.1,
        'lambda': 2.0,
        'seed': 42
    }
    
    evals = [(dtrain, 'train'), (dtest, 'test')]
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=100,
        evals=evals,
        early_stopping_rounds=10,
        verbose_eval=20
    )
    
    return model

def evaluate_temporal(model, X_test, y_test, feature_names):
    """Evaluate on 2025 data."""
    logger.info("="*70)
    logger.info("PRUNED MODEL: TEMPORAL VALIDATION (2025 TEST SET)")
    logger.info("="*70)

    dtest = xgb.DMatrix(X_test, feature_names=feature_names)
    y_pred = model.predict(dtest)

    ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)

    logger.info("NDCG Scores on 2025 CVEs:")
    logger.info(f"  NDCG@5:  {ndcg_5:.4f}")
    logger.info(f"  NDCG@10: {ndcg_10:.4f}")
    logger.info(f"  NDCG@20: {ndcg_20:.4f}")

    top_k_indices = np.argsort(y_pred)[::-1]

    logger.info("Precision at K:")
    for k in [10, 20, 50, 100]:
        top_k = y_test.iloc[top_k_indices[:k]]
        high_priority = (top_k >= 3).sum()
        logger.info(f"  P@{k:3d}: {100*high_priority/k:5.1f}% ({high_priority}/{k} L3+)")

    logger.info("Label Distribution in Top 100 (2025 CVEs):")
    top_100_labels = y_test.iloc[top_k_indices[:100]]
    for label in sorted(top_100_labels.unique(), reverse=True):
        count = (top_100_labels == label).sum()
        label_name = ['L0', 'L1', 'L2', 'L3', 'L4'][label] if label < 5 else f'L{label}'
        logger.info(f"  {label_name}: {count:3d} ({100*count/100:.0f}%)")

    return {'ndcg_5': ndcg_5, 'ndcg_10': ndcg_10, 'ndcg_20': ndcg_20}

def main() -> int:
    logger.info("="*70)
    logger.info("PRUNED MODEL: TEMPORAL VALIDATION")
    logger.info("Train: 2018-2024 | Test: 2025")
    logger.info("Features: 14 (pruned) | Regularization: STRONG")
    logger.info("="*70)

    try:
        train_df, test_df = load_temporal_data()

        logger.info("Preparing training features...")
        X_train, y_train, scaler = prepare_pruned_features(train_df)

        logger.info("Preparing test features...")
        X_test, y_test, _ = prepare_pruned_features(test_df, scaler=scaler)

        model = train_pruned_model(X_train, y_train, X_test, y_test)
        results = evaluate_temporal(model, X_test, y_test, X_train.columns.tolist())

        logger.info("="*70)
        logger.info("[OK] Temporal validation complete!")
        logger.info("="*70)
        logger.info(f"Pruned model NDCG@10 on 2025: {results['ndcg_10']:.4f}")
        logger.info(f"Drop: {1.0 - results['ndcg_10']:.4f} (due to regularization + feature pruning)")
        return 0

    except Exception:
        logger.exception("Temporal validation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
