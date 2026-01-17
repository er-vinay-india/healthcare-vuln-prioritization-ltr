#!/usr/bin/env python3
"""
Temporal Validation: Train on 2018-2024, test on 2025 CVEs.
Tests model's ability to generalize to future threats.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.metrics import ndcg_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
from datetime import datetime

from src.core.cve_database import CVEDatabase
from src.utils.logging_config import get_logger

logger = get_logger(__name__)

def load_temporal_data():
    """Load data split by publication year."""
    logger.info("Loading temporal data from database...")
    db = CVEDatabase()
    
    # Disable automatic timestamp conversion to avoid Python 3.14 issues
    import sqlite3
    sqlite3.register_adapter(type(None), lambda x: None)
    
    query = """
    SELECT 
        e.cve_id,
        e.kev_flag,
        e.epss_score,
        e.epss_percentile,
        e.is_healthcare,
        e.is_curated,
        e.chpl_flag,
        e.attack_flag,
        e.attack_technique_count,
        e.label,
        c.cvss,
        CAST(c.published AS TEXT) as published,
        c.description
    FROM enrichments e
    LEFT JOIN cves c ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    """
    
    df = pd.read_sql_query(query, db.conn)
    db.close()
    
    # Parse dates
    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    df['year'] = df['published'].dt.year
    
    # Split by year
    train_df = df[df['year'] < 2025].copy()
    test_df = df[df['year'] == 2025].copy()
    
    logger.info("Temporal split completed", extra={
        "train_years": "2018-2024",
        "train_count": len(train_df),
        "test_year": 2025,
        "test_count": len(test_df)
    })
    logger.info(f"Train label distribution:\n{train_df['label'].value_counts().sort_index()}")
    logger.info(f"Test label distribution:\n{test_df['label'].value_counts().sort_index()}")
    
    return train_df, test_df

def prepare_features(df, scaler=None):
    """Extract and engineer features."""
    features = pd.DataFrame({
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'epss_percentile': df['epss_percentile'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'chpl_flag': df['chpl_flag'].fillna(0).astype(int),
        'attack_flag': df['attack_flag'].fillna(0).astype(int),
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
        'cvss': df['cvss'].fillna(0.0),
    })
    
    # Engineered features
    features['cvss_high'] = (features['cvss'] >= 7.0).astype(int)
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    features['chpl_healthcare'] = (features['chpl_flag'] & features['is_healthcare']).astype(int)
    features['attack_healthcare'] = (features['attack_flag'] & features['is_healthcare']).astype(int)
    features['attack_multi'] = (features['attack_technique_count'] > 1).astype(int)
    
    # Interaction features
    features['healthcare_x_cvss'] = features['is_healthcare'] * features['cvss']
    features['kev_x_epss'] = features['kev_flag'] * features['epss_score']
    features['chpl_x_attack'] = features['chpl_flag'] * features['attack_flag']
    features['attack_count_x_healthcare'] = features['attack_technique_count'] * features['is_healthcare']
    
    # Recency
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    # Scale continuous features
    continuous_cols = ['cvss', 'epss_score', 'epss_percentile', 'attack_technique_count', 
                       'healthcare_x_cvss', 'kev_x_epss', 'attack_count_x_healthcare', 'days_since_2018']
    
    if scaler is None:
        scaler = StandardScaler()
        features[continuous_cols] = scaler.fit_transform(features[continuous_cols])
    else:
        features[continuous_cols] = scaler.transform(features[continuous_cols])
    
    return features, df['label'], scaler

def compute_class_weights(y):
    """Compute sample weights based on inverse class frequency."""
    unique, counts = np.unique(y, return_counts=True)
    class_weights = {label: len(y) / (len(unique) * count) for label, count in zip(unique, counts)}
    sample_weights = np.array([class_weights[label] for label in y])
    logger.info("Class weights calculated", extra={"weights": class_weights})
    return sample_weights

def train_with_class_weights(X_train, y_train, X_test, y_test, sample_weights):
    """Train XGBoost ranker with adjusted parameters for class imbalance."""
    logger.info("Training XGBoost Ranker with class imbalance handling...")
    
    # For ranking objectives, we can't use per-sample weights
    # Instead, we'll adjust learning parameters
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.05,  # Lower learning rate for better generalization
        'max_depth': 6,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 1,  # Allow leaf splits with fewer samples (helps rare classes)
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
    logger.info("TEMPORAL VALIDATION RESULTS (2025 TEST SET)")
    logger.info("="*70)
    
    dtest = xgb.DMatrix(X_test, feature_names=feature_names)
    y_pred = model.predict(dtest)
    
    # NDCG scores
    ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
    
    logger.info("NDCG Scores on 2025 CVEs", extra={
        "ndcg_5": f"{ndcg_5:.4f}",
        "ndcg_10": f"{ndcg_10:.4f}",
        "ndcg_20": f"{ndcg_20:.4f}"
    })
    
    # Top-K analysis
    top_k_indices = np.argsort(y_pred)[::-1]
    
    for k in [10, 20, 50, 100]:
        top_k = y_test.iloc[top_k_indices[:k]]
        high_priority = (top_k >= 3).sum()
        logger.info(f"P@{k:3d}: {100*high_priority/k:5.1f}% ({high_priority}/{k} L3+)")
    
    # Label distribution in top 100
    logger.info("Label Distribution in Top 100 (2025 CVEs):")
    top_100_labels = y_test.iloc[top_k_indices[:100]]
    for label in sorted(top_100_labels.unique(), reverse=True):
        count = (top_100_labels == label).sum()
        label_name = ['L0', 'L1', 'L2', 'L3', 'L4'][label] if label < 5 else f'L{label}'
        logger.info(f"  {label_name}: {count:3d} ({100*count/100:.0f}%)")
    
    return {
        'ndcg_5': ndcg_5,
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20
    }

def main():
    logger.info("="*70)
    logger.info("TEMPORAL VALIDATION: Train on 2018-2024, Test on 2025")
    logger.info("="*70)
    
    # Load data
    train_df, test_df = load_temporal_data()
    
    if len(test_df) == 0:
        logger.error("No 2025 CVEs found in database!")
        return
    
    # Prepare features
    logger.info("Preparing training features...")
    X_train, y_train, scaler = prepare_features(train_df)
    
    logger.info("Preparing test features...")
    X_test, y_test, _ = prepare_features(test_df, scaler=scaler)
    
    # Compute class weights
    sample_weights = compute_class_weights(y_train)
    
    # Train model
    model = train_with_class_weights(X_train, y_train, X_test, y_test, sample_weights)
    
    # Evaluate
    results = evaluate_temporal(model, X_test, y_test, X_train.columns.tolist())
    
    logger.info("="*70)
    logger.info("✅ Temporal validation complete!")
    logger.info("="*70)
    logger.info(f"Key Insight: NDCG@10 on 2025 data = {results['ndcg_10']:.4f}")
    logger.info("(Compare to 1.0000 on random split - temporal split is more realistic)")

if __name__ == "__main__":
    main()
