#!/usr/bin/env python3
"""
Optimized LTR Model Training with Pruned Features
Removes 9 redundant/zero-variance features identified in correlation analysis.
Adds stronger regularization to prevent overfitting.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import ndcg_score
from sklearn.preprocessing import StandardScaler
import xgboost as xgb
import pickle
from datetime import datetime

from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def load_training_data():
    """Load enriched CVE data from database."""
    logger.info("Loading training data from database...")
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
        CAST(c.published AS TEXT) as published_str,
        c.description
    FROM enrichments e
    LEFT JOIN cves c ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    """
    
    try:
        df = pd.read_sql_query(query, db.conn)
    except Exception:
        logger.exception("Failed to load training data from database")
        raise
    finally:
        db.close()

    logger.info(f"Loaded {len(df):,} CVEs with complete data", extra={'cve_count': len(df)})
    return df

def prepare_pruned_features(df):
    """
    Extract ONLY useful features (removed 9 redundant features).
    
    REMOVED (redundant/zero-variance):
    - epss_percentile (r=1.0 with epss_score)
    - kev_x_epss (r=1.0 with kev_flag)
    - healthcare_x_cvss (r=0.91 with is_healthcare)
    - cvss_high (r=0.87 with cvss)
    - chpl_flag (zero variance)
    - chpl_healthcare (zero variance)
    - chpl_x_attack (zero variance)
    - attack_flag (zero variance)
    - attack_healthcare (zero variance)
    
    KEPT (14 useful features):
    - Core: kev_flag, epss_score, is_healthcare, is_curated, cvss
    - Engineered: cvss_critical, epss_high, healthcare_critical, kev_healthcare, attack_multi
    - Interaction: attack_count_x_healthcare
    - Temporal: days_since_2018, is_recent, attack_technique_count
    """
    logger.info("Preparing PRUNED feature set (14 features)...")
    
    # Basic features (kept)
    features = pd.DataFrame({
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
        'cvss': df['cvss'].fillna(0.0),
    })
    
    # Engineered features (kept useful ones)
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    features['attack_multi'] = (features['attack_technique_count'] > 1).astype(int)
    
    # Interaction feature (kept)
    features['attack_count_x_healthcare'] = features['attack_technique_count'] * features['is_healthcare']
    
    # Recency features
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    # Apply feature scaling to continuous variables
    continuous_cols = ['cvss', 'epss_score', 'attack_technique_count', 
                       'attack_count_x_healthcare', 'days_since_2018']
    
    scaler = StandardScaler()
    features[continuous_cols] = scaler.fit_transform(features[continuous_cols])
    
    logger.info(f"Created {len(features.columns)} features (down from 23)", extra={'feature_count': len(features.columns)})
    for i, col in enumerate(features.columns, 1):
        logger.info(f"  {i:2d}. {col}")
    logger.info(f"Applied StandardScaler to {len(continuous_cols)} continuous features", extra={'scaled_features': len(continuous_cols)})
    
    return features, df['label'], scaler

def train_model_with_regularization(X_train, y_train, X_test, y_test):
    """
    Train XGBoost ranker with STRONGER REGULARIZATION to prevent overfitting.
    
    Changes from previous model:
    - min_child_weight: 1 -> 5 (require more samples per leaf)
    - max_depth: 6 -> 5 (shallower trees)
    - alpha: 0 -> 0.1 (L1 regularization)
    - lambda: 1 -> 2 (L2 regularization)
    - eta: 0.05 (kept low for stability)
    """
    logger.info("Training XGBoost Ranker with STRONG REGULARIZATION...")
    
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.05,              # Learning rate (kept low)
        'max_depth': 5,           # Reduced from 6 (shallower trees)
        'min_child_weight': 5,    # Increased from 1 (require more samples)
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'alpha': 0.1,             # L1 regularization (NEW)
        'lambda': 2.0,            # L2 regularization (increased from 1)
        'seed': 42
    }
    
    logger.info("Regularization settings:")
    logger.info(f"  min_child_weight: {params['min_child_weight']} (require {params['min_child_weight']} samples per leaf)")
    logger.info(f"  max_depth: {params['max_depth']} (shallower trees)")
    logger.info(f"  L1 (alpha): {params['alpha']}")
    logger.info(f"  L2 (lambda): {params['lambda']}")
    
    evals = [(dtrain, 'train'), (dtest, 'test')]
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=100,
        evals=evals,
        early_stopping_rounds=10,
        verbose_eval=10
    )
    
    logger.info("Feature Importance (pruned model):")
    importance = model.get_score(importance_type='gain')
    for feat, score in sorted(importance.items(), key=lambda x: x[1], reverse=True):
        logger.info(f"  {feat}: {score:.2f}")
    
    return model

def evaluate_model(model, X_test, y_test, feature_names):
    """Evaluate model performance."""
    logger.info("="*70)
    logger.info("PRUNED MODEL EVALUATION")
    logger.info("="*70)
    
    dtest = xgb.DMatrix(X_test, feature_names=feature_names)
    y_pred = model.predict(dtest)
    
    # NDCG scores
    ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
    
    logger.info("NDCG Scores:", extra={'ndcg_5': ndcg_5, 'ndcg_10': ndcg_10, 'ndcg_20': ndcg_20})
    logger.info(f"  NDCG@5:  {ndcg_5:.4f}")
    logger.info(f"  NDCG@10: {ndcg_10:.4f}")
    logger.info(f"  NDCG@20: {ndcg_20:.4f}")
    
    # Top-K precision
    top_k_indices = np.argsort(y_pred)[::-1]
    
    logger.info("Precision at K (L3+ CVEs):")
    for k in [10, 20, 50, 100]:
        top_k = y_test.iloc[top_k_indices[:k]]
        high_priority = (top_k >= 3).sum()
        logger.info(f"  P@{k:3d}: {100*high_priority/k:5.1f}% ({high_priority}/{k} high-priority)")

    # Label distribution in top 100
    logger.info("Label Distribution in Top 100:")
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

def main() -> int:
    logger.info("="*70)
    logger.info("OPTIMIZED LTR MODEL TRAINING")
    logger.info("Features: 14 (pruned from 23)")
    logger.info("Regularization: STRONG (min_child_weight=5, max_depth=5, L1/L2)")
    logger.info("="*70)

    try:
        # Load data
        df = load_training_data()

        # Prepare pruned features
        X, y, scaler = prepare_pruned_features(df)

        # Label distribution
        logger.info("Label distribution:")
        for label in sorted(y.unique(), reverse=True):
            count = (y == label).sum()
            pct = 100 * count / len(y)
            label_name = ['L0', 'L1', 'L2', 'L3', 'L4'][label] if label < 5 else f'L{label}'
            logger.info(f"  {label_name}: {count:>6,} ({pct:>4.1f}%)")

        # Split data
        logger.info("Splitting data (80% train, 20% test)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        logger.info(f"Train: {len(X_train):>6,} samples")
        logger.info(f"Test:  {len(X_test):>6,} samples")

        # Train model
        model = train_model_with_regularization(X_train, y_train, X_test, y_test)

        # Evaluate
        metrics = evaluate_model(model, X_test, y_test, X.columns.tolist())

        # Save model
        model_dir = Path(__file__).parent.parent / 'models'
        model_dir.mkdir(exist_ok=True)

        model_path = model_dir / 'ltr_ranker_pruned.model'
        metadata_path = model_dir / 'ltr_metadata_pruned.pkl'

        try:
            model.save_model(str(model_path))
            logger.info(f"Pruned model saved: {model_path}")
        except Exception:
            logger.exception("Failed to save model to %s", model_path)
            return 1

        metadata = {
            'training_date': datetime.now().isoformat(),
            'feature_names': X.columns.tolist(),
            'n_features': len(X.columns),
            'n_train': len(X_train),
            'n_test': len(X_test),
            'scaler': scaler,
            'metrics': metrics,
            'hyperparameters': {
                'eta': 0.05,
                'max_depth': 5,
                'min_child_weight': 5,
                'alpha': 0.1,
                'lambda': 2.0
            },
            'removed_features': [
                'epss_percentile', 'kev_x_epss', 'healthcare_x_cvss', 'cvss_high',
                'chpl_flag', 'chpl_healthcare', 'chpl_x_attack', 'attack_flag', 'attack_healthcare'
            ]
        }

        try:
            with open(metadata_path, 'wb') as f:
                pickle.dump(metadata, f)
            logger.info(f"Metadata saved: {metadata_path}")
        except Exception:
            logger.exception("Failed to save metadata to %s", metadata_path)
            return 1

        logger.info("="*70)
        logger.info("[OK] Training complete!")
        logger.info("="*70)
        logger.info(f"Model summary: {len(X.columns)} features, NDCG@10={metrics['ndcg_10']:.4f}")
        return 0

    except Exception:
        logger.exception("Training failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
