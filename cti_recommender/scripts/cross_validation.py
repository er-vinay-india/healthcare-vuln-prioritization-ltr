#!/usr/bin/env python3
"""
5-Fold Cross-Validation for LTR model.
Reports mean NDCG ± standard deviation for robust performance estimates.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import KFold
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

def load_data():
    """Load enriched CVE data."""
    logger.info("Loading data from database...")
    db = CVEDatabase()
    
    # Disable automatic timestamp conversion
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
    
    try:
        df = pd.read_sql_query(query, db.conn)
    except Exception:
        logger.exception("Failed to load enriched CVE data from database")
        raise
    finally:
        db.close()

    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    logger.info(f"Loaded {len(df):,} CVEs", extra={'cve_count': len(df)})
    return df

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
    """Compute sample weights for class imbalance."""
    unique, counts = np.unique(y, return_counts=True)
    class_weights = {label: len(y) / (len(unique) * count) for label, count in zip(unique, counts)}
    sample_weights = np.array([class_weights[label] for label in y])
    return sample_weights

def train_fold(X_train, y_train, X_val, y_val, sample_weights):
    """Train model on one fold."""
    # For ranking objectives, we adjust hyperparameters instead of using sample weights
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dval = xgb.DMatrix(X_val, label=y_val)
    
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.05,  # Lower learning rate
        'max_depth': 6,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 1,  # Helps with rare classes
        'seed': 42
    }
    
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=100,
        evals=[(dval, 'val')],
        early_stopping_rounds=10,
        verbose_eval=False
    )
    
    return model

def evaluate_fold(model, X_val, y_val):
    """Evaluate model on validation fold."""
    dval = xgb.DMatrix(X_val)
    y_pred = model.predict(dval)
    
    ndcg_5 = ndcg_score([y_val], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_val], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_val], [y_pred], k=20)
    
    # Top-K precision
    top_k_indices = np.argsort(y_pred)[::-1]
    top_20 = y_val.iloc[top_k_indices[:20]]
    p_20 = (top_20 >= 3).sum() / 20
    
    return {
        'ndcg_5': ndcg_5,
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20,
        'p_20': p_20
    }

def main() -> int:
    logger.info("="*70)
    logger.info("5-FOLD CROSS-VALIDATION")
    logger.info("="*70)

    try:
        # Load data
        df = load_data()

        # Prepare all features once
        logger.info("Preparing features...")
        X, y, _ = prepare_features(df)

        logger.info("Label distribution:")
        label_counts = y.value_counts().sort_index()
        for label, count in label_counts.items():
            logger.info(f"  Label {label}: {count}")

        # 5-fold cross-validation
        kfold = KFold(n_splits=5, shuffle=True, random_state=42)

        fold_results = []

        logger.info("="*70)
        logger.info("Training 5 folds...")
        logger.info("="*70)

        for fold_idx, (train_idx, val_idx) in enumerate(kfold.split(X), 1):
            logger.info(f"Fold {fold_idx}/5:")

            X_train, X_val = X.iloc[train_idx].copy(), X.iloc[val_idx].copy()
            y_train, y_val = y.iloc[train_idx], y.iloc[val_idx]

            # Scale within fold
            scaler = StandardScaler()
            continuous_cols = ['cvss', 'epss_score', 'epss_percentile', 'attack_technique_count',
                               'healthcare_x_cvss', 'kev_x_epss', 'attack_count_x_healthcare', 'days_since_2018']
            X_train[continuous_cols] = scaler.fit_transform(X_train[continuous_cols])
            X_val[continuous_cols] = scaler.transform(X_val[continuous_cols])

            # Compute sample weights
            sample_weights = compute_class_weights(y_train)

            # Train
            model = train_fold(X_train, y_train, X_val, y_val, sample_weights)

            # Evaluate
            results = evaluate_fold(model, X_val, y_val)
            fold_results.append(results)

            logger.info(f"  NDCG@10: {results['ndcg_10']:.4f}  P@20: {results['p_20']*100:.1f}%",
                       extra={'fold': fold_idx, 'ndcg_10': results['ndcg_10'], 'p_20': results['p_20']})

        # Aggregate results
        logger.info("="*70)
        logger.info("CROSS-VALIDATION RESULTS")
        logger.info("="*70)

        results_df = pd.DataFrame(fold_results)

        logger.info(f"NDCG@5:  {results_df['ndcg_5'].mean():.4f} ± {results_df['ndcg_5'].std():.4f}")
        logger.info(f"NDCG@10: {results_df['ndcg_10'].mean():.4f} ± {results_df['ndcg_10'].std():.4f}")
        logger.info(f"NDCG@20: {results_df['ndcg_20'].mean():.4f} ± {results_df['ndcg_20'].std():.4f}")
        logger.info(f"P@20:    {results_df['p_20'].mean()*100:.1f}% ± {results_df['p_20'].std()*100:.1f}%")

        logger.info("Per-fold breakdown:")
        for fold_idx, row in results_df.iterrows():
            logger.info(f"  Fold {fold_idx+1}: NDCG@10={row['ndcg_10']:.4f}, P@20={row['p_20']*100:.1f}%")

        # Save results
        output_path = Path(__file__).parent.parent / 'outputs' / 'cv_results.csv'
        try:
            results_df.to_csv(output_path, index=False)
            logger.info(f"Results saved: {output_path}")
        except Exception:
            logger.exception("Failed to save CV results to %s", output_path)
            return 1

        logger.info("="*70)
        logger.info("[OK] Cross-validation complete!")
        logger.info("="*70)
        return 0

    except Exception:
        logger.exception("Cross-validation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
