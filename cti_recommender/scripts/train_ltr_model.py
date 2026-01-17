#!/usr/bin/env python3
"""
Learning to Rank (LTR) model training pipeline for healthcare CVE prioritization.
Uses enriched data from database - no API calls needed.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import ndcg_score, precision_score, recall_score
import xgboost as xgb
import pickle
from datetime import datetime

from src.core.cve_database import CVEDatabase

def load_training_data():
    """Load enriched CVE data from database."""
    print("Loading training data from database...")
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
        e.label,
        c.cvss,
        CAST(c.published AS TEXT) as published_str,
        c.description
    FROM enrichments e
    LEFT JOIN cves c ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    """
    
    df = pd.read_sql_query(query, db.conn)
    db.close()
    
    print(f"Loaded {len(df):,} CVEs with complete data")
    return df

def prepare_features(df):
    """Extract and engineer features for LTR model."""
    print("\nPreparing features...")
    
    # Basic features
    features = pd.DataFrame({
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'epss_percentile': df['epss_percentile'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'cvss': df['cvss'].fillna(0.0),
    })
    
    # Engineered features
    features['cvss_high'] = (features['cvss'] >= 7.0).astype(int)
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    
    # Interaction features
    features['healthcare_x_cvss'] = features['is_healthcare'] * features['cvss']
    features['kev_x_epss'] = features['kev_flag'] * features['epss_score']
    
    # Recency (days since 2018-01-01)
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)  # ~7 years
    
    print(f"Created {len(features.columns)} features:")
    print(f"  - {list(features.columns)}")
    
    return features, df['label']

def train_model(X_train, y_train, X_test, y_test):
    """Train XGBoost ranker model."""
    print("\nTraining XGBoost Ranker...")
    
    # Create DMatrix for XGBoost
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    # Model parameters
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.1,
        'max_depth': 6,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'seed': 42
    }
    
    # Train model
    evals = [(dtrain, 'train'), (dtest, 'test')]
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=100,
        evals=evals,
        early_stopping_rounds=10,
        verbose_eval=10
    )
    
    print("\nFeature Importance:")
    importance = model.get_score(importance_type='gain')
    for feat, score in sorted(importance.items(), key=lambda x: x[1], reverse=True):
        print(f"  {feat}: {score:.2f}")
    
    return model

def evaluate_model(model, X_test, y_test, feature_names):
    """Evaluate model performance."""
    print("\n" + "="*70)
    print("MODEL EVALUATION")
    print("="*70)
    
    # Make predictions
    dtest = xgb.DMatrix(X_test, feature_names=feature_names)
    y_pred = model.predict(dtest)
    
    # NDCG scores
    ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
    
    print(f"\nNDCG Scores:")
    print(f"  NDCG@5:  {ndcg_5:.4f}")
    print(f"  NDCG@10: {ndcg_10:.4f}")
    print(f"  NDCG@20: {ndcg_20:.4f}")
    
    # Top-K precision (L3+ CVEs in top K predictions)
    top_k = [10, 20, 50, 100]
    print(f"\nPrecision at K (L3+ CVEs):")
    for k in top_k:
        top_k_idx = np.argsort(y_pred)[-k:]
        high_priority_in_top_k = (y_test.iloc[top_k_idx] >= 3).sum()
        precision_k = high_priority_in_top_k / k
        print(f"  P@{k:3d}: {precision_k:.2%} ({high_priority_in_top_k}/{k} high-priority)")
    
    # Label distribution in top predictions
    print(f"\nLabel Distribution in Top 100:")
    top_100_idx = np.argsort(y_pred)[-100:]
    top_100_labels = y_test.iloc[top_100_idx]
    for label in [3, 2, 1, 0]:
        count = (top_100_labels == label).sum()
        print(f"  L{label}: {count:2d} ({100*count/100:.0f}%)")
    
    return {
        'ndcg_5': ndcg_5,
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20,
        'y_pred': y_pred
    }

def save_model(model, feature_names, metrics):
    """Save trained model and metadata."""
    output_dir = Path(__file__).parent.parent / 'models'
    output_dir.mkdir(exist_ok=True)
    
    model_path = output_dir / 'ltr_ranker.model'
    metadata_path = output_dir / 'ltr_metadata.pkl'
    
    # Save XGBoost model
    model.save_model(str(model_path))
    print(f"\nModel saved: {model_path}")
    
    # Save metadata
    metadata = {
        'feature_names': feature_names,
        'metrics': metrics,
        'training_date': datetime.now().isoformat(),
        'model_type': 'xgboost_ranker'
    }
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)
    print(f"Metadata saved: {metadata_path}")

def main():
    print("="*70)
    print("LTR MODEL TRAINING PIPELINE")
    print("="*70)
    
    # Load data
    df = load_training_data()
    
    # Prepare features and labels
    X, y = prepare_features(df)
    feature_names = list(X.columns)
    
    print(f"\nLabel distribution:")
    for label in sorted(y.unique(), reverse=True):
        count = (y == label).sum()
        pct = 100 * count / len(y)
        print(f"  L{label}: {count:,} ({pct:.1f}%)")
    
    # Train/test split (80/20)
    print(f"\nSplitting data (80% train, 20% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train):,} samples")
    print(f"Test:  {len(X_test):,} samples")
    
    # Train model
    model = train_model(X_train, y_train, X_test, y_test)
    
    # Evaluate
    metrics = evaluate_model(model, X_test, y_test, feature_names)
    
    # Save model
    save_model(model, feature_names, metrics)
    
    print("\n" + "="*70)
    print("✅ Training complete!")
    print("="*70)

if __name__ == "__main__":
    main()
