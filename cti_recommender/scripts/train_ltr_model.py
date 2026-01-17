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
from sklearn.preprocessing import StandardScaler
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
        e.chpl_flag,
        e.attack_flag,
        e.attack_technique_count,
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
    
    # Recency (days since 2018-01-01)
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)  # ~7 years
    
    # Apply feature scaling to continuous variables
    continuous_cols = ['cvss', 'epss_score', 'epss_percentile', 'attack_technique_count', 
                       'healthcare_x_cvss', 'kev_x_epss', 'attack_count_x_healthcare', 'days_since_2018']
    
    scaler = StandardScaler()
    features[continuous_cols] = scaler.fit_transform(features[continuous_cols])
    
    print(f"Created {len(features.columns)} features:")
    print(f"  - {list(features.columns)}")
    print(f"Applied StandardScaler to {len(continuous_cols)} continuous features")
    
    return features, df['label'], scaler

def compute_class_weights(y):
    """Compute sample weights for class imbalance."""
    unique, counts = np.unique(y, return_counts=True)
    class_weights = {label: len(y) / (len(unique) * count) for label, count in zip(unique, counts)}
    sample_weights = np.array([class_weights[label] for label in y])
    
    print("\nClass weights (handling imbalance):")
    for label, weight in sorted(class_weights.items(), reverse=True):
        label_name = ['L0', 'L1', 'L2', 'L3', 'L4'][label] if label < 5 else f'L{label}'
        print(f"  {label_name}: {weight:.4f}")
    
    return sample_weights

def train_model(X_train, y_train, X_test, y_test):
    """Train XGBoost ranker model with adjustments for class imbalance."""
    print("\nTraining XGBoost Ranker (with class imbalance handling)...")
    
    # Compute class weights for information only
    compute_class_weights(y_train)
    
    # For ranking objectives, adjust hyperparameters instead of using sample weights
    # Create DMatrix for XGBoost
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    # Model parameters (adjusted for class imbalance)
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.05,  # Lower learning rate
        'max_depth': 6,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'min_child_weight': 1,  # Allow splits with fewer samples (helps rare classes)
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

def save_model(model, feature_names, metrics, scaler):
    """Save trained model and metadata."""
    output_dir = Path(__file__).parent.parent / 'models'
    output_dir.mkdir(exist_ok=True)
    
    model_path = output_dir / 'ltr_ranker.model'
    metadata_path = output_dir / 'ltr_metadata.pkl'
    
    # Save XGBoost model
    model.save_model(str(model_path))
    print(f"\nModel saved: {model_path}")
    
    # Save metadata including scaler
    metadata = {
        'feature_names': feature_names,
        'metrics': metrics,
        'scaler': scaler,
        'training_date': datetime.now().isoformat(),
        'model_type': 'xgboost_ranker'
    }
    with open(metadata_path, 'wb') as f:
        pickle.dump(metadata, f)
    print(f"Metadata saved: {metadata_path}")
    print(f"Scaler saved in metadata for inference")

def main():
    print("="*70)
    print("LTR MODEL TRAINING PIPELINE")
    print("="*70)
    
    # Load data
    df = load_training_data()
    
    # Prepare features and labels
    X, y, scaler = prepare_features(df)
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
    
    # Save model with scaler
    save_model(model, feature_names, metrics, scaler)
    
    print("\n" + "="*70)
    print("✅ Training complete!")
    print("="*70)

if __name__ == "__main__":
    main()
