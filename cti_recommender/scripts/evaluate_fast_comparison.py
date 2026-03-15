#!/usr/bin/env python3
"""
Fast Production Model Comparison (Simplified)

Quickly compares OLD vs NEW features using simple KEV labels.
Optimized for speed - completes in <2 minutes.

Author: AI-Enhanced Evaluation
Date: 2026-03-03
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from src.core.cve_database import CVEDatabase
from src.features.temporal_labeling import extract_temporal_features as extract_old_features, get_temporal_feature_columns as get_old_features
from src.features.production_features import ProductionFeatureEngineer
from src.models.ltr import prepare_ranking_data
from src.evaluation.metrics import ndcg_at_k, precision_at_k

import lightgbm as lgb


def load_data():
    """Load recent CVE data."""
    print("=" * 80)
    print("FAST PRODUCTION EVALUATION - OLD vs NEW Features")
    print("=" * 80)
    
    db = CVEDatabase()
    
    query = """
    SELECT 
        c.cve_id,
        CAST(c.published AS TEXT) as published,
        c.cvss,
        c.description,
        c.cwe,
        e.kev_flag,
        e.is_healthcare,
        e.attack_technique_count,
        e.chpl_flag
    FROM cves c
    LEFT JOIN enrichments e ON c.cve_id = e.cve_id
    WHERE c.cvss IS NOT NULL
        AND c.published >= '2024-06-01'
        AND c.published < '2025-01-01'
    ORDER BY c.published
    """
    
    df = pd.read_sql_query(query, db.conn)
    db.close()
    
    df['published'] = pd.to_datetime(df['published'])
    df['cvss'] = pd.to_numeric(df['cvss'], errors='coerce')
    df['kev_flag'] = pd.to_numeric(df['kev_flag'], errors='coerce').fillna(0).astype(int)
    df['is_healthcare'] = pd.to_numeric(df['is_healthcare'], errors='coerce').fillna(0).astype(int)
    df['chpl_flag'] = pd.to_numeric(df['chpl_flag'], errors='coerce').fillna(0).astype(int)
    df['attack_technique_count'] = pd.to_numeric(df['attack_technique_count'], errors='coerce').fillna(0).astype(int)
    
    print(f"✓ Loaded {len(df):,} CVEs (Jun-Dec 2024)")
    print(f"  KEV CVEs: {df['kev_flag'].sum()}")
    
    return df


def create_splits(df):
    """Create train/val/test splits by date."""
    train_df = df[df['published'] < '2024-09-01'].copy()
    val_df = df[(df['published'] >= '2024-09-01') & (df['published'] < '2024-10-01')].copy()
    test_df = df[df['published'] >= '2024-10-01'].copy()
    
    print(f"\n✓ Splits:")
    print(f"  Train:      {len(train_df):,} ({train_df['kev_flag'].sum()} KEV)")
    print(f"  Validation: {len(val_df):,} ({val_df['kev_flag'].sum()} KEV)")
    print(f"  Test:       {len(test_df):,} ({test_df['kev_flag'].sum()} KEV)")
    
    return train_df, val_df, test_df


def train_fast(train_df, val_df, feature_cols, label_col='kev_flag'):
    """Train LambdaRank quickly."""
    # Create query groups by month
    train_df['query_id'] = train_df['published'].dt.to_period('M').astype(str)
    val_df['query_id'] = val_df['published'].dt.to_period('M').astype(str)
    
    X_train = train_df[feature_cols].fillna(0)
    y_train = train_df[label_col]
    q_train = train_df.groupby('query_id').size().values
    
    X_val = val_df[feature_cols].fillna(0)
    y_val = val_df[label_col]
    q_val = val_df.groupby('query_id').size().values
    
    train_data = lgb.Dataset(X_train,label=y_train, group=q_train)
    val_data = lgb.Dataset(X_val, label=y_val, group=q_val, reference=train_data)
    
    params = {
        'objective': 'lambdarank',
        'metric': 'ndcg',
        'ndcg_eval_at': [5, 10, 20],
        'learning_rate': 0.05,
        'num_leaves': 15,
        'max_depth': 4,
        'verbose': -1,
        'seed': 42
    }
    
    model = lgb.train(
        params,
        train_data,
        num_boost_round=50,
        valid_sets=[val_data],
        valid_names=['val']
    )
    
    return model


def evaluate(model, test_df, feature_cols, label_col='kev_flag'):
    """Evaluate model."""
    y_true = test_df[label_col].values
    y_pred = model.predict(test_df[feature_cols].fillna(0))
    
    results = {}
    for k in [5, 10, 20]:
        results[f'NDCG@{k}'] = ndcg_at_k(y_true, y_pred, k)
        results[f'P@{k}'] = precision_at_k(y_true, y_pred, k, threshold=0.5)
    
    # KEV capture
    top_20_idx = np.argsort(y_pred)[::-1][:20]
    results['KEV_top20'] = y_true[top_20_idx].sum()
    results['KEV_total'] = y_true.sum()
    
    return results, y_pred


def print_comparison(old_results, new_results):
    """Print comparison table."""
    print("\n" + "=" * 80)
    print("RESULTS COMPARISON")
    print("=" * 80)
    
    print(f"\n{'Metric':<15} {'OLD':<15} {'NEW':<15} {'Improvement':<15}")
    print("-" * 65)
    
    for metric in ['NDCG@10', 'NDCG@20', 'P@10', 'P@20', 'KEV_top20']:
        old_val = old_results[metric]
        new_val = new_results[metric]
        
        if metric == 'KEV_top20':
            print(f"{metric:<15} {old_val:<15.0f} {new_val:<15.0f} {'+' + str(int(new_val - old_val)):<15}")
        else:
            imp_pct = ((new_val / old_val - 1) * 100) if old_val > 0 else 0
            print(f"{metric:<15} {old_val:<15.4f} {new_val:<15.4f} {f'+{imp_pct:.1f}%':<15}")
    
    print("-" * 65)
    print(f"Total KEV: {old_results['KEV_total']}\n")


def main():
    """Main evaluation."""
    
    # Load and split
    df = load_data()
    train_df, val_df, test_df = create_splits(df)
    
    # === OLD FEATURES (13) ===
    print("\n" + "=" * 80)
    print("EXTRACTING OLD FEATURES (13)")
    print("=" * 80)
    
    train_old = extract_old_features(train_df)
    val_old = extract_old_features(val_df)
    test_old = extract_old_features(test_df)
    old_features = get_old_features()
    
    print(f"✓ Extracted {len(old_features)} OLD features")
    
    print(f"\n → Training OLD model...")
    model_old = train_fast(train_old, val_old, old_features)
    
    print(f" → Evaluating OLD model...")
    old_results, _ = evaluate(model_old, test_old, old_features)
    
    # === NEW FEATURES ===
    print("\n" + "=" * 80)
    print("EXTRACTING NEW FEATURES")
    print("=" * 80)
    
    # Use train data for historical risk scores
    historical = train_df[train_df['kev_flag'].notna()].copy()
    engineer = ProductionFeatureEngineer(historical_data=historical)
    
    print("Extracting features (optimized)...")
    train_new = engineer.extract_features(train_df)
    val_new = engineer.extract_features(val_df)
    test_new = engineer.extract_features(test_df)
    new_features = engineer.get_feature_columns()
    
    print(f"✓ Extracted {len(new_features)} NEW features")
    
    # Show feature groups
    groups = engineer.get_feature_importance_groups()
    print(f"\nFeature groups:")
    for group_name, group_feats in groups.items():
        print(f"  • {group_name}: {len(group_feats)} features")
    
    print(f"\n → Training NEW model...")
    model_new = train_fast(train_new, val_new, new_features)
    
    print(f" → Evaluating NEW model...")
    new_results, _ = evaluate(model_new, test_new, new_features)
    
    # === COMPARISON ===
    print_comparison(old_results, new_results)
    
    # === SAVE ===
    output_dir = Path(__file__).parent.parent / 'outputs'
    output_dir.mkdir(exist_ok=True)
    
    comparison_df = pd.DataFrame({
        'OLD_13_features': old_results,
        'NEW_28_features': new_results
    }).T
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f'fast_comparison_{timestamp}.csv'
    comparison_df.to_csv(output_path)
    
    print(f"✓ Results saved: {output_path}")
    
    # === SUMMARY ===
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    improvement = (new_results['NDCG@20'] / old_results['NDCG@20'] - 1) * 100 if old_results['NDCG@20'] > 0 else 0
    
    print(f"\nOLD Model (13 basic features):")
    print(f"  NDCG@20 = {old_results['NDCG@20']:.4f}")
    print(f"  KEV captured (top 20) = {old_results['KEV_top20']:.0f}/{old_results['KEV_total']:.0f}")
    
    print(f"\nNEW Model ({len(new_features)} enriched features):")
    print(f"  NDCG@20 = {new_results['NDCG@20']:.4f}")
    print(f"  KEV captured (top 20) = {new_results['KEV_top20']:.0f}/{new_results['KEV_total']:.0f}")
    
    print(f"\n→ IMPROVEMENT: {improvement:.1f}% increase in NDCG@20")
    print(f"→ Additional KEV CVEs captured: +{int(new_results['KEV_top20'] - old_results['KEV_top20'])}")
    print()


if __name__ == "__main__":
    main()
