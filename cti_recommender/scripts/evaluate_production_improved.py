#!/usr/bin/env python3
"""
Improved Production Model Evaluation

Compares OLD vs NEW feature engineering approaches:
- OLD: 13 basic features (current production)
- NEW: 28+ enriched features (CWE, vendor, NLP, historical)

Author: AI-Enhanced Evaluation
Date: 2026-03-03
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import json
import warnings
warnings.filterwarnings('ignore')

# Local imports
from src.core.cve_database import CVEDatabase
from src.features.temporal_labeling import (
    build_temporal_labels,
    extract_temporal_features as extract_old_features,
    get_temporal_feature_columns as get_old_feature_columns,
)
from src.features.production_features import ProductionFeatureEngineer
from src.models.ltr import prepare_ranking_data, train_lambdarank
from src.evaluation.metrics import ndcg_at_k, precision_at_k

import lightgbm as lgb


def load_data_from_db() -> pd.DataFrame:
    """Load CVE data from database."""
    print("=" * 80)
    print("IMPROVED PRODUCTION EVALUATION - OLD vs NEW Features")
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
        e.epss_score,
        e.is_healthcare,
        e.attack_technique_count,
        e.chpl_flag
    FROM cves c
    LEFT JOIN enrichments e ON c.cve_id = e.cve_id
    WHERE c.cvss IS NOT NULL
        AND c.published >= '2024-01-01'
    ORDER BY c.published DESC
    """
    
    df = pd.read_sql_query(query, db.conn)
    db.close()
    
    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    df['cvss'] = pd.to_numeric(df['cvss'], errors='coerce')
    df['attack_technique_count'] = pd.to_numeric(df['attack_technique_count'], errors='coerce').fillna(0).astype(int)
    df['is_healthcare'] = pd.to_numeric(df['is_healthcare'], errors='coerce').fillna(0).astype(int)
    df['chpl_flag'] = pd.to_numeric(df['chpl_flag'], errors='coerce').fillna(0).astype(int)
    
    print(f"✓ Loaded {len(df):,} CVEs from database")
    print(f"  Date range: {df['published'].min().date()} to {df['published'].max().date()}")
    print(f"  KEV CVEs: {df['kev_flag'].sum():,} ({df['kev_flag'].mean()*100:.1f}%)")
    
    return df


def prepare_labels_and_splits(
    df: pd.DataFrame,
    train_end_date: str = '2024-09-30',
    test_start_date: str = '2024-10-01',
    horizon_days: int = 90
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Prepare temporal labels and train/val/test splits.
    
    Returns:
        train_df, val_df, test_df
    """
    print("\n" + "=" * 80)
    print("TEMPORAL LABEL CONSTRUCTION")
    print("=" * 80)
    print(f"Horizon: {horizon_days} days (look-forward for KEV)")
    
    # Build temporal labels
    df = build_temporal_labels(df, horizon_days=horizon_days)
    
    # Create splits
    train_end = pd.to_datetime(train_end_date)
    test_start = pd.to_datetime(test_start_date)
    val_start = train_end - timedelta(days=60)  # 2 months for validation
    
    train_df = df[df['published'] < val_start].copy()
    val_df = df[(df['published'] >= val_start) & (df['published'] < train_end)].copy()
    test_df = df[df['published'] >= test_start].copy()
    
    print(f"\n✓ Data splits created:")
    print(f"  Train:      {len(train_df):,} CVEs ({train_df['kev_flag'].sum()} KEV)")
    print(f"  Validation: {len(val_df):,} CVEs ({val_df['kev_flag'].sum()} KEV)")
    print(f"  Test:       {len(test_df):,} CVEs ({test_df['kev_flag'].sum()} KEV)")
    
    return train_df, val_df, test_df


def extract_old_production_features(train_df, val_df, test_df):
    """Extract OLD 13-feature set (current production)."""
    print("\n" + "=" * 80)
    print("EXTRACTING OLD FEATURES (Current Production - 13 features)")
    print("=" * 80)
    
    train_old = extract_old_features(train_df)
    val_old = extract_old_features(val_df)
    test_old = extract_old_features(test_df)
    
    feature_cols = get_old_feature_columns()
    print(f"✓ Old features ({len(feature_cols)}):")
    for i, col in enumerate(feature_cols, 1):
        print(f"  {i:2d}. {col}")
    
    return train_old, val_old, test_old, feature_cols


def extract_new_production_features(train_df, val_df, test_df):
    """Extract NEW feature set (improved production)."""
    print("\n" + "=" * 80)
    print("EXTRACTING NEW FEATURES (Improved)")
    print("=" * 80)
    
    # Compute historical risk scores from training data
    historical_data = train_df[train_df['kev_flag'].notna()].copy()
    
    engineer = ProductionFeatureEngineer(historical_data=historical_data)
    
    train_new = engineer.extract_features(train_df)
    val_new = engineer.extract_features(val_df)
    test_new = engineer.extract_features(test_df)
    
    feature_cols = engineer.get_feature_columns()
    
    print(f"✓ New features ({len(feature_cols)}):")
    
    # Show grouped by type
    groups = engineer.get_feature_importance_groups()
    for group_name, group_features in groups.items():
        print(f"\n  {group_name.upper()} ({len(group_features)} features):")
        for feat in group_features:
            if feat in feature_cols:
                print(f"    • {feat}")
    
    return train_new, val_new, test_new, feature_cols


def train_model(train_df, val_df, feature_cols, model_name="Model"):
    """Train LambdaRank model."""
    print(f"\n → Training {model_name}...")
    
    # Prepare ranking data
    train_df = train_df.copy()
    val_df = val_df.copy()
    
    train_df['soft_label'] = train_df['temporal_label']
    val_df['soft_label'] = val_df['temporal_label']
    
    # Create query groups by week
    train_df['published_week'] = train_df['published'].dt.to_period('W').astype(str)
    val_df['published_week'] = val_df['published'].dt.to_period('W').astype(str)
    
    model = train_lambdarank(train_df, val_df, feature_cols)
    
    return model


def evaluate_model(model, test_df, feature_cols, y_true_col='kev_flag'):
    """Evaluate model on test set."""
    y_true = test_df[y_true_col].fillna(0).values
    y_pred = model.predict(test_df[feature_cols].fillna(0))
    
    results = {}
    for k in [5, 10, 20, 50]:
        results[f'NDCG@{k}'] = ndcg_at_k(y_true, y_pred, k)
        results[f'P@{k}'] = precision_at_k(y_true, y_pred, k, threshold=0.5)
    
    # KEV capture count
    top_20_indices = np.argsort(y_pred)[::-1][:20]
    results['KEV_captured_top20'] = y_true[top_20_indices].sum()
    results['KEV_total'] = y_true.sum()
    
    return results, y_pred


def print_comparison_table(old_results, new_results):
    """Print beautiful comparison table."""
    print("\n" + "=" * 80)
    print("RESULTS COMPARISON: OLD vs NEW Features")
    print("=" * 80)
    
    print(f"\n{'Metric':<20} {'OLD':<20} {'NEW':<20} {'Improvement':<15}")
    print("-" * 80)
    
    for metric in ['NDCG@5', 'NDCG@10', 'NDCG@20', 'P@10', 'P@20', 'KEV_captured_top20']:
        old_val = old_results[metric]
        new_val = new_results[metric]
        
        if metric == 'KEV_captured_top20':
            improvement = f"+{new_val - old_val:.0f} CVEs"
            print(f"{metric:<20} {old_val:<20.0f} {new_val:<20.0f} {improvement:<15}")
        else:
            improvement_pct = ((new_val / old_val - 1) * 100) if old_val > 0 else 0
            improvement = f"+{improvement_pct:.1f}%"
            print(f"{metric:<20} {old_val:<20.4f} {new_val:<20.4f} {improvement:<15}")
    
    print("-" * 80)
    print(f"{'Total KEV in test':<20} {old_results['KEV_total']:.0f}")
    print()


def run_ablation_study(train_df, val_df, test_df):
    """Run ablation study to show contribution of each feature group."""
    print("\n" + "=" * 80)
    print("ABLATION STUDY - Feature Group Contributions")
    print("=" * 80)
    
    # Get historical data for feature engineer
    historical_data = train_df[train_df['kev_flag'].notna()].copy()
    engineer = ProductionFeatureEngineer(historical_data=historical_data)
    
    # Extract all features
    train_all = engineer.extract_features(train_df)
    val_all = engineer.extract_features(val_df)
    test_all = engineer.extract_features(test_df)
    
    groups = engineer.get_feature_importance_groups()
    
    # Baseline: CVSS only
    cvss_features = groups['cvss']
    model_cvss = train_model(train_all, val_all, cvss_features, "CVSS Only")
    results_cvss, _ = evaluate_model(model_cvss, test_all, cvss_features)
    
    print(f"\n  CVSS Only → NDCG@20 = {results_cvss['NDCG@20']:.4f}")
    
    # Incrementally add feature groups
    ablation_results = {'CVSS Only': results_cvss['NDCG@20']}
    cumulative_features = cvss_features.copy()
    
    add_order = ['cwe', 'vendor', 'description', 'attack', 'healthcare', 'temporal']
    
    for group_name in add_order:
        cumulative_features.extend(groups[group_name])
        
        model = train_model(train_all, val_all, cumulative_features, f"+ {group_name}")
        results, _ = evaluate_model(model, test_all, cumulative_features)
        
        ablation_results[f"+ {group_name}"] = results['NDCG@20']
        
        improvement = results['NDCG@20'] - ablation_results['CVSS Only']
        print(f"  + {group_name:<12} → NDCG@20 = {results['NDCG@20']:.4f} (Δ = +{improvement:.4f})")
    
    return ablation_results


def main():
    """Main evaluation pipeline."""
    
    # Load data
    df = load_data_from_db()
    
    # Prepare labels and splits
    train_df, val_df, test_df = prepare_labels_and_splits(
        df,
        train_end_date='2024-09-30',
        test_start_date='2024-10-01',
        horizon_days=90
    )
    
    # === EXPERIMENT 1: OLD Features (13) ===
    train_old, val_old, test_old, old_features = extract_old_production_features(
        train_df, val_df, test_df
    )
    
    model_old = train_model(train_old, val_old, old_features, "OLD Model (13 features)")
    old_results, old_pred = evaluate_model(model_old, test_old, old_features)
    
    # === EXPERIMENT 2: NEW Features ===
    train_new, val_new, test_new, new_features = extract_new_production_features(
        train_df, val_df, test_df
    )
    
    model_new = train_model(train_new, val_new, new_features, f"NEW Model ({len(new_features)} features)")
    new_results, new_pred = evaluate_model(model_new, test_new, new_features)
    
    # === COMPARISON ===
    print_comparison_table(old_results, new_results)
    
    # === ABLATION STUDY ===
    ablation_results = run_ablation_study(train_df, val_df, test_df)
    
    # === SAVE RESULTS ===
    output_dir = Path(__file__).parent.parent / 'outputs'
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Save metrics
    comparison_df = pd.DataFrame({
        'OLD_13_features': old_results,
        'NEW_28_features': new_results
    }).T
    comparison_df.to_csv(output_dir / f'production_comparison_{timestamp}.csv')
    
    # Save ablation
    ablation_df = pd.DataFrame.from_dict(ablation_results, orient='index', columns=['NDCG@20'])
    ablation_df.to_csv(output_dir / f'ablation_study_{timestamp}.csv')
    
    # Save predictions for analysis
    test_results = test_df[['cve_id', 'published', 'cvss', 'kev_flag']].copy()
    test_results['pred_old'] = old_pred
    test_results['pred_new'] = new_pred
    test_results.to_csv(output_dir / f'test_predictions_{timestamp}.csv', index=False)
    
    print("\n" + "=" * 80)
    print("✓ EVALUATION COMPLETE")
    print("=" * 80)
    print(f"\nResults saved:")
    print(f"  • {output_dir / f'production_comparison_{timestamp}.csv'}")
    print(f"  • {output_dir / f'ablation_study_{timestamp}.csv'}")
    print(f"  • {output_dir / f'test_predictions_{timestamp}.csv'}")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"OLD Model (13 features):")
    print(f"  NDCG@20 = {old_results['NDCG@20']:.4f}")
    print(f"  KEV Captured (top 20) = {old_results['KEV_captured_top20']:.0f}/{old_results['KEV_total']:.0f}")
    
    print(f"\nNEW Model ({len(new_features)} features):")
    print(f"  NDCG@20 = {new_results['NDCG@20']:.4f}")
    print(f"  KEV Captured (top 20) = {new_results['KEV_captured_top20']:.0f}/{new_results['KEV_total']:.0f}")
    
    improvement = (new_results['NDCG@20'] / old_results['NDCG@20'] - 1) * 100
    print(f"\n→ IMPROVEMENT: {improvement:.1f}% increase in NDCG@20")
    print()


if __name__ == "__main__":
    main()
