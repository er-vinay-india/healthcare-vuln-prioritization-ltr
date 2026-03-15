"""
Compare Model Performance: Original vs Enhanced Features
=========================================================

Compares model performance with different feature sets.
"""

import pandas as pd
import numpy as np
import lightgbm as lgb
from sklearn.metrics import ndcg_score
import sys
sys.path.append('.')

from src.features.enhanced_features import get_enhanced_feature_columns

def calculate_ndcg_at_k(y_true, y_pred, k=20):
    """Calculate NDCG@k."""
    if len(y_true) < k:
        k = len(y_true)
    return ndcg_score([y_true], [y_pred], k=k)

def train_and_evaluate(X_train, y_train, X_test, y_test, train_groups, test_groups, feature_set_name):
    """Train model and return metrics."""
    print(f"\n{'='*60}")
    print(f"Training with: {feature_set_name}")
    print(f"{'='*60}")
    print(f"Features: {X_train.shape[1]}")
    print(f"Train samples: {len(X_train):,}")
    print(f"Test samples: {len(X_test):,}")
    
    # LightGBM parameters
    params = {
        'objective': 'lambdarank',
        'metric': 'ndcg',
        'ndcg_eval_at': [5, 10, 20],
        'learning_rate': 0.05,
        'num_leaves': 31,
        'min_data_in_leaf': 20,
        'verbose': -1,
    }
    
    # Create datasets
    train_data = lgb.Dataset(X_train, y_train, group=train_groups)
    test_data = lgb.Dataset(X_test, y_test, group=test_groups, reference=train_data)
    
    # Train
    model = lgb.train(
        params,
        train_data,
        num_boost_round=100,
        valid_sets=[test_data],
        callbacks=[lgb.early_stopping(10), lgb.log_evaluation(0)]
    )
    
    # Predict
    y_pred = model.predict(X_test)
    
    # Calculate NDCG@k
    ndcg_5 = calculate_ndcg_at_k(y_test.values, y_pred, k=5)
    ndcg_10 = calculate_ndcg_at_k(y_test.values, y_pred, k=10)
    ndcg_20 = calculate_ndcg_at_k(y_test.values, y_pred, k=20)
    
    print(f"\nResults:")
    print(f"  NDCG@5:  {ndcg_5:.4f}")
    print(f"  NDCG@10: {ndcg_10:.4f}")
    print(f"  NDCG@20: {ndcg_20:.4f}")
    
    # Feature importance (top 10)
    importance = model.feature_importance(importance_type='gain')
    feature_names = X_train.columns
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importance
    }).sort_values('importance', ascending=False)
    
    print(f"\nTop 10 Features:")
    for idx, row in importance_df.head(10).iterrows():
        print(f"  {row['feature']}: {row['importance']:.0f}")
    
    return {
        'name': feature_set_name,
        'n_features': X_train.shape[1],
        'ndcg_5': ndcg_5,
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20,
        'model': model,
        'feature_importance': importance_df
    }

def main():
    print("="*80)
    print("FEATURE SET COMPARISON")
    print("="*80)
    
    # Load data
    print("\n[1] Loading data...")
    df = pd.read_csv('outputs/features/features_enhanced_latest.csv')
    df['published'] = pd.to_datetime(df['published'])
    df_labeled = df[df['soft_label'].notna()].copy()
    print(f"✓ Loaded {len(df_labeled):,} labeled CVEs")
    
    # Temporal split
    print("\n[2] Creating temporal split...")
    df_train = df_labeled[df_labeled['published'] < '2025-01-01']
    df_test = df_labeled[df_labeled['published'] >= '2025-01-01']
    print(f"✓ Train: {len(df_train):,} CVEs (2018-2024)")
    print(f"✓ Test: {len(df_test):,} CVEs (2025)")
    
    # Define feature sets
    ORIGINAL_FEATURES = [
        'cvss_norm', 'epss_score', 'kev_flag', 'has_attack',
        'attack_technique_count', 'is_healthcare', 'healthcare_score',
        'chpl_flag', 'days_since_published', 'recency_score',
        'cvss_epss_product', 'kev_healthcare_interaction', 'published_week'
    ]
    
    ENHANCED_FEATURES = get_enhanced_feature_columns()
    ENHANCED_AVAILABLE = [f for f in ENHANCED_FEATURES 
                          if f in df.columns 
                          and not f.startswith('desc_')
                          and f != 'description_cvss_risk']
    
    FEATURES_ORIGINAL = [f for f in ORIGINAL_FEATURES if f in df.columns]
    FEATURES_ENHANCED = ENHANCED_AVAILABLE
    FEATURES_COMBINED = FEATURES_ORIGINAL + ENHANCED_AVAILABLE
    
    # Create groups for LambdaMART
    train_groups = df_train.groupby(df_train['published'].dt.to_period('D')).size().values
    test_groups = df_test.groupby(df_test['published'].dt.to_period('D')).size().values
    
    # Compare feature sets
    results = []
    
    # Test 1: Original features only
    print("\n" + "="*80)
    print("TEST 1: ORIGINAL FEATURES")
    print("="*80)
    X_train = df_train[FEATURES_ORIGINAL]
    y_train = df_train['soft_label']
    X_test = df_test[FEATURES_ORIGINAL]
    y_test = df_test['soft_label']
    
    result1 = train_and_evaluate(
        X_train, y_train, X_test, y_test, 
        train_groups, test_groups,
        f"Original Features ({len(FEATURES_ORIGINAL)})"
    )
    results.append(result1)
    
    # Test 2: Enhanced features only
    print("\n" + "="*80)
    print("TEST 2: ENHANCED FEATURES ONLY")
    print("="*80)
    X_train = df_train[FEATURES_ENHANCED]
    y_train = df_train['soft_label']
    X_test = df_test[FEATURES_ENHANCED]
    y_test = df_test['soft_label']
    
    result2 = train_and_evaluate(
        X_train, y_train, X_test, y_test,
        train_groups, test_groups,
        f"Enhanced Features ({len(FEATURES_ENHANCED)})"
    )
    results.append(result2)
    
    # Test 3: Combined features
    print("\n" + "="*80)
    print("TEST 3: COMBINED FEATURES")
    print("="*80)
    X_train = df_train[FEATURES_COMBINED]
    y_train = df_train['soft_label']
    X_test = df_test[FEATURES_COMBINED]
    y_test = df_test['soft_label']
    
    result3 = train_and_evaluate(
        X_train, y_train, X_test, y_test,
        train_groups, test_groups,
        f"Combined Features ({len(FEATURES_COMBINED)})"
    )
    results.append(result3)
    
    # Summary comparison
    print("\n" + "="*80)
    print("FINAL COMPARISON")
    print("="*80)
    
    comparison_df = pd.DataFrame([
        {
            'Feature Set': r['name'],
            'N Features': r['n_features'],
            'NDCG@5': r['ndcg_5'],
            'NDCG@10': r['ndcg_10'],
            'NDCG@20': r['ndcg_20'],
        }
        for r in results
    ])
    
    print("\n" + comparison_df.to_string(index=False))
    
    # Calculate improvements
    print("\n" + "="*80)
    print("IMPROVEMENTS")
    print("="*80)
    
    baseline_ndcg20 = results[0]['ndcg_20']
    enhanced_ndcg20 = results[1]['ndcg_20']
    combined_ndcg20 = results[2]['ndcg_20']
    
    print(f"\nEnhanced vs Original:")
    print(f"  Δ NDCG@20: {enhanced_ndcg20 - baseline_ndcg20:+.4f} ({100*(enhanced_ndcg20/baseline_ndcg20 - 1):+.1f}%)")
    
    print(f"\nCombined vs Original:")
    print(f"  Δ NDCG@20: {combined_ndcg20 - baseline_ndcg20:+.4f} ({100*(combined_ndcg20/baseline_ndcg20 - 1):+.1f}%)")
    
    # Save results
    comparison_df.to_csv('outputs/enhanced_features_comparison.csv', index=False)
    print(f"\n✓ Results saved to: outputs/enhanced_features_comparison.csv")
    
    print("\n" + "="*80)
    print("✓ COMPARISON COMPLETE")
    print("="*80)

if __name__ == '__main__':
    main()
