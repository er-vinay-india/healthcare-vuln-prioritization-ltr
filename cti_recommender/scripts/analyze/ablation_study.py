#!/usr/bin/env python3
"""
Ablation Study: Evaluate contribution of each feature set.
Tests incremental value of KEV, EPSS, Healthcare, ATT&CK, and CHPL signals.
"""
import sys
from pathlib import Path
# Add project root to path (scripts/analyze/ -> scripts/ -> project root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import ndcg_score
import xgboost as xgb
from datetime import datetime

from src.core.cve_database import CVEDatabase

def load_data():
    """Load training data from database."""
    print("Loading data from database...")
    db = CVEDatabase()
    
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
        CAST(c.published AS TEXT) as published_str
    FROM enrichments e
    LEFT JOIN cves c ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    """
    
    df = pd.read_sql_query(query, db.conn)
    db.close()
    
    print(f"Loaded {len(df):,} CVEs")
    return df

def prepare_all_features(df):
    """Prepare all possible features."""
    features = pd.DataFrame({
        # Basic features
        'cvss': df['cvss'].fillna(0.0),
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'epss_percentile': df['epss_percentile'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'chpl_flag': df['chpl_flag'].fillna(0).astype(int),
        'attack_flag': df['attack_flag'].fillna(0).astype(int),
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
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
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    return features, df['label']

def train_and_evaluate(X_train, y_train, X_test, y_test, variant_name):
    """Train model and evaluate."""
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg',
        'eta': 0.1,
        'max_depth': 6,
        'min_child_weight': 1,
        'subsample': 0.8,
        'colsample_bytree': 0.8,
        'verbosity': 0,
        'seed': 42
    }
    
    model = xgb.train(
        params,
        dtrain,
        num_boost_round=50,
        evals=[(dtest, 'test')],
        verbose_eval=False
    )
    
    # Predictions
    y_pred = model.predict(dtest)
    
    # NDCG scores
    ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
    
    # Precision at K (high-priority CVEs: L3+)
    y_test_arr = y_test.values
    top_k_indices = np.argsort(y_pred)[::-1]
    
    def precision_at_k(k):
        top_k = top_k_indices[:k]
        high_priority = (y_test_arr[top_k] >= 3).sum()
        return high_priority / k
    
    p_10 = precision_at_k(10)
    p_20 = precision_at_k(20)
    p_50 = precision_at_k(50)
    
    return {
        'variant': variant_name,
        'features': X_train.shape[1],
        'ndcg_5': ndcg_5,
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20,
        'p_10': p_10,
        'p_20': p_20,
        'p_50': p_50
    }

def ablation_study():
    """Run ablation study with different feature combinations."""
    print("\n" + "="*70)
    print("ABLATION STUDY: Feature Contribution Analysis")
    print("="*70)
    
    # Load data
    df = load_data()
    all_features, labels = prepare_all_features(df)
    
    # Split data (same split for all variants)
    X_train_all, X_test_all, y_train, y_test = train_test_split(
        all_features, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    print(f"\nTrain: {len(X_train_all):,} | Test: {len(X_test_all):,}")
    
    # Define feature sets for each variant
    variants = {
        'V1_Baseline_CVSS': [
            'cvss', 'cvss_high', 'cvss_critical'
        ],
        'V2_+KEV': [
            'cvss', 'cvss_high', 'cvss_critical',
            'kev_flag'
        ],
        'V3_+EPSS': [
            'cvss', 'cvss_high', 'cvss_critical',
            'kev_flag',
            'epss_score', 'epss_percentile', 'epss_high', 'kev_x_epss'
        ],
        'V4_+Healthcare': [
            'cvss', 'cvss_high', 'cvss_critical',
            'kev_flag',
            'epss_score', 'epss_percentile', 'epss_high', 'kev_x_epss',
            'is_healthcare', 'healthcare_critical', 'kev_healthcare', 'healthcare_x_cvss'
        ],
        'V5_+Curated': [
            'cvss', 'cvss_high', 'cvss_critical',
            'kev_flag',
            'epss_score', 'epss_percentile', 'epss_high', 'kev_x_epss',
            'is_healthcare', 'healthcare_critical', 'kev_healthcare', 'healthcare_x_cvss',
            'is_curated'
        ],
        'V6_+ATT&CK': [
            'cvss', 'cvss_high', 'cvss_critical',
            'kev_flag',
            'epss_score', 'epss_percentile', 'epss_high', 'kev_x_epss',
            'is_healthcare', 'healthcare_critical', 'kev_healthcare', 'healthcare_x_cvss',
            'is_curated',
            'attack_flag', 'attack_technique_count', 'attack_healthcare', 'attack_multi', 'attack_count_x_healthcare'
        ],
        'V7_Full_+CHPL': [
            'cvss', 'cvss_high', 'cvss_critical',
            'kev_flag',
            'epss_score', 'epss_percentile', 'epss_high', 'kev_x_epss',
            'is_healthcare', 'healthcare_critical', 'kev_healthcare', 'healthcare_x_cvss',
            'is_curated',
            'attack_flag', 'attack_technique_count', 'attack_healthcare', 'attack_multi', 'attack_count_x_healthcare',
            'chpl_flag', 'chpl_healthcare', 'chpl_x_attack',
            'days_since_2018', 'is_recent'
        ]
    }
    
    print("\n" + "="*70)
    print("Training and evaluating variants...")
    print("="*70)
    
    results = []
    for variant_name, feature_list in variants.items():
        print(f"\n{variant_name} ({len(feature_list)} features)...")
        
        X_train = X_train_all[feature_list]
        X_test = X_test_all[feature_list]
        
        result = train_and_evaluate(X_train, y_train, X_test, y_test, variant_name)
        results.append(result)
        
        print(f"  NDCG@10: {result['ndcg_10']:.4f}")
        print(f"  P@20:    {result['p_20']:.2%}")
    
    # Summary table
    results_df = pd.DataFrame(results)
    
    print("\n" + "="*70)
    print("ABLATION STUDY RESULTS")
    print("="*70)
    print("\n{:<25} {:>6} {:>10} {:>10} {:>10} {:>8} {:>8} {:>8}".format(
        "Variant", "#Feat", "NDCG@5", "NDCG@10", "NDCG@20", "P@10", "P@20", "P@50"
    ))
    print("-" * 105)
    
    for _, row in results_df.iterrows():
        print("{:<25} {:>6} {:>10.4f} {:>10.4f} {:>10.4f} {:>7.1%} {:>7.1%} {:>7.1%}".format(
            row['variant'],
            row['features'],
            row['ndcg_5'],
            row['ndcg_10'],
            row['ndcg_20'],
            row['p_10'],
            row['p_20'],
            row['p_50']
        ))
    
    # Incremental improvements
    print("\n" + "="*70)
    print("INCREMENTAL IMPROVEMENT (vs previous variant)")
    print("="*70)
    
    for i in range(1, len(results_df)):
        curr = results_df.iloc[i]
        prev = results_df.iloc[i-1]
        
        ndcg_gain = curr['ndcg_10'] - prev['ndcg_10']
        p20_gain = curr['p_20'] - prev['p_20']
        
        print(f"\n{curr['variant']}:")
        print(f"  NDCG@10: {ndcg_gain:+.4f} ({ndcg_gain/prev['ndcg_10']*100:+.1f}%)")
        print(f"  P@20:    {p20_gain:+.4f} ({p20_gain/prev['p_20']*100:+.1f}%)")
    
    # Overall improvement
    baseline_ndcg = results_df.iloc[0]['ndcg_10']
    full_ndcg = results_df.iloc[-1]['ndcg_10']
    total_gain = full_ndcg - baseline_ndcg
    
    print("\n" + "="*70)
    print(f"OVERALL: Full model vs Baseline")
    print("="*70)
    print(f"  NDCG@10: {baseline_ndcg:.4f} → {full_ndcg:.4f} ({total_gain:+.4f}, {total_gain/baseline_ndcg*100:+.1f}%)")
    print(f"  P@20:    {results_df.iloc[0]['p_20']:.2%} → {results_df.iloc[-1]['p_20']:.2%}")
    
    # Key findings
    print("\n" + "="*70)
    print("KEY FINDINGS")
    print("="*70)
    
    # Find biggest gains
    gains = []
    for i in range(1, len(results_df)):
        gain = results_df.iloc[i]['ndcg_10'] - results_df.iloc[i-1]['ndcg_10']
        gains.append((results_df.iloc[i]['variant'], gain))
    
    gains.sort(key=lambda x: x[1], reverse=True)
    
    print("\nTop 3 feature additions by NDCG@10 improvement:")
    for i, (variant, gain) in enumerate(gains[:3], 1):
        print(f"  {i}. {variant}: +{gain:.4f}")
    
    print("\n✅ Ablation study complete!")
    print("="*70)
    
    # Save results
    output_dir = Path('outputs')
    output_dir.mkdir(exist_ok=True)
    results_df.to_csv(output_dir / 'ablation_study_results.csv', index=False)
    print(f"\nResults saved: outputs/ablation_study_results.csv")

if __name__ == '__main__':
    ablation_study()
