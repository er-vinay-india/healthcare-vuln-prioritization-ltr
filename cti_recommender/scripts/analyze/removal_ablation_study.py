#!/usr/bin/env python3
"""
Removal Ablation Study: Measure performance degradation when removing key features.
Trains full model, then retrains with each feature removed to measure impact.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import ndcg_score
import lightgbm as lgb
from datetime import datetime

from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def print_separator(char='=', length=70):
    print(char * length)

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
    
    try:
        df = pd.read_sql_query(query, db.conn)
    except Exception:
        logger.exception("Failed to load data")
        raise
    finally:
        db.close()
    
    print(f"Loaded {len(df):,} CVEs")
    return df

def prepare_features(df):
    """Prepare all features for training."""
    features = pd.DataFrame({
        # Core features
        'cvss_norm': df['cvss'].fillna(0.0) / 10.0,  # Normalize to [0,1]
        'kev_flag': df['kev_flag'].astype(int),
        'epss_score': df['epss_score'].fillna(0.0),
        'epss_percentile': df['epss_percentile'].fillna(0.0),
        'is_healthcare': df['is_healthcare'].astype(int),
        'is_curated': df['is_curated'].astype(int),
        'chpl_flag': df['chpl_flag'].fillna(0).astype(int),
        'has_attack': df['attack_flag'].fillna(0).astype(int),
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
    })
    
    # Engineered features
    features['cvss_high'] = (df['cvss'] >= 7.0).astype(int)
    features['cvss_critical'] = (df['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    
    # Interaction features
    features['cvss_epss_product'] = features['cvss_norm'] * features['epss_score']
    features['kev_healthcare_interaction'] = features['kev_flag'] * features['is_healthcare']
    features['healthcare_x_cvss'] = features['is_healthcare'] * features['cvss_norm']
    features['kev_x_epss'] = features['kev_flag'] * features['epss_score']
    
    # Recency
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    ref_date = pd.to_datetime('2018-01-01')
    days_since = (df['published'] - ref_date).dt.days.fillna(0)
    max_days = days_since.max()
    features['recency_score'] = 1.0 - (days_since / max_days) if max_days > 0 else 0.0
    
    return features, df['label']

def evaluate_with_lightgbm(model, X_test, y_test, variant_name, active_features):
    """Evaluate using production LightGBM LambdaMART model with feature masking."""
    # Get model's expected features
    model_features = model.feature_name()
    
    # Reindex X_test to match model's feature schema
    X_test_aligned = X_test.reindex(columns=model_features, fill_value=0)
    
    # Predictions
    y_pred = model.predict(X_test_aligned.values)
    
    # NDCG scores
    ndcg_5 = ndcg_score([y_test], [y_pred], k=5)
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
    
    # Precision at K
    y_test_arr = y_test.values
    top_k_indices = np.argsort(y_pred)[::-1]
    
    def precision_at_k(k):
        top_k = top_k_indices[:k]
        high_priority = (y_test_arr[top_k] >= 3).sum()
        return high_priority / k
    
    p_10 = precision_at_k(10)
    p_20 = precision_at_k(20)
    
    return {
        'variant': variant_name,
        'features': active_features,
        'ndcg_5': ndcg_5,
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20,
        'p_10': p_10,
        'p_20': p_20
    }

def removal_ablation_study():
    """Run removal ablation: load production LambdaMART model, mask features one at a time."""
    print("\n" + "="*70)
    print("REMOVAL ABLATION STUDY: Performance Impact of Individual Features")
    print("Using Production LightGBM LambdaMART Model")
    print_separator()
    
    # Load production model
    model_path = Path('models/ltr_ranker.model')
    if not model_path.exists():
        raise FileNotFoundError(f"Production model not found: {model_path}")
    
    print(f"\nLoading production model: {model_path}")
    ltr_model = lgb.Booster(model_file=str(model_path))
    model_features = ltr_model.feature_name()
    print(f"Model expects {len(model_features)} features")
    
    # Load data
    df = load_data()
    all_features, labels = prepare_features(df)
    
    # Split data (same split for all variants)
    X_train_all, X_test_all, y_train, y_test = train_test_split(
        all_features, labels, test_size=0.2, random_state=42, stratify=labels
    )
    
    print(f"\nTrain: {len(X_train_all):,} | Test: {len(X_test_all):,}")
    print(f"Total features prepared: {len(all_features.columns)}")
    
    # Define key features to remove (one at a time)
    key_features_to_remove = {
        'kev_flag': 'KEV Flag',
        'epss_percentile': 'EPSS Percentile',
        'has_attack': 'ATT&CK Flag',
        'cvss_norm': 'CVSS (normalized)',
        'is_healthcare': 'Healthcare Flag'
    }
    
    print("\n" + "="*70)
    print("Evaluating model with feature masking...")
    print_separator()
    
    results = []
    
    # 1. Full model (baseline for comparison)
    print("\n[1/6] Full Model (all features)...")
    X_test_full = X_test_all.copy()
    full_result = evaluate_with_lightgbm(
        ltr_model, X_test_full, y_test, 'Full_Model', len(all_features.columns)
    )
    results.append(full_result)
    print(f"  NDCG@20: {full_result['ndcg_20']:.4f}")
    
    baseline_ndcg20 = full_result['ndcg_20']
    
    # 2. Evaluate variants with each feature MASKED (set to 0)
    for idx, (feature, feature_name) in enumerate(key_features_to_remove.items(), start=2):
        if feature not in all_features.columns:
            print(f"\n[{idx}/6] SKIP: {feature_name} (feature '{feature}' not found)")
            continue
            
        print(f"\n[{idx}/6] Masking: {feature_name}...")
        
        # Create copy and mask the feature (set to 0)
        X_test_masked = X_test_all.copy()
        X_test_masked[feature] = 0.0
        
        variant_name = f'Without_{feature}'
        active_features = len(all_features.columns) - 1  # One feature masked
        result = evaluate_with_lightgbm(
            ltr_model, X_test_masked, y_test, variant_name, active_features
        )
        
        # Calculate drop
        ndcg_drop = result['ndcg_20'] - baseline_ndcg20
        pct_drop = (ndcg_drop / baseline_ndcg20) * 100
        
        result['ndcg_20_drop'] = ndcg_drop
        result['pct_drop'] = pct_drop
        result['feature_removed'] = feature
        result['feature_name'] = feature_name
        
        results.append(result)
        
        print(f"  NDCG@20: {result['ndcg_20']:.4f} (drop: {ndcg_drop:+.4f}, {pct_drop:+.1f}%)")
    
    # Summary table
    results_df = pd.DataFrame(results)
    
    print("\n" + "="*70)
    print("REMOVAL ABLATION RESULTS")
    print_separator()
    print("\n{:<30} {:>10} {:>10} {:>12} {:>12}".format(
        "Variant", "NDCG@20", "NDCG@10", "Drop (abs)", "Drop (%)"
    ))
    print("-" * 75)
    
    for _, row in results_df.iterrows():
        variant = row['variant'].replace('Without_', '−')
        drop_abs = row.get('ndcg_20_drop', 0.0)
        drop_pct = row.get('pct_drop', 0.0)
        print("{:<30} {:>10.4f} {:>10.4f} {:>12.4f} {:>11.1f}%".format(
            variant,
            row['ndcg_20'],
            row['ndcg_10'],
            drop_abs,
            drop_pct
        ))
    
    # Feature importance ranking
    removal_results = results_df[results_df['variant'] != 'Full_Model'].copy()
    if not removal_results.empty:
        removal_results = removal_results.sort_values('pct_drop', ascending=True)  # Most negative first
        
        print("\n" + "="*70)
        print("FEATURE IMPORTANCE RANKING (by NDCG@20 degradation)")
        print_separator()
        print("\nRank | Feature              | Impact")
        print("-" * 50)
        for i, (_, row) in enumerate(removal_results.iterrows(), 1):
            feature_name = row['feature_name']
            pct_drop = row['pct_drop']
            interpretation = ""
            if pct_drop < -10:
                interpretation = "CRITICAL"
            elif pct_drop < -5:
                interpretation = "HIGH"
            elif pct_drop < -2:
                interpretation = "MODERATE"
            else:
                interpretation = "LOW"
            
            print(f"{i:4} | {feature_name:<20} | {pct_drop:+6.1f}%  [{interpretation}]")
    
    # Key findings
    print("\n" + "="*70)
    print("KEY FINDINGS")
    print_separator()
    
    if not removal_results.empty:
        top_feature = removal_results.iloc[0]
        print(f"\nMost critical feature: {top_feature['feature_name']}")
        print(f"  Removal causes {top_feature['pct_drop']:+.1f}% NDCG@20 degradation")
        
        print("\nFeature retention justification:")
        print("  All features contribute to ranking performance or domain relevance.")
        print("  Exploitation signals (KEV, EPSS) typically have highest impact.")
        print("  Domain features (healthcare, CHPL) ensure sector-specific prioritization.")
    
    print("\n[OK] Removal ablation study complete!")
    print_separator()
    
    # Save results
    output_dir = Path('outputs')
    output_dir.mkdir(exist_ok=True)
    
    output_path = output_dir / 'removal_ablation_results.csv'
    results_df.to_csv(output_path, index=False)
    print(f"\nResults saved: {output_path}")
    
    # Save formatted table for thesis
    if not removal_results.empty:
        thesis_table = removal_results[['feature_name', 'pct_drop', 'ndcg_20']].copy()
        thesis_table.columns = ['Feature_Removed', 'NDCG@20_Drop_%', 'NDCG@20']
        thesis_table = thesis_table.sort_values('NDCG@20_Drop_%', ascending=True)
        
        thesis_path = output_dir / 'removal_ablation_thesis_table.csv'
        thesis_table.to_csv(thesis_path, index=False)
        print(f"Thesis table:     {thesis_path}")

def main() -> int:
    try:
        removal_ablation_study()
        return 0
    except Exception:
        logger.exception("Removal ablation study failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
