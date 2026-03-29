#!/usr/bin/env python3
"""
Removal Ablation Study: Measure impact of removing individual features.
Trains full model, then retrains with each key feature removed to quantify degradation.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import ndcg_score
import xgboost as xgb
from datetime import datetime

from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def print_separator():
    print("-" * 80)

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
        logger.exception("Failed to load data from database")
        raise
    finally:
        db.close()
    
    print(f"Loaded {len(df):,} CVEs")
    return df

def prepare_features(df):
    """Prepare all features for the full model."""
    features = pd.DataFrame({
        # Basic features
        'cvss': df['cvss'].fillna(0.0),
        'cvss_norm': (df['cvss'].fillna(0.0) / 10.0),  # Normalized CVSS
        'kev_flag': df['kev_flag'].astype(int),
        'epss_score': df['epss_score'].fillna(0.0),
        'epss_percentile': df['epss_percentile'].fillna(0.0),
        'is_healthcare': df['is_healthcare'].astype(int),
        'is_curated': df['is_curated'].astype(int),
        'chpl_flag': df['chpl_flag'].fillna(0).astype(int),
        'has_attack': df['attack_flag'].fillna(0).astype(int),  # Renamed for clarity
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
    })
    
    # Engineered features
    features['cvss_high'] = (features['cvss'] >= 7.0).astype(int)
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    
    # Interaction features
    features['cvss_epss_product'] = features['cvss_norm'] * features['epss_score']
    features['kev_x_epss'] = features['kev_flag'] * features['epss_score']
    
    # Recency
    df['published'] = pd.to_datetime(df['published_str'], errors='coerce')
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    return features, df['label']

def train_and_evaluate(X_train, y_train, X_test, y_test, variant_name):
    """Train XGBoost model and evaluate on test set."""
    dtrain = xgb.DMatrix(X_train, label=y_train)
    dtest = xgb.DMatrix(X_test, label=y_test)
    
    params = {
        'objective': 'rank:ndcg',
        'eval_metric': 'ndcg@20',
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
        num_boost_round=100,
        evals=[(dtest, 'test')],
        verbose_eval=False
    )
    
    # Predictions
    y_pred = model.predict(dtest)
    
    # NDCG scores
    ndcg_10 = ndcg_score([y_test], [y_pred], k=10)
    ndcg_20 = ndcg_score([y_test], [y_pred], k=20)
    ndcg_100 = ndcg_score([y_test], [y_pred], k=100)
    
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
        'features': X_train.shape[1],
        'ndcg_10': ndcg_10,
        'ndcg_20': ndcg_20,
        'ndcg_100': ndcg_100,
        'p_10': p_10,
        'p_20': p_20
    }

def removal_ablation_study():
    """Run removal ablation: measure impact of dropping each key feature."""
    print("\n" + "="*80)
    print("REMOVAL ABLATION STUDY: Feature Importance via Exclusion")
    print("="*80)
    
    # Load data
    df = load_data()
    all_features, labels = prepare_features(df)
    
    # Split data (same split for all experiments)
    X_train_all, X_test_all, y_train, y_test = train_test_split(
        all_features, labels, test_size=0.3, random_state=42, stratify=labels
    )
    
    print(f"\nTrain: {len(X_train_all):,} | Test: {len(X_test_all):,}")
    print(f"Total features: {X_train_all.shape[1]}")
    
    # Key features to ablate (matching thesis Table 4.2)
    key_features = {
        'kev_flag': ['kev_flag', 'kev_healthcare', 'kev_x_epss'],
        'epss_percentile': ['epss_percentile', 'epss_score', 'epss_high', 'cvss_epss_product', 'kev_x_epss'],
        'has_attack': ['has_attack', 'attack_technique_count'],
        'cvss_norm': ['cvss_norm', 'cvss', 'cvss_high', 'cvss_critical', 'cvss_epss_product', 'healthcare_critical'],
        'is_healthcare': ['is_healthcare', 'healthcare_critical', 'kev_healthcare']
    }
    
    print("\n" + "="*80)
    print("FEATURE GROUPS TO ABLATE")
    print_separator()
    for name, cols in key_features.items():
        available = [c for c in cols if c in all_features.columns]
        print(f"{name:20s}: {', '.join(available)}")
    
    # 1. Train FULL model (baseline)
    print("\n" + "="*80)
    print("Training FULL model (all features)...")
    print_separator()
    
    full_result = train_and_evaluate(
        X_train_all, y_train, X_test_all, y_test, 'Full_Model'
    )
    
    baseline_ndcg20 = full_result['ndcg_20']
    print(f"Full Model NDCG@20: {baseline_ndcg20:.4f} ({baseline_ndcg20*100:.2f}%)")
    
    # 2. Train models with each feature group removed
    print("\n" + "="*80)
    print("Training ablated models (one feature group removed at a time)...")
    print_separator()
    
    results = [full_result]
    
    for feature_name, feature_cols in key_features.items():
        # Get columns to DROP (those that exist in the dataset)
        cols_to_drop = [c for c in feature_cols if c in all_features.columns]
        
        if not cols_to_drop:
            print(f"\n[SKIP] {feature_name}: No matching columns found")
            continue
        
        # Create reduced feature set
        remaining_cols = [c for c in all_features.columns if c not in cols_to_drop]
        X_train_reduced = X_train_all[remaining_cols]
        X_test_reduced = X_test_all[remaining_cols]
        
        print(f"\n{feature_name}:")
        print(f"  Removing: {', '.join(cols_to_drop)}")
        print(f"  Remaining features: {len(remaining_cols)}")
        
        # Train and evaluate
        result = train_and_evaluate(
            X_train_reduced, y_train, X_test_reduced, y_test,
            f'Without_{feature_name}'
        )
        results.append(result)
        
        # Calculate degradation
        ndcg_drop = baseline_ndcg20 - result['ndcg_20']
        ndcg_drop_pct = (ndcg_drop / baseline_ndcg20) * 100
        
        print(f"  NDCG@20: {result['ndcg_20']:.4f} ({result['ndcg_20']*100:.2f}%)")
        print(f"  Drop: {ndcg_drop:.4f} ({ndcg_drop_pct:.1f}%)")
    
    # Summary table
    results_df = pd.DataFrame(results)
    
    print("\n" + "="*80)
    print("REMOVAL ABLATION RESULTS")
    print("="*80)
    print("\n{:<30} {:>10} {:>12} {:>12} {:>15}".format(
        "Variant", "NDCG@10", "NDCG@20", "NDCG@100", "Drop vs Full"
    ))
    print_separator()
    
    for _, row in results_df.iterrows():
        if row['variant'] == 'Full_Model':
            drop_str = "—"
        else:
            drop = baseline_ndcg20 - row['ndcg_20']
            drop_pct = (drop / baseline_ndcg20) * 100
            drop_str = f"–{drop_pct:.1f}%"
        
        print("{:<30} {:>10.2f}% {:>12.2f}% {:>12.2f}% {:>15}".format(
            row['variant'],
            row['ndcg_10'] * 100,
            row['ndcg_20'] * 100,
            row['ndcg_100'] * 100,
            drop_str
        ))
    
    # Thesis-ready table (Table 4.2 format)
    print("\n" + "="*80)
    print("TABLE 4.2 FORMAT (for thesis)")
    print("="*80)
    print("\n{:<25} {:>15} {}".format(
        "Feature Removed", "NDCG@20 Drop", "Performance Interpretation"
    ))
    print_separator()
    
    interpretations = {
        'kev_flag': 'Critical for top-rank accuracy; KEV provides the strongest exploitation evidence.',
        'epss_percentile': 'Essential for prioritizing non-KEV vulnerabilities; predictive exploitation likelihood heavily influences ranking.',
        'has_attack': 'Captures adversarial behavioural context; provides mid-level impact via ATT&CK mappings.',
        'cvss_norm': 'Acts as a severity-based tiebreaker; contributes but is not dominant.',
        'is_healthcare': 'Affects healthcare sector prioritization; ensures medically relevant CVEs remain visible.'
    }
    
    for _, row in results_df.iterrows():
        if row['variant'] == 'Full_Model':
            continue
        
        feature_key = row['variant'].replace('Without_', '')
        drop = baseline_ndcg20 - row['ndcg_20']
        drop_pct = (drop / baseline_ndcg20) * 100
        
        interpretation = interpretations.get(feature_key, 'N/A')
        
        print(f"{feature_key:<25} {drop_pct:>14.1f}%  {interpretation}")
    
    # Save results
    output_dir = Path('outputs')
    output_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_path = output_dir / f'removal_ablation_results_{timestamp}.csv'
    results_df.to_csv(csv_path, index=False)
    
    print(f"\n[SAVED] {csv_path}")
    print("\n" + "="*80)
    print("[OK] Removal ablation study complete!")
    print("="*80)

def main() -> int:
    try:
        removal_ablation_study()
        return 0
    except Exception:
        logger.exception("Removal ablation study failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
