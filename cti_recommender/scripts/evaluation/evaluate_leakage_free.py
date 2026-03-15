#!/usr/bin/env python3
"""
Leakage-Free Model Evaluation Script

This script implements the corrected evaluation pipeline that:
1. Uses temporal labels (look-forward 30 days for KEV/EPSS)
2. Ensures features only use information available at prediction time
3. Re-trains and evaluates all models under fair conditions
4. Computes statistical significance tests

Author: CVE Prioritization Research Team
Date: January 27, 2026
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import json
import warnings
warnings.filterwarnings('ignore')

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

# Local imports
from src.core.cve_database import CVEDatabase
from src.features.temporal_labeling import (
    build_temporal_labels,
    extract_temporal_features,
    get_temporal_feature_columns,
    create_temporal_train_test_split,
    print_temporal_label_diagnostics
)
from src.models.ltr import prepare_ranking_data, train_lambdarank
from src.models.bootstrap_ensemble import BootstrapEnsemble
from src.models.baselines import compute_cvss_only_scores, compute_heuristic_scores
from src.evaluation.significance import (
    pairwise_significance_test,
    print_significance_report,
    create_comparison_table
)
from src.evaluation.metrics import ndcg_at_k, precision_at_k

import lightgbm as lgb


def load_data_from_db() -> pd.DataFrame:
    """Load CVE data from database."""
    print("=" * 70)
    print("LOADING DATA FROM DATABASE")
    print("=" * 70)
    
    db = CVEDatabase()
    
    # Disable automatic timestamp conversion that causes issues
    import sqlite3
    sqlite3.register_adapter(type(None), lambda x: None)
    
    query = """
    SELECT 
        c.cve_id,
        CAST(c.published AS TEXT) as published,
        c.cvss,
        c.description,
        e.kev_flag,
        e.epss_score,
        e.epss_percentile,
        e.is_healthcare,
        e.attack_technique_count,
        e.chpl_flag,
        e.label as old_label
    FROM cves c
    LEFT JOIN enrichments e ON c.cve_id = e.cve_id
    WHERE c.cvss IS NOT NULL
    ORDER BY c.published DESC
    """
    
    try:
        df = pd.read_sql_query(query, db.conn)
    except Exception:
        logger.exception("Failed to load leakage-free evaluation data from database")
        raise
    finally:
        db.close()
    
    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    
    print(f"Loaded {len(df):,} CVEs from database")
    print(f"Date range: {df['published'].min()} to {df['published'].max()}")
    
    return df


def prepare_temporal_data(df: pd.DataFrame, horizon_days: int = 30) -> pd.DataFrame:
    """
    Prepare data with temporal labels and leakage-free features.
    """
    print("\n" + "=" * 70)
    print("BUILDING TEMPORAL LABELS (Leakage-Free)")
    print("=" * 70)
    print(f"Horizon: {horizon_days} days (look-forward window)")
    
    # Build temporal labels
    df = build_temporal_labels(df, horizon_days=horizon_days)
    
    # Print diagnostics
    print_temporal_label_diagnostics(df)
    
    # Extract leakage-free features
    print("\n" + "=" * 70)
    print("EXTRACTING LEAKAGE-FREE FEATURES")
    print("=" * 70)
    
    df = extract_temporal_features(df)
    
    feature_cols = get_temporal_feature_columns()
    print(f"Feature columns ({len(feature_cols)}):")
    for i, col in enumerate(feature_cols, 1):
        print(f"  {i:2d}. {col}")
    
    # Create published_week for grouping
    df['published_week'] = df['published'].dt.to_period('W').astype(str)
    
    return df


def train_confidence_weighted_ltr(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: List[str]
) -> lgb.Booster:
    """
    Train confidence-weighted LambdaRank model.
    """
    print("\n" + "=" * 70)
    print("TRAINING CONFIDENCE-WEIGHTED LAMBDARANK")
    print("=" * 70)
    
    # Use temporal_label and label_confidence
    train_df = train_df.copy()
    val_df = val_df.copy()
    
    # Rename for compatibility with existing function
    train_df['soft_label'] = train_df['temporal_label']
    val_df['soft_label'] = val_df['temporal_label']
    
    model = train_lambdarank(train_df, val_df, feature_cols)
    
    return model


def train_bootstrap_ensemble(
    train_df: pd.DataFrame,
    feature_cols: List[str],
    K: int = 10
) -> BootstrapEnsemble:
    """
    Train bootstrap ensemble for uncertainty quantification.
    """
    print("\n" + "=" * 70)
    print(f"TRAINING BOOTSTRAP ENSEMBLE (K={K})")
    print("=" * 70)
    
    train_df = train_df.copy()
    train_df['soft_label'] = train_df['temporal_label']
    
    ensemble = BootstrapEnsemble(K=K, seed=42)
    ensemble.train(train_df, feature_cols, prepare_ranking_data)
    
    return ensemble


def evaluate_model(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    k_values: List[int] = [5, 10, 20]
) -> Dict[str, float]:
    """
    Evaluate a single model's predictions.
    """
    results = {}
    
    for k in k_values:
        results[f'NDCG@{k}'] = ndcg_at_k(y_true, y_pred, k)
        results[f'P@{k}'] = precision_at_k(y_true, y_pred, k, threshold=2)
    
    return results


def run_leakage_free_evaluation(
    train_end_date: str = '2024-06-01',
    test_start_date: str = '2024-07-01',
    horizon_days: int = 30,
    output_dir: Path = None
) -> Dict:
    """
    Run the complete leakage-free evaluation pipeline.
    
    Args:
        train_end_date: End date for training data
        test_start_date: Start date for test data
        horizon_days: Days to look forward for label construction
        output_dir: Directory for output files
    
    Returns:
        Dict with all results
    """
    if output_dir is None:
        output_dir = Path(__file__).resolve().parents[2] / 'outputs'
    output_dir.mkdir(exist_ok=True)
    
    results = {
        'metadata': {
            'train_end_date': train_end_date,
            'test_start_date': test_start_date,
            'horizon_days': horizon_days,
            'evaluation_date': datetime.now().isoformat()
        },
        'models': {},
        'significance': None
    }
    
    # Step 1: Load data
    df = load_data_from_db()
    
    # Step 2: Build temporal labels and features
    df = prepare_temporal_data(df, horizon_days=horizon_days)
    
    # Step 3: Create train/test split
    print("\n" + "=" * 70)
    print("CREATING TEMPORAL TRAIN/TEST SPLIT")
    print("=" * 70)
    
    train_df, test_df = create_temporal_train_test_split(
        df,
        train_end_date=train_end_date,
        test_start_date=test_start_date,
        horizon_days=horizon_days
    )
    
    # Further split training into train/val for early stopping
    val_split_date = pd.to_datetime(train_end_date) - timedelta(days=60)
    train_only_df = train_df[train_df['published'] < val_split_date]
    val_df = train_df[train_df['published'] >= val_split_date]
    
    print(f"  Train (for model): {len(train_only_df):,} CVEs")
    print(f"  Validation: {len(val_df):,} CVEs")
    print(f"  Test: {len(test_df):,} CVEs")
    
    feature_cols = get_temporal_feature_columns()
    
    # Check we have enough data
    if len(train_only_df) < 100 or len(test_df) < 50:
        print("\n[WARN] WARNING: Insufficient data for robust evaluation")
        print("   This may be because temporal labels require future data")
        print("   that isn't available for recent CVEs.")
    
    # Step 4: Train models
    
    # 4a. Confidence-weighted LambdaRank
    try:
        ltr_model = train_confidence_weighted_ltr(train_only_df, val_df, feature_cols)
        ltr_predictions = ltr_model.predict(test_df[feature_cols].values)
        results['models']['LambdaRank_Conf_Weighted'] = {
            'predictions': ltr_predictions.tolist(),
            'metrics': evaluate_model(test_df['temporal_label'].values, ltr_predictions)
        }
        print(f"[OK] LambdaRank trained and evaluated")
    except Exception as e:
        print(f"[X] LambdaRank failed: {e}")
        ltr_predictions = np.zeros(len(test_df))
    
    # 4b. Bootstrap Ensemble
    try:
        ensemble = train_bootstrap_ensemble(train_df, feature_cols, K=10)
        
        # Mean predictions (standard)
        mean_preds, std_preds = ensemble.predict(test_df, feature_cols)
        results['models']['Ensemble_Mean'] = {
            'predictions': mean_preds.tolist(),
            'uncertainty': std_preds.tolist(),
            'metrics': evaluate_model(test_df['temporal_label'].values, mean_preds)
        }
        
        # Risk-averse predictions (mean - λ*std)
        for lambda_val in [0.25, 0.5, 1.0]:
            risk_aware_preds = ensemble.predict_risk_aware(test_df, feature_cols, lambda_val=lambda_val)
            results['models'][f'Ensemble_RiskAware_λ={lambda_val}'] = {
                'predictions': risk_aware_preds.tolist(),
                'metrics': evaluate_model(test_df['temporal_label'].values, risk_aware_preds)
            }
        
        print(f"[OK] Bootstrap Ensemble trained (Mean + Risk-Averse)")
    except Exception as e:
        print(f"[X] Bootstrap Ensemble failed: {e}")
        mean_preds = np.zeros(len(test_df))
        std_preds = np.zeros(len(test_df))
    
    # 4c. Baselines (no training needed)
    try:
        # CVSS-only baseline
        cvss_scores = compute_cvss_only_scores(test_df)
        results['models']['CVSS_Only'] = {
            'predictions': cvss_scores.tolist(),
            'metrics': evaluate_model(test_df['temporal_label'].values, cvss_scores)
        }
        
        # Heuristic baseline (uses CVSS + available features, NOT KEV/EPSS)
        # Create modified heuristic that doesn't use KEV/EPSS
        heuristic_scores = (
            0.50 * test_df['cvss_norm'].fillna(0.5).values +
            0.20 * test_df['has_attack'].fillna(0).values +
            0.15 * test_df['is_healthcare'].fillna(0).values +
            0.15 * test_df['recency_score'].fillna(0.5).values
        )
        results['models']['Heuristic_NoLeak'] = {
            'predictions': heuristic_scores.tolist(),
            'metrics': evaluate_model(test_df['temporal_label'].values, heuristic_scores)
        }
        
        print(f"[OK] Baselines computed (CVSS-only, Heuristic)")
    except Exception as e:
        print(f"[X] Baselines failed: {e}")
    
    # Step 5: Statistical Significance Tests
    print("\n" + "=" * 70)
    print("STATISTICAL SIGNIFICANCE TESTING")
    print("=" * 70)
    
    try:
        model_predictions = {}
        for model_name, model_data in results['models'].items():
            model_predictions[model_name] = np.array(model_data['predictions'])
        
        # Run pairwise tests
        significance_df = pairwise_significance_test(
            model_predictions=model_predictions,
            y_true=test_df['temporal_label'].values,
            groups=test_df['published_week'].values,
            k=10,
            alpha=0.05
        )
        
        results['significance'] = significance_df.to_dict('records')
        
        # Print report
        model_metrics = {name: data['metrics'] for name, data in results['models'].items()}
        print_significance_report(significance_df, model_metrics)
        
    except Exception as e:
        print(f"[X] Significance testing failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Step 6: Generate comparison table
    print("\n" + "=" * 70)
    print("FINAL COMPARISON TABLE")
    print("=" * 70)
    
    model_metrics = {name: data['metrics'] for name, data in results['models'].items()}
    
    print("\n{:<35} {:>10} {:>10} {:>10} {:>10}".format(
        'Model', 'NDCG@5', 'NDCG@10', 'NDCG@20', 'P@10'
    ))
    print("-" * 80)
    
    for model_name, metrics in model_metrics.items():
        print("{:<35} {:>10.4f} {:>10.4f} {:>10.4f} {:>10.4f}".format(
            model_name,
            metrics.get('NDCG@5', 0),
            metrics.get('NDCG@10', 0),
            metrics.get('NDCG@20', 0),
            metrics.get('P@10', 0)
        ))
    
    # Step 7: Save results
    output_file = output_dir / 'leakage_free_evaluation_results.json'
    
    # Convert numpy types for JSON serialization
    def convert_for_json(obj):
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, (np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: convert_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [convert_for_json(v) for v in obj]
        return obj
    
    with open(output_file, 'w') as f:
        json.dump(convert_for_json(results), f, indent=2)
    
    print(f"\n[OK] Results saved to: {output_file}")
    
    # Save comparison CSV
    comparison_df = pd.DataFrame(model_metrics).T
    comparison_csv = output_dir / 'leakage_free_comparison.csv'
    comparison_df.to_csv(comparison_csv)
    print(f"[OK] Comparison CSV saved to: {comparison_csv}")
    
    # Generate summary report
    report_path = output_dir / 'LEAKAGE_FREE_EVALUATION_REPORT.md'
    generate_markdown_report(results, model_metrics, report_path)
    print(f"[OK] Report saved to: {report_path}")
    
    return results


def generate_markdown_report(
    results: Dict,
    model_metrics: Dict,
    output_path: Path
) -> None:
    """Generate a comprehensive markdown report."""
    
    report = f"""# Leakage-Free Model Evaluation Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Horizon:** {results['metadata']['horizon_days']} days  
**Train End:** {results['metadata']['train_end_date']}  
**Test Start:** {results['metadata']['test_start_date']}  

---

## Key Changes from Previous Evaluation

1. **Temporal Labels**: Labels now reflect whether a CVE becomes high-risk 
   in the NEXT 30 days (KEV addition or EPSS spike), rather than using 
   current KEV/EPSS status.

2. **Feature Exclusion**: KEV flag and EPSS score are EXCLUDED from features
   since they are what we're trying to predict.

3. **Available Features**: Only information available at CVE publish time:
   - CVSS score and severity levels
   - Healthcare relevance (text-based)
   - ATT&CK mappings
   - CVE age/recency

---

## Performance Comparison

| Model | NDCG@5 | NDCG@10 | NDCG@20 | P@10 |
|-------|--------|---------|---------|------|
"""
    
    for model_name, metrics in model_metrics.items():
        report += f"| {model_name} | {metrics.get('NDCG@5', 0):.4f} | {metrics.get('NDCG@10', 0):.4f} | {metrics.get('NDCG@20', 0):.4f} | {metrics.get('P@10', 0):.4f} |\n"
    
    report += """
---

## Statistical Significance

"""
    
    if results.get('significance'):
        report += "| Model A | Model B | Mean Diff | p-value | Significant |\n"
        report += "|---------|---------|-----------|---------|-------------|\n"
        for row in results['significance']:
            sig = "[OK]" if row.get('significant', False) else "[X]"
            p_val = f"{row['p_value']:.4f}" if not np.isnan(row.get('p_value', np.nan)) else "N/A"
            report += f"| {row['model_a']} | {row['model_b']} | {row['mean_diff']:.4f} | {p_val} | {sig} |\n"
    else:
        report += "*Significance tests not available*\n"
    
    report += """
---

## Interpretation

### What Changed?

Without KEV and EPSS as features:
- The model cannot "cheat" by using the target variable as input
- Performance reflects true predictive ability
- CVSS and attack mappings become the primary signals

### Risk-Aware Ranking

The ensemble's risk-averse predictions (mean - λ×std) penalize high-uncertainty
CVEs. This is valuable when:
- False negatives are costly (missing a critical CVE)
- Manual review capacity is limited
- Prioritizing "sure bets" over uncertain predictions

---

## Recommendations

1. **Use Confidence-Weighted LambdaRank** as the primary model
2. **Apply Risk-Averse Ranking** (λ=0.5) for conservative prioritization
3. **Monitor uncertainty** to identify CVEs needing manual review
4. **Retrain periodically** as new KEV/EPSS ground truth becomes available

---

*This evaluation follows temporal evaluation best practices to ensure 
research validity and real-world applicability.*
"""
    
    with open(output_path, 'w') as f:
        f.write(report)


def main() -> int:
    """Main entry point."""
    print("\n" + "=" * 70)
    print("LEAKAGE-FREE CVE PRIORITIZATION EVALUATION")
    print("=" * 70)
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        # Run evaluation with default dates
        # Note: Adjust these dates based on your data availability
        run_leakage_free_evaluation(
            train_end_date='2024-06-01',
            test_start_date='2024-07-01',
            horizon_days=30
        )

        print("\n" + "=" * 70)
        print("[OK] EVALUATION COMPLETE")
        print("=" * 70)
        return 0
    except Exception:
        logger.exception("Leakage-free evaluation failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
