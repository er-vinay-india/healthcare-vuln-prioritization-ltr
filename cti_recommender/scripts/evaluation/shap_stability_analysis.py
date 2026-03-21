#!/usr/bin/env python3
"""
SHAP Stability Analysis for sample-size/seed sensitivity.

Evaluates stability of global SHAP feature rankings across sample sizes and seeds,
then justifies whether sample_size=5000 is a stable choice for beeswarm plotting.

Outputs (default under outputs/explainability/):
- shap_stability_runs.csv
- shap_stability_summary.csv
- shap_stability_pairwise.csv
- shap_stability_vs_size.png
"""

from __future__ import annotations

import argparse
import ast
import itertools
import json
from pathlib import Path
import sys
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import xgboost as xgb

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.features.production_features import ProductionFeatureEngineer
from src.utils.logging_config import get_logger
from scripts.evaluation.generate_shap_beeswarm import load_dataset, load_feature_names

logger = get_logger(__name__)


SAMPLE_SIZES_DEFAULT = [1000, 3000, 5000, 10000]
SEEDS_DEFAULT = [42, 7, 123]
BASELINE_SIZE = 5000
BASELINE_SEED = 42


def add_missing_pruned_features(features_df: pd.DataFrame, raw_df: pd.DataFrame) -> pd.DataFrame:
    """Backfill engineered columns expected by pruned-model metadata."""
    out = features_df.copy()

    if 'epss_high' not in out.columns:
        out['epss_high'] = (pd.to_numeric(out.get('epss_score', 0), errors='coerce').fillna(0.0) >= 0.1).astype(int)

    if 'kev_healthcare' not in out.columns:
        out['kev_healthcare'] = (
            pd.to_numeric(out.get('kev_flag', 0), errors='coerce').fillna(0).astype(int)
            * pd.to_numeric(out.get('is_healthcare', 0), errors='coerce').fillna(0).astype(int)
        )

    if 'attack_count_x_healthcare' not in out.columns:
        out['attack_count_x_healthcare'] = (
            pd.to_numeric(out.get('attack_technique_count', 0), errors='coerce').fillna(0)
            * pd.to_numeric(out.get('is_healthcare', 0), errors='coerce').fillna(0)
        )

    if 'days_since_2018' not in out.columns:
        baseline_date = pd.to_datetime('2018-01-01')
        published = pd.to_datetime(out.get('published', raw_df.get('published')), errors='coerce')
        out['days_since_2018'] = (published - baseline_date).dt.days.fillna(0).astype(int)

    return out


def ranking_from_importance(mean_abs_shap: np.ndarray, feature_names: List[str]) -> pd.Series:
    imp = pd.Series(mean_abs_shap, index=feature_names)
    return imp.rank(ascending=False, method='average')


def spearman_from_rank_series(rank_a: pd.Series, rank_b: pd.Series) -> float:
    # Spearman = Pearson correlation over ranks.
    return float(rank_a.corr(rank_b, method='pearson'))


def top10_overlap(top_a: List[str], top_b: List[str]) -> float:
    return float(100.0 * len(set(top_a).intersection(set(top_b))) / 10.0)


def run_shap_stability(
    limit: int,
    sample_sizes: List[int],
    seeds: List[int],
    max_display: int,
    output_dir: Path,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, Dict]:
    """Execute SHAP stability experiment grid and return run/summary/pairwise tables."""

    logger.info("Loading model metadata and dataset")
    feature_names = load_feature_names(PROJECT_ROOT)
    raw_df = load_dataset(limit=limit)

    logger.info("Extracting production features")
    features_df = ProductionFeatureEngineer(historical_data=None).extract_features(raw_df)
    features_df = add_missing_pruned_features(features_df, raw_df)

    missing = [f for f in feature_names if f not in features_df.columns]
    if missing:
        raise KeyError(f"Missing required model features: {missing}")

    X = features_df[feature_names].fillna(0)
    total_rows = len(X)

    if max(sample_sizes) > total_rows:
        raise ValueError(f"Requested sample_size {max(sample_sizes)} exceeds available rows {total_rows}")

    model_path = PROJECT_ROOT / "models/ltr_ranker_pruned.model"
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")

    logger.info("Loading model from %s", model_path)
    model = xgb.Booster()
    model.load_model(str(model_path))

    try:
        import shap
    except ImportError as exc:
        raise ImportError("SHAP is required. Install with: pip install shap") from exc

    explainer = shap.TreeExplainer(model)

    run_rows: List[Dict] = []
    run_meta: Dict[str, Dict] = {}

    for sample_size in sample_sizes:
        for seed in seeds:
            logger.info("Computing SHAP for sample_size=%s seed=%s", sample_size, seed)
            rng = np.random.RandomState(seed)
            sample_idx = rng.choice(total_rows, size=sample_size, replace=False)
            X_sample = X.iloc[sample_idx]

            shap_values = explainer.shap_values(X_sample)
            if isinstance(shap_values, list):
                shap_values = shap_values[0]

            shap_df = pd.DataFrame(shap_values, columns=feature_names)
            mean_abs = shap_df.abs().mean(axis=0).sort_values(ascending=False)
            top_features = mean_abs.head(10).index.tolist()
            top_vals = mean_abs.head(10).round(6).tolist()

            run_id = f"n{sample_size}_s{seed}"
            run_meta[run_id] = {
                "sample_size": sample_size,
                "seed": seed,
                "ranking": ranking_from_importance(mean_abs.values, mean_abs.index.tolist()),
                "top10": top_features,
                "mean_abs_series": mean_abs,
            }

            run_rows.append(
                {
                    "run_id": run_id,
                    "sample_size": sample_size,
                    "seed": seed,
                    "top_features": json.dumps(top_features),
                    "mean_abs_shap": json.dumps(top_vals),
                }
            )

    runs_df = pd.DataFrame(run_rows).sort_values(["sample_size", "seed"]).reset_index(drop=True)

    baseline_id = f"n{BASELINE_SIZE}_s{BASELINE_SEED}"
    if baseline_id not in run_meta:
        raise ValueError(
            f"Baseline run {baseline_id} missing. Ensure sample_sizes contains {BASELINE_SIZE} and seeds contains {BASELINE_SEED}."
        )

    baseline_rank = run_meta[baseline_id]["ranking"]
    baseline_top10 = run_meta[baseline_id]["top10"]

    corr_vals = []
    overlap_vals = []
    for _, row in runs_df.iterrows():
        rid = row["run_id"]
        rank = run_meta[rid]["ranking"]
        t10 = run_meta[rid]["top10"]
        corr_vals.append(spearman_from_rank_series(rank, baseline_rank))
        overlap_vals.append(top10_overlap(t10, baseline_top10))

    runs_df["spearman_corr_with_5000_seed42"] = corr_vals
    runs_df["top10_overlap_with_5000_seed42"] = overlap_vals

    pair_rows: List[Dict] = []
    run_ids = list(run_meta.keys())
    for a, b in itertools.combinations(run_ids, 2):
        rank_a = run_meta[a]["ranking"]
        rank_b = run_meta[b]["ranking"]
        top_a = run_meta[a]["top10"]
        top_b = run_meta[b]["top10"]

        pair_rows.append(
            {
                "run_a": a,
                "run_b": b,
                "sample_size_a": run_meta[a]["sample_size"],
                "seed_a": run_meta[a]["seed"],
                "sample_size_b": run_meta[b]["sample_size"],
                "seed_b": run_meta[b]["seed"],
                "spearman_corr": spearman_from_rank_series(rank_a, rank_b),
                "top10_overlap_pct": top10_overlap(top_a, top_b),
            }
        )

    pairwise_df = pd.DataFrame(pair_rows)

    summary_df = (
        runs_df.groupby("sample_size", as_index=False)
        .agg(
            avg_spearman_corr=("spearman_corr_with_5000_seed42", "mean"),
            min_spearman_corr=("spearman_corr_with_5000_seed42", "min"),
            avg_top10_overlap=("top10_overlap_with_5000_seed42", "mean"),
            min_top10_overlap=("top10_overlap_with_5000_seed42", "min"),
        )
        .sort_values("sample_size")
        .reset_index(drop=True)
    )

    summary_df[[
        "avg_spearman_corr",
        "min_spearman_corr",
        "avg_top10_overlap",
        "min_top10_overlap",
    ]] = summary_df[[
        "avg_spearman_corr",
        "min_spearman_corr",
        "avg_top10_overlap",
        "min_top10_overlap",
    ]].round(4)

    stable_rule = {
        "spearman_threshold": 0.90,
        "top10_overlap_threshold": 80.0,
    }

    qualifying = summary_df[
        (summary_df["min_spearman_corr"] >= stable_rule["spearman_threshold"])
        & (summary_df["min_top10_overlap"] >= stable_rule["top10_overlap_threshold"])
    ]

    min_stable_sample = int(qualifying["sample_size"].min()) if not qualifying.empty else None
    is_5000_stable = bool(
        not summary_df[
            (summary_df["sample_size"] == 5000)
            & (summary_df["min_spearman_corr"] >= stable_rule["spearman_threshold"])
            & (summary_df["min_top10_overlap"] >= stable_rule["top10_overlap_threshold"])
        ].empty
    )

    decision = {
        "baseline": baseline_id,
        "stable_rule": stable_rule,
        "is_5000_stable": is_5000_stable,
        "minimum_stable_sample_size": min_stable_sample,
        "total_rows_used": total_rows,
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    runs_df.to_csv(output_dir / "shap_stability_runs.csv", index=False)
    summary_df.to_csv(output_dir / "shap_stability_summary.csv", index=False)
    pairwise_df.to_csv(output_dir / "shap_stability_pairwise.csv", index=False)

    with open(output_dir / "shap_stability_decision.json", "w", encoding="utf-8") as f:
        json.dump(decision, f, indent=2)

    return runs_df, summary_df, pairwise_df, decision


def plot_stability(summary_df: pd.DataFrame, output_dir: Path) -> None:
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed; skipping stability plot")
        return

    fig, ax1 = plt.subplots(figsize=(9, 5.5))
    x = summary_df["sample_size"].values

    ax1.plot(x, summary_df["avg_spearman_corr"].values, marker='o', label='Avg Spearman')
    ax1.plot(x, summary_df["min_spearman_corr"].values, marker='o', linestyle='--', label='Min Spearman')
    ax1.set_xlabel("Sample Size")
    ax1.set_ylabel("Spearman Correlation")
    ax1.set_ylim(0.0, 1.0)
    ax1.grid(True, alpha=0.3)

    ax2 = ax1.twinx()
    ax2.plot(x, summary_df["avg_top10_overlap"].values, marker='s', color='tab:green', label='Avg Top-10 Overlap')
    ax2.plot(x, summary_df["min_top10_overlap"].values, marker='s', linestyle='--', color='tab:red', label='Min Top-10 Overlap')
    ax2.set_ylabel("Top-10 Overlap (%)")
    ax2.set_ylim(0, 100)

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc='lower right')

    plt.title("SHAP Stability vs Sample Size")
    plt.tight_layout()
    plt.savefig(output_dir / "shap_stability_vs_size.png", dpi=300, bbox_inches='tight')
    plt.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SHAP stability analysis")
    parser.add_argument("--limit", type=int, default=57000, help="Rows loaded from DB")
    parser.add_argument("--sample-sizes", default="1000,3000,5000,10000", help="Comma-separated sample sizes")
    parser.add_argument("--seeds", default="42,7,123", help="Comma-separated seeds")
    parser.add_argument("--max-display", type=int, default=20, help="Top features retained per run")
    parser.add_argument("--output-dir", default="outputs/explainability", help="Output directory")
    args = parser.parse_args()

    try:
        sample_sizes = [int(x.strip()) for x in args.sample_sizes.split(',') if x.strip()]
        seeds = [int(x.strip()) for x in args.seeds.split(',') if x.strip()]
        output_dir = PROJECT_ROOT / args.output_dir

        runs_df, summary_df, _pairwise_df, decision = run_shap_stability(
            limit=args.limit,
            sample_sizes=sample_sizes,
            seeds=seeds,
            max_display=args.max_display,
            output_dir=output_dir,
        )

        plot_stability(summary_df, output_dir)

        print("\n=== SHAP Stability Run Table (first 12 rows) ===")
        print(runs_df.head(12).to_string(index=False))

        print("\n=== SHAP Stability Summary ===")
        print(summary_df.to_string(index=False))

        print("\n=== Stability Decision ===")
        print(json.dumps(decision, indent=2))

        if decision["is_5000_stable"]:
            print("\nConclusion: sample_size=5000 is stable under configured thresholds.")
        else:
            print("\nConclusion: sample_size=5000 is NOT stable under configured thresholds.")

        if decision["minimum_stable_sample_size"] is not None:
            print(f"Minimum stable sample size: {decision['minimum_stable_sample_size']}")
        else:
            print("No sample size met the configured stability thresholds.")

        print(f"\nSaved CSVs/plot to: {output_dir}")
        return 0
    except Exception:
        logger.exception("SHAP stability analysis failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
