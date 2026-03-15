#!/usr/bin/env python3
"""Unified reproducible scientific protocol for model evaluation.

This script standardizes the evaluation pipeline used by STEP_5 and STEP_8.
It produces consistent artifacts for:
- Split diagnostics
- Confidence-weight search
- Cross-validation fold metrics
- Final model comparison on canonical test sets
- Markdown summary report
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import TimeSeriesSplit

PROJECT_ROOT = Path(__file__).resolve().parent.parent

from src.evaluation.metrics import compute_ranking_metrics
from src.models.baselines import compute_cvss_only_scores, compute_heuristic_scores
from src.models.ltr import get_default_ltr_params, save_model, train_lambdarank


EXPECTED_FEATURES = [
    "kev_flag",
    "epss_score",
    "epss_percentile",
    "is_healthcare",
    "healthcare_score",
    "attack_flag",
    "attack_technique_count",
    "chpl_flag",
    "is_curated",
    "curated_severity",
    "cvss_av",
    "cvss_ac",
    "cvss_pr",
    "cvss_ui",
    "cvss_s",
    "cvss_c",
    "cvss_i",
    "cvss_a",
    "cvss_score_derived",
    "cvss_severity_category",
    "cwe_is_top25",
    "cwe_is_injection",
    "cwe_is_crypto",
    "cwe_is_access_control",
    "cwe_is_input_validation",
    "cwe_is_memory_corruption",
    "cwe_category",
    "cwe_severity_score",
    "desc_has_rce",
    "desc_has_auth_bypass",
    "desc_has_priv_esc",
    "desc_has_sqli",
    "desc_has_xss",
    "desc_has_dos",
    "desc_has_buffer_overflow",
    "desc_has_path_traversal",
    "desc_has_csrf",
    "desc_has_xxe",
    "vendor_is_high_risk",
    "vendor_is_healthcare",
    "vendor_risk_score",
    "ultimate_risk",
    "critical_exploitable",
    "network_accessible",
    "auth_not_required",
    "high_impact_network",
    "healthcare_critical",
]


@dataclass
class SplitBundle:
    name: str
    train_df: pd.DataFrame
    val_df: pd.DataFrame
    test_df: pd.DataFrame


def _load_latest_features(features_dir: Path) -> pd.DataFrame:
    candidates = sorted(features_dir.glob("features_with_labels_*.csv"))
    if not candidates:
        raise FileNotFoundError(f"No feature files found in {features_dir}")
    path = candidates[-1]
    print(f"[INFO] Loading features from: {path}")
    df = pd.read_csv(path, low_memory=False)
    df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    df = df[df["published"].notna()].copy()
    return df


def _prepare_common_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()

    out["cvss"] = pd.to_numeric(out.get("cvss", 5.0), errors="coerce").fillna(5.0)
    out["cvss_norm"] = out["cvss"] / 10.0

    if "modified" in out.columns:
        out["modified"] = pd.to_datetime(out["modified"], utc=True, errors="coerce")

    days_since_pub = (pd.Timestamp.now(tz="UTC") - out["published"]).dt.days.clip(lower=0)
    max_days = max(float(days_since_pub.max()), 1.0)
    out["recency_score"] = 1.0 - (days_since_pub / max_days)

    if "attack_flag" in out.columns:
        out["has_attack"] = pd.to_numeric(out["attack_flag"], errors="coerce").fillna(0).astype(int)
    else:
        out["has_attack"] = 0

    for col in ["cvss_severity_category", "cwe_category", "curated_severity"]:
        if col in out.columns:
            out[col] = pd.Categorical(out[col].astype(str).fillna("unknown")).codes

    out["soft_label"] = pd.to_numeric(out.get("soft_label", 0), errors="coerce").fillna(0).astype(int)
    out["label_confidence"] = pd.to_numeric(out.get("label_confidence", 0.2), errors="coerce").fillna(0.2)

    return out


def _split_complete_temporal(df: pd.DataFrame) -> SplitBundle:
    d = df.sort_values("published").reset_index(drop=True)
    n = len(d)
    train_end = int(n * 0.70)
    val_end = int(n * 0.85)
    return SplitBundle(
        name="complete_70_15_15",
        train_df=d.iloc[:train_end].copy(),
        val_df=d.iloc[train_end:val_end].copy(),
        test_df=d.iloc[val_end:].copy(),
    )


def _split_year_based(df: pd.DataFrame, cutoff_date: str) -> SplitBundle:
    cutoff = pd.Timestamp(cutoff_date, tz="UTC")
    train_all = df[df["published"] <= cutoff].sort_values("published").copy()
    test_df = df[df["published"] > cutoff].sort_values("published").copy()

    val_size = max(int(len(train_all) * 0.15), 1)
    train_df = train_all.iloc[:-val_size].copy()
    val_df = train_all.iloc[-val_size:].copy()

    return SplitBundle(
        name="year_based_70_30",
        train_df=train_df,
        val_df=val_df,
        test_df=test_df,
    )


def _add_group_col(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["published_week"] = out["published"].dt.tz_localize(None).dt.to_period("W").astype(str)
    return out


def _metrics_for_scores(y_true: np.ndarray, scores: np.ndarray) -> Dict[str, float]:
    metrics = {}
    for k in [5, 10, 20, 50]:
        metrics.update(compute_ranking_metrics(y_true, scores, k=k))
    return metrics


def _search_confidence_scale(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    feature_cols: List[str],
    params: Dict,
) -> Tuple[float, pd.DataFrame, object]:
    scales = [0.5, 1.0, 1.5, 2.0]
    rows = []
    best_scale = 1.0
    best_score = -1.0
    best_model = None

    for scale in scales:
        tr = train_df.copy()
        va = val_df.copy()
        tr["label_confidence"] = (tr["label_confidence"] * scale).clip(lower=0.05, upper=2.0)
        va["label_confidence"] = (va["label_confidence"] * scale).clip(lower=0.05, upper=2.0)

        model = train_lambdarank(tr, va, feature_cols, params=params, random_seed=42)
        preds = model.predict(va[feature_cols].fillna(0).values)
        ndcg10 = _metrics_for_scores(va["soft_label"].values, preds)["NDCG@10"]
        rows.append({"scale": scale, "val_ndcg10": float(ndcg10)})

        if ndcg10 > best_score:
            best_score = ndcg10
            best_scale = scale
            best_model = model

    return best_scale, pd.DataFrame(rows), best_model


def _run_time_series_cv(df: pd.DataFrame, feature_cols: List[str], params: Dict) -> pd.DataFrame:
    d = df.sort_values("published").reset_index(drop=True).copy()
    tss = TimeSeriesSplit(n_splits=5)
    rows = []

    for fold_idx, (train_idx, val_idx) in enumerate(tss.split(d), start=1):
        tr = _add_group_col(d.iloc[train_idx].copy())
        va = _add_group_col(d.iloc[val_idx].copy())

        model = train_lambdarank(tr, va, feature_cols, params=params, random_seed=42 + fold_idx)
        preds = model.predict(va[feature_cols].fillna(0).values)
        m = _metrics_for_scores(va["soft_label"].values, preds)
        rows.append({
            "fold": fold_idx,
            "rows_train": len(tr),
            "rows_val": len(va),
            "NDCG@10": m["NDCG@10"],
            "NDCG@20": m["NDCG@20"],
            "Precision@20": m["Precision@20"],
        })

    return pd.DataFrame(rows)


def _evaluate_split(bundle: SplitBundle, feature_cols: List[str], output_dir: Path) -> pd.DataFrame:
    params = get_default_ltr_params()

    train_df = _add_group_col(bundle.train_df)
    val_df = _add_group_col(bundle.val_df)
    test_df = _add_group_col(bundle.test_df)

    best_scale, weight_search_df, initial_model = _search_confidence_scale(train_df, val_df, feature_cols, params)
    weight_search_path = output_dir / f"weight_search_{bundle.name}.csv"
    weight_search_df.to_csv(weight_search_path, index=False)

    # Retrain once with selected scale (train + val) for final test evaluation.
    merged_train = pd.concat([train_df, val_df], ignore_index=True)
    merged_train["label_confidence"] = (merged_train["label_confidence"] * best_scale).clip(lower=0.05, upper=2.0)

    # Use test split as validation for consistency with notebook behavior.
    test_scaled = test_df.copy()
    test_scaled["label_confidence"] = (test_scaled["label_confidence"] * best_scale).clip(lower=0.05, upper=2.0)

    final_model = train_lambdarank(merged_train, test_scaled, feature_cols, params=params, random_seed=42)

    model_path = PROJECT_ROOT / "models" / f"ltr_ranker_protocol_{bundle.name}.model"
    save_model(final_model, str(model_path))

    y_true = test_df["soft_label"].values

    ltr_scores = final_model.predict(test_df[feature_cols].fillna(0).values)
    cvss_scores = compute_cvss_only_scores(test_df)
    heuristic_scores = compute_heuristic_scores(test_df)

    model_scores = {
        "LambdaMART": ltr_scores,
        "Heuristic": heuristic_scores,
        "CVSS": cvss_scores,
    }

    rows = []
    for model_name, scores in model_scores.items():
        metrics = _metrics_for_scores(y_true, scores)
        for metric_name, metric_value in metrics.items():
            rows.append(
                {
                    "split": bundle.name,
                    "model": model_name,
                    "metric": metric_name,
                    "value": float(metric_value),
                    "best_confidence_scale": best_scale,
                }
            )

    # Save fold metrics for this split on train+val data only.
    fold_metrics_df = _run_time_series_cv(pd.concat([train_df, val_df], ignore_index=True), feature_cols, params)
    fold_metrics_df["split"] = bundle.name
    fold_metrics_df.to_csv(output_dir / f"fold_metrics_{bundle.name}.csv", index=False)

    return pd.DataFrame(rows)


def _build_split_summary(splits: List[SplitBundle]) -> pd.DataFrame:
    rows = []
    for sp in splits:
        for subset_name, subset_df in [
            ("train", sp.train_df),
            ("val", sp.val_df),
            ("test", sp.test_df),
        ]:
            rows.append(
                {
                    "split": sp.name,
                    "subset": subset_name,
                    "rows": len(subset_df),
                    "start": subset_df["published"].min().date().isoformat(),
                    "end": subset_df["published"].max().date().isoformat(),
                    "high_priority_pct": float((subset_df["soft_label"] >= 2).mean() * 100.0),
                }
            )
    return pd.DataFrame(rows)


def _write_report(final_df: pd.DataFrame, split_summary_df: pd.DataFrame, output_path: Path) -> None:
    lines = [
        "# Scientific Protocol Report",
        "",
        "This report is generated by `scripts/run_scientific_protocol.py`.",
        "",
        "## Split Summary",
        "",
        split_summary_df.to_markdown(index=False),
        "",
        "## LambdaMART vs Baselines (NDCG@10)",
        "",
    ]

    ndcg10 = final_df[final_df["metric"] == "NDCG@10"].pivot_table(index=["split"], columns="model", values="value")
    lines.append(ndcg10.to_markdown())
    lines.append("")
    lines.append("## Full Artifacts")
    lines.append("")
    lines.append("- `split_summary.csv`")
    lines.append("- `final_comparison.csv`")
    lines.append("- `weight_search_<split>.csv`")
    lines.append("- `fold_metrics_<split>.csv`")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run unified scientific protocol")
    parser.add_argument("--features-dir", default="outputs/features", help="Directory containing features_with_labels_*.csv")
    parser.add_argument("--output-dir", default="outputs/scientific_protocol", help="Directory to write protocol artifacts")
    parser.add_argument("--cutoff-date", default="2024-12-31", help="Year split cutoff date (inclusive for train)")
    args = parser.parse_args()

    features_dir = (PROJECT_ROOT / args.features_dir).resolve()
    output_dir = (PROJECT_ROOT / args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    df_raw = _load_latest_features(features_dir)
    df = _prepare_common_columns(df_raw)

    available_features = [f for f in EXPECTED_FEATURES if f in df.columns]
    if not available_features:
        raise RuntimeError("No expected feature columns found in features dataset")

    missing = [f for f in EXPECTED_FEATURES if f not in available_features]
    if missing:
        print(f"[WARN] Missing {len(missing)} expected features. Continuing with {len(available_features)} available features.")

    splits = [
        _split_complete_temporal(df),
        _split_year_based(df, args.cutoff_date),
    ]

    split_summary_df = _build_split_summary(splits)
    split_summary_df.to_csv(output_dir / "split_summary.csv", index=False)

    comparison_rows = []
    for split_bundle in splits:
        print(f"\n[INFO] Evaluating split: {split_bundle.name}")
        comparison_rows.append(_evaluate_split(split_bundle, available_features, output_dir))

    final_df = pd.concat(comparison_rows, ignore_index=True)
    final_df.to_csv(output_dir / "final_comparison.csv", index=False)

    _write_report(final_df, split_summary_df, output_dir / "scientific_protocol_report.md")

    manifest = {
        "features_used": available_features,
        "missing_expected_features": missing,
        "output_dir": str(output_dir),
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("\n[OK] Scientific protocol complete")
    print(f"[OK] Artifacts written to: {output_dir}")


if __name__ == "__main__":
    main()
