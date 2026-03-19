#!/usr/bin/env python3
"""
Generate Figure 5.1-style SHAP beeswarm plot from the current pruned model.

Outputs:
- outputs/plots/shap_beeswarm_figure5_1.png
- outputs/plots/shap_beeswarm_top_features.csv
"""

from __future__ import annotations

import argparse
import pickle
from pathlib import Path
import sys

import pandas as pd
import xgboost as xgb


PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from src.core.cve_database import CVEDatabase
from src.features.production_features import ProductionFeatureEngineer
from src.visualization.explainability import save_shap_beeswarm
from src.utils.logging_config import get_logger


logger = get_logger(__name__)


def load_feature_names(project_root: Path) -> list[str]:
    metadata_candidates = [
        project_root / "models/ltr_metadata_pruned.pkl",
        project_root / "models/ltr_metadata.pkl",
    ]
    for path in metadata_candidates:
        if path.exists():
            with open(path, "rb") as f:
                metadata = pickle.load(f)
            names = metadata.get("feature_names")
            if names:
                return list(names)
    raise FileNotFoundError("No model metadata with feature_names found in models/")


def load_dataset(limit: int) -> pd.DataFrame:
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
        e.epss_percentile,
        e.is_healthcare,
        e.is_curated,
        e.attack_technique_count,
        e.chpl_flag,
        e.label
    FROM cves c
    LEFT JOIN enrichments e ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    ORDER BY c.published DESC
    LIMIT ?
    """
    try:
        df = pd.read_sql_query(query, db.conn, params=[limit])
    except Exception:
        logger.exception("Failed to load dataset for SHAP beeswarm generation")
        raise
    finally:
        db.close()

    df["published"] = pd.to_datetime(df["published"], errors="coerce")
    return df


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SHAP beeswarm figure")
    parser.add_argument("--limit", type=int, default=50000, help="Rows to load from DB")
    parser.add_argument("--sample-size", type=int, default=5000, help="Rows sampled for SHAP")
    parser.add_argument("--max-display", type=int, default=20, help="Top features in beeswarm")
    parser.add_argument(
        "--output",
        default="outputs/plots/shap_beeswarm_figure5_1.png",
        help="Output image path relative to project root",
    )
    args = parser.parse_args()

    try:
        model_path = PROJECT_ROOT / "models/ltr_ranker_pruned.model"
        if not model_path.exists():
            raise FileNotFoundError(f"Model not found: {model_path}")

        feature_names = load_feature_names(PROJECT_ROOT)

        print("Loading data from SQLite...")
        raw_df = load_dataset(limit=args.limit)
        print(f"Loaded {len(raw_df):,} rows")

        print("Extracting production features...")
        features_df = ProductionFeatureEngineer(historical_data=None).extract_features(raw_df)

        if 'epss_high' not in features_df.columns:
            features_df['epss_high'] = (pd.to_numeric(features_df.get('epss_score', 0), errors='coerce').fillna(0.0) >= 0.1).astype(int)
        if 'kev_healthcare' not in features_df.columns:
            features_df['kev_healthcare'] = (
                pd.to_numeric(features_df.get('kev_flag', 0), errors='coerce').fillna(0).astype(int)
                * pd.to_numeric(features_df.get('is_healthcare', 0), errors='coerce').fillna(0).astype(int)
            )
        if 'attack_count_x_healthcare' not in features_df.columns:
            features_df['attack_count_x_healthcare'] = (
                pd.to_numeric(features_df.get('attack_technique_count', 0), errors='coerce').fillna(0)
                * pd.to_numeric(features_df.get('is_healthcare', 0), errors='coerce').fillna(0)
            )
        if 'days_since_2018' not in features_df.columns:
            baseline_date = pd.to_datetime('2018-01-01')
            published = pd.to_datetime(features_df.get('published', raw_df.get('published')), errors='coerce')
            features_df['days_since_2018'] = (published - baseline_date).dt.days.fillna(0).astype(int)

        missing = [f for f in feature_names if f not in features_df.columns]
        if missing:
            raise KeyError(f"Missing required model features in extracted dataframe: {missing}")

        X = features_df[feature_names].fillna(0)

        print("Loading XGBoost model...")
        model = xgb.Booster()
        model.load_model(str(model_path))

        output_path = PROJECT_ROOT / args.output
        shap_values = save_shap_beeswarm(
            model=model,
            X=X,
            feature_names=feature_names,
            output_path=str(output_path),
            max_display=args.max_display,
            sample_size=args.sample_size,
        )

        if shap_values is None:
            logger.error("SHAP beeswarm generation returned no values")
            return 1

        abs_mean = pd.DataFrame(
            {
                "feature": feature_names,
                "mean_abs_shap": pd.Series(shap_values).abs().mean() if len(getattr(shap_values, "shape", [])) == 1 else pd.DataFrame(shap_values).abs().mean().values,
            }
        ).sort_values("mean_abs_shap", ascending=False)

        csv_path = output_path.with_name("shap_beeswarm_top_features.csv")
        abs_mean.to_csv(csv_path, index=False)

        print(f"Saved figure: {output_path}")
        print(f"Saved summary: {csv_path}")
        return 0
    except Exception:
        logger.exception("SHAP beeswarm generation failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
