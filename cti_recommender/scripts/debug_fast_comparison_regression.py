#!/usr/bin/env python3
"""Debug why NEW feature set gets zero metrics in fast comparison."""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.evaluate_fast_comparison import create_splits, load_data, train_fast
from src.features.production_features import ProductionFeatureEngineer
from src.features.temporal_labeling import (
    extract_temporal_features as extract_old_features,
    get_temporal_feature_columns as get_old_features,
)


def kev_rank_summary(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    order = np.argsort(y_pred)[::-1]
    rank = {idx: i + 1 for i, idx in enumerate(order)}
    kev_idx = np.where(y_true == 1)[0]
    kev_ranks = sorted(rank[i] for i in kev_idx)
    return {
        "kev_count": int(len(kev_idx)),
        "best_kev_rank": int(kev_ranks[0]) if kev_ranks else -1,
        "kev_in_top10": int(sum(r <= 10 for r in kev_ranks)),
        "kev_in_top20": int(sum(r <= 20 for r in kev_ranks)),
    }


def main() -> None:
    df = load_data()
    train_df, val_df, test_df = create_splits(df)

    # OLD path
    train_old = extract_old_features(train_df)
    val_old = extract_old_features(val_df)
    test_old = extract_old_features(test_df)
    old_feats = get_old_features()
    old_model = train_fast(train_old.copy(), val_old.copy(), old_feats)
    old_pred = old_model.predict(test_old[old_feats].fillna(0))

    # NEW path
    historical = train_df[train_df["kev_flag"].notna()].copy()
    engineer = ProductionFeatureEngineer(historical_data=historical)
    train_new = engineer.extract_features(train_df)
    val_new = engineer.extract_features(val_df)
    test_new = engineer.extract_features(test_df)
    new_feats = engineer.get_feature_columns()
    new_model = train_fast(train_new.copy(), val_new.copy(), new_feats)
    new_pred = new_model.predict(test_new[new_feats].fillna(0))

    y_true = test_new["kev_flag"].fillna(0).astype(int).values

    print("OLD prediction stats:", float(np.min(old_pred)), float(np.max(old_pred)), float(np.std(old_pred)))
    print("NEW prediction stats:", float(np.min(new_pred)), float(np.max(new_pred)), float(np.std(new_pred)))

    print("OLD KEV ranking:", kev_rank_summary(y_true, old_pred))
    print("NEW KEV ranking:", kev_rank_summary(y_true, new_pred))

    x_new = test_new[new_feats].copy().apply(pd.to_numeric, errors="coerce")
    all_nan = [c for c in x_new.columns if x_new[c].isna().all()]
    zero_var = [c for c in x_new.columns if x_new[c].fillna(0).nunique() <= 1]

    print("NEW feature diagnostics:")
    print("  total_features:", len(new_feats))
    print("  all_nan:", len(all_nan), all_nan)
    print("  zero_variance:", len(zero_var), zero_var)

    corr = x_new.copy()
    corr["kev_flag"] = y_true
    corr_vals = corr.corr(numeric_only=True)["kev_flag"].drop("kev_flag").fillna(0)
    top = corr_vals.abs().sort_values(ascending=False).head(10)
    print("Top |corr| with KEV:")
    print(top.to_string())


if __name__ == "__main__":
    main()
