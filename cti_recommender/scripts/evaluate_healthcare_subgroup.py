#!/usr/bin/env python3
"""Evaluate ranking quality on healthcare vs non-healthcare subgroups."""

from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.evaluate_fast_comparison import create_splits, load_data, train_fast
from src.evaluation.metrics import ndcg_at_k, precision_at_k
from src.features.production_features import ProductionFeatureEngineer

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


def _safe_metric(fn, y_true: np.ndarray, y_pred: np.ndarray, k: int) -> float:
    if len(y_true) == 0:
        return float("nan")
    try:
        return float(fn(y_true, y_pred, k))
    except Exception:
        return float("nan")


def eval_slice(df: pd.DataFrame, y_pred: np.ndarray, name: str) -> dict:
    y_true = df["kev_flag"].fillna(0).astype(int).values
    out = {
        "slice": name,
        "rows": int(len(df)),
        "kev_count": int(y_true.sum()),
        "ndcg@10": _safe_metric(ndcg_at_k, y_true, y_pred, 10),
        "ndcg@20": _safe_metric(ndcg_at_k, y_true, y_pred, 20),
        "p@10": _safe_metric(lambda yt, yp, k: precision_at_k(yt, yp, k, threshold=0.5), y_true, y_pred, 10),
        "p@20": _safe_metric(lambda yt, yp, k: precision_at_k(yt, yp, k, threshold=0.5), y_true, y_pred, 20),
    }
    return out


def main() -> int:
    try:
        df = load_data()
        train_df, val_df, test_df = create_splits(df)

        historical = train_df[train_df["kev_flag"].notna()].copy()
        engineer = ProductionFeatureEngineer(historical_data=historical)

        train_new = engineer.extract_features(train_df)
        val_new = engineer.extract_features(val_df)
        test_new = engineer.extract_features(test_df)
        features = engineer.get_feature_columns()

        model = train_fast(train_new, val_new, features)
        preds = model.predict(test_new[features].fillna(0))

        overall = eval_slice(test_new, preds, "overall")

        hc_mask = test_new["is_healthcare"].fillna(0).astype(int) == 1
        non_hc_mask = ~hc_mask

        healthcare = eval_slice(test_new.loc[hc_mask], preds[hc_mask.values], "healthcare_only")
        non_healthcare = eval_slice(test_new.loc[non_hc_mask], preds[non_hc_mask.values], "non_healthcare")

        result_df = pd.DataFrame([overall, healthcare, non_healthcare])

        out_dir = Path("outputs")
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"healthcare_subgroup_eval_{ts}.csv"
        result_df.to_csv(out_path, index=False)

        logger.info("\n%s", result_df.to_string(index=False))
        logger.info("Saved: %s", out_path)
        return 0
    except Exception:
        logger.exception("Healthcare subgroup evaluation failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
