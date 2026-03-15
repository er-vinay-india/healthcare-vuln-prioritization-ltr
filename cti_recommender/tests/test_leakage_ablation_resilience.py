"""Resilience tests for leakage-free evaluation and ablation study scripts."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest


class TestLeakageFreeEvaluation:
    def test_load_data_from_db_re_raises_and_closes_db(self):
        import scripts.evaluation.evaluate_leakage_free as mod

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("query failed")):
            with pytest.raises(RuntimeError, match="query failed"):
                mod.load_data_from_db()

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_pipeline_fails(self):
        import scripts.evaluation.evaluate_leakage_free as mod

        with patch.object(mod, "run_leakage_free_evaluation", side_effect=RuntimeError("boom")):
            result = mod.main()

        assert result == 1

    def test_run_leakage_free_evaluation_happy_path_generates_outputs(self, tmp_path):
        import scripts.evaluation.evaluate_leakage_free as mod

        train_df = pd.DataFrame(
            {
                "published": pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01"]),
                "temporal_label": [0, 1, 2],
                "published_week": ["2024-01", "2024-02", "2024-03"],
                "cvss_norm": [0.2, 0.5, 0.9],
                "has_attack": [0, 1, 1],
                "is_healthcare": [1, 0, 1],
                "recency_score": [0.3, 0.6, 0.8],
                "f1": [0.1, 0.2, 0.3],
                "f2": [1.0, 1.1, 1.2],
            }
        )
        test_df = pd.DataFrame(
            {
                "published": pd.to_datetime(["2024-08-01", "2024-09-01"]),
                "temporal_label": [2, 1],
                "published_week": ["2024-31", "2024-35"],
                "cvss_norm": [0.9, 0.7],
                "has_attack": [1, 0],
                "is_healthcare": [1, 1],
                "recency_score": [0.95, 0.8],
                "f1": [0.7, 0.4],
                "f2": [1.3, 1.1],
            }
        )

        ltr_model = MagicMock()
        ltr_model.predict.return_value = np.array([0.8, 0.4])

        ensemble = MagicMock()
        ensemble.predict.return_value = (np.array([0.75, 0.45]), np.array([0.1, 0.2]))
        ensemble.predict_risk_aware.side_effect = [np.array([0.7, 0.35]), np.array([0.65, 0.3]), np.array([0.6, 0.2])]

        sig_df = pd.DataFrame(
            [
                {
                    "model_a": "LambdaRank_Conf_Weighted",
                    "model_b": "CVSS_Only",
                    "mean_diff": 0.05,
                    "p_value": 0.03,
                    "significant": True,
                }
            ]
        )

        with patch.object(mod, "load_data_from_db", return_value=train_df), \
             patch.object(mod, "prepare_temporal_data", return_value=train_df), \
             patch.object(mod, "create_temporal_train_test_split", return_value=(train_df, test_df)), \
             patch.object(mod, "get_temporal_feature_columns", return_value=["f1", "f2"]), \
             patch.object(mod, "train_confidence_weighted_ltr", return_value=ltr_model), \
             patch.object(mod, "train_bootstrap_ensemble", return_value=ensemble), \
             patch.object(mod, "compute_cvss_only_scores", return_value=np.array([0.9, 0.7])), \
             patch.object(mod, "pairwise_significance_test", return_value=sig_df):
            results = mod.run_leakage_free_evaluation(output_dir=tmp_path)

        assert "models" in results
        assert (tmp_path / "leakage_free_evaluation_results.json").exists()
        assert (tmp_path / "leakage_free_comparison.csv").exists()
        assert (tmp_path / "LEAKAGE_FREE_EVALUATION_REPORT.md").exists()


class TestAblationStudy:
    def test_load_data_re_raises_and_closes_db(self):
        import scripts.analyze.ablation_study as mod

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("db broken")):
            with pytest.raises(RuntimeError, match="db broken"):
                mod.load_data()

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_ablation_fails(self):
        import scripts.analyze.ablation_study as mod

        with patch.object(mod, "ablation_study", side_effect=RuntimeError("train crash")):
            result = mod.main()

        assert result == 1
