"""Resilience tests for evaluation/recommender scripts (next sequential wave)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


class TestEvaluateHealthcareSubgroup:
    def test_main_returns_nonzero_on_load_failure(self):
        import scripts.evaluation.evaluate_healthcare_subgroup as mod

        with patch.object(mod, "load_data", side_effect=RuntimeError("db down")):
            result = mod.main()

        assert result == 1


class TestEvaluateFastComparison:
    def test_load_data_re_raises_query_error_and_closes_db(self):
        import scripts.evaluation.evaluate_fast_comparison as mod

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("query failed")):
            with pytest.raises(RuntimeError, match="query failed"):
                mod.load_data()

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_output_save_fails(self):
        import scripts.evaluation.evaluate_fast_comparison as mod

        df = pd.DataFrame(
            {
                "published": pd.to_datetime(["2024-08-01", "2024-09-15", "2024-10-20"]),
                "kev_flag": [0, 1, 0],
                "cvss": [5.0, 9.0, 7.0],
            }
        )

        fake_results = {"NDCG@10": 1.0, "NDCG@20": 1.0, "P@10": 1.0, "P@20": 1.0, "KEV_top20": 1, "KEV_total": 1}

        with patch.object(mod, "load_data", return_value=df), \
             patch.object(mod, "create_splits", return_value=(df, df, df)), \
             patch.object(mod, "extract_old_features", return_value=df.assign(query_id="2024-08")), \
             patch.object(mod, "get_old_features", return_value=["cvss"]), \
             patch.object(mod, "train_fast", return_value=MagicMock()), \
             patch.object(mod, "evaluate", side_effect=[(fake_results, None), (fake_results, None)]), \
             patch.object(mod, "ProductionFeatureEngineer") as mock_engineer, \
             patch("pandas.DataFrame.to_csv", side_effect=OSError("disk full")):
            engineer = MagicMock()
            engineer.extract_features.return_value = df
            engineer.get_feature_columns.return_value = ["cvss"]
            engineer.get_feature_importance_groups.return_value = {"core": ["cvss"]}
            mock_engineer.return_value = engineer

            result = mod.main()

        assert result == 1


class TestRecommendCVEs:
    def test_recommend_from_db_re_raises_query_error_and_closes_db(self):
        import scripts.evaluation.recommend_cves as mod

        fake_recommender = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        fake_recommender.recommend = MagicMock()

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("db timeout")):
            with pytest.raises(RuntimeError, match="db timeout"):
                fake_recommender.recommend_from_db()

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_recommender_init_fails(self):
        import scripts.evaluation.recommend_cves as mod

        with patch.object(mod, "HealthcareCVERecommender", side_effect=RuntimeError("missing model")):
            result = mod.main()

        assert result == 1
