"""Resilience tests for evaluation/recommender scripts (next sequential wave)."""
from __future__ import annotations

import pickle
from unittest.mock import MagicMock, patch

import numpy as np
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
    def test_init_loads_model_and_metadata(self, tmp_path):
        import scripts.evaluation.recommend_cves as mod

        model_path = tmp_path / "ltr_ranker.model"
        metadata_path = tmp_path / "ltr_metadata.pkl"
        model_path.write_text("stub", encoding="utf-8")

        metadata = {
            "feature_names": ["cvss", "kev_flag"],
            "training_date": "2026-03-01T00:00:00",
            "metrics": {"ndcg_10": 0.75},
            "scaler": None,
        }
        with metadata_path.open("wb") as f:
            pickle.dump(metadata, f)

        fake_booster = MagicMock()
        fake_booster.feature_names = ["cvss", "kev_flag"]

        with patch.object(mod.xgb, "Booster", return_value=fake_booster), \
             patch.object(mod, "ProductionFeatureEngineer", return_value=MagicMock()):
            rec = mod.HealthcareCVERecommender(model_path=model_path, metadata_path=metadata_path)

        assert rec.feature_names == ["cvss", "kev_flag"]
        fake_booster.load_model.assert_called_once()

    def test_prepare_features_selects_available_feature_set(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.feature_names = ["feature_a", "feature_b"]

        prod = pd.DataFrame({"feature_a": [1.0], "feature_b": [2.0]})
        legacy = pd.DataFrame({"feature_a": [3.0], "feature_b": [4.0]})

        with patch.object(rec, "_prepare_production_features", return_value=prod), \
             patch.object(rec, "_prepare_legacy_features", return_value=legacy):
            result = rec.prepare_features(pd.DataFrame({"dummy": [1]}))

        assert list(result.columns) == ["feature_a", "feature_b"]
        assert float(result.iloc[0]["feature_a"]) == 1.0

    def test_prepare_features_raises_when_feature_missing_in_both_sets(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.feature_names = ["missing_feature"]

        with patch.object(rec, "_prepare_production_features", return_value=pd.DataFrame({"a": [1]})), \
             patch.object(rec, "_prepare_legacy_features", return_value=pd.DataFrame({"b": [2]})):
            with pytest.raises(ValueError, match="Unable to prepare model features"):
                rec.prepare_features(pd.DataFrame({"dummy": [1]}))

    def test_recommend_sorts_by_model_score_desc(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.feature_names = ["cvss"]
        rec.model = MagicMock()
        rec.model.predict.return_value = np.array([0.1, 0.9])

        with patch.object(rec, "prepare_features", return_value=pd.DataFrame({"cvss": [5.0, 9.0]})), \
             patch.object(mod.xgb, "DMatrix", return_value=MagicMock()):
            ranked = rec.recommend(pd.DataFrame({"cve_id": ["CVE-1", "CVE-2"]}), top_k=2)

        assert list(ranked["cve_id"]) == ["CVE-2", "CVE-1"]

    def test_recommend_from_db_returns_empty_when_no_candidates(self):
        import scripts.evaluation.recommend_cves as mod

        fake_recommender = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        fake_recommender.recommend = MagicMock()

        empty_df = pd.DataFrame(columns=["cve_id", "cvss", "published_str"])
        mock_db = MagicMock()

        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", return_value=empty_df):
            result = fake_recommender.recommend_from_db()

        assert result.empty
        mock_db.close.assert_called_once()

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

    def test_prepare_legacy_features_applies_scaler_and_recency(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.scaler = MagicMock()
        rec.scaler.transform.side_effect = lambda arr: arr

        df = pd.DataFrame(
            {
                "kev_flag": [1],
                "epss_score": [0.2],
                "epss_percentile": [0.9],
                "is_healthcare": [1],
                "is_curated": [1],
                "chpl_flag": [1],
                "attack_flag": [1],
                "attack_technique_count": [2],
                "cvss": [9.5],
                "published_str": ["2024-01-01"],
            }
        )

        features = rec._prepare_legacy_features(df)

        assert "cvss_critical" in features.columns
        assert "days_since_2018" in features.columns
        assert int(features.iloc[0]["is_recent"]) in [0, 1]
        rec.scaler.transform.assert_called_once()

    def test_prepare_production_features_adds_missing_columns(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.production_engineer = MagicMock()
        rec.production_engineer.extract_features.return_value = pd.DataFrame({"f1": [1.0]})

        input_df = pd.DataFrame({"published_str": ["2024-02-01"]})
        result = rec._prepare_production_features(input_df)

        assert list(result.columns) == ["f1"]
        called_df = rec.production_engineer.extract_features.call_args[0][0]
        assert "cwe" in called_df.columns
        assert "description" in called_df.columns
        assert "published" in called_df.columns

    def test_prepare_features_uses_engineer_defaults_when_feature_names_empty(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.feature_names = []
        rec.production_engineer = MagicMock()
        rec.production_engineer.get_feature_columns.return_value = ["f1", "f2"]

        prod = pd.DataFrame({"f1": [1.0], "f2": [2.0]})
        legacy = pd.DataFrame({"legacy": [1]})

        with patch.object(rec, "_prepare_production_features", return_value=prod), \
             patch.object(rec, "_prepare_legacy_features", return_value=legacy):
            result = rec.prepare_features(pd.DataFrame({"dummy": [1]}))

        assert rec.feature_names == ["f1", "f2"]
        assert list(result.columns) == ["f1", "f2"]

    def test_recommend_from_db_success_path_calls_recommend(self):
        import scripts.evaluation.recommend_cves as mod

        rec = mod.HealthcareCVERecommender.__new__(mod.HealthcareCVERecommender)
        rec.recommend = MagicMock(return_value=pd.DataFrame({"cve_id": ["CVE-1"]}))

        query_df = pd.DataFrame(
            {
                "cve_id": ["CVE-1", "CVE-2"],
                "cvss": [8.0, 7.2],
                "published_str": ["2024-01-01", "2024-01-02"],
            }
        )
        mock_db = MagicMock()

        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", return_value=query_df):
            result = rec.recommend_from_db(days_back=10, top_k=5, min_cvss=7.0)

        assert list(result["cve_id"]) == ["CVE-1"]
        rec.recommend.assert_called_once()
        mock_db.close.assert_called_once()

    def test_main_returns_zero_on_successful_recommendation(self):
        import scripts.evaluation.recommend_cves as mod

        recommendations = pd.DataFrame(
            {
                "cve_id": ["CVE-1"],
                "cvss": [9.0],
                "model_score": [0.95],
                "kev_flag": [1],
                "is_healthcare": [1],
                "label": [1],
                "published_str": ["2024-01-01"],
            }
        )
        fake_rec = MagicMock()
        fake_rec.recommend_from_db.return_value = recommendations

        with patch.object(mod, "HealthcareCVERecommender", return_value=fake_rec):
            result = mod.main()

        assert result == 0
