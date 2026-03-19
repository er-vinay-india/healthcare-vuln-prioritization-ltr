"""Resilience tests for SHAP beeswarm generation script."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd


class TestGenerateShapBeeswarm:
    def test_load_feature_names_raises_when_metadata_missing(self, tmp_path):
        import scripts.evaluation.generate_shap_beeswarm as mod

        with patch.object(mod, "PROJECT_ROOT", tmp_path):
            try:
                mod.load_feature_names(tmp_path)
                assert False, "Expected FileNotFoundError"
            except FileNotFoundError:
                assert True

    def test_load_dataset_closes_db_on_query_error(self):
        import scripts.evaluation.generate_shap_beeswarm as mod

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("query failed")):
            try:
                mod.load_dataset(limit=100)
                assert False, "Expected RuntimeError"
            except RuntimeError:
                assert True

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_model_missing(self, tmp_path):
        import scripts.evaluation.generate_shap_beeswarm as mod

        with patch.object(mod, "PROJECT_ROOT", tmp_path), \
             patch("sys.argv", ["generate_shap_beeswarm.py"]):
            result = mod.main()

        assert result == 1

    def test_main_happy_path_returns_zero_and_writes_summary(self, tmp_path):
        import scripts.evaluation.generate_shap_beeswarm as mod

        models_dir = tmp_path / "models"
        outputs_dir = tmp_path / "outputs" / "plots"
        models_dir.mkdir(parents=True, exist_ok=True)
        outputs_dir.mkdir(parents=True, exist_ok=True)

        (models_dir / "ltr_ranker_pruned.model").write_text("dummy", encoding="utf-8")

        raw_df = pd.DataFrame(
            {
                "cve_id": ["CVE-1", "CVE-2"],
                "published": pd.to_datetime(["2024-01-01", "2024-01-02"]),
                "cvss": [9.0, 5.0],
                "description": ["a", "b"],
                "cwe": ["CWE-79", "CWE-89"],
                "kev_flag": [1, 0],
                "epss_score": [0.2, 0.01],
                "epss_percentile": [0.9, 0.4],
                "is_healthcare": [1, 0],
                "is_curated": [1, 0],
                "attack_technique_count": [2, 0],
                "chpl_flag": [1, 0],
                "label": [3, 1],
            }
        )

        feature_names = [
            "kev_flag",
            "epss_score",
            "is_healthcare",
            "cvss",
            "attack_technique_count",
            "epss_high",
            "kev_healthcare",
            "attack_count_x_healthcare",
            "days_since_2018",
        ]

        engineered = raw_df.copy()
        engineered["days_since_2018"] = [1000, 1001]
        engineered["epss_high"] = [1, 0]
        engineered["kev_healthcare"] = [1, 0]
        engineered["attack_count_x_healthcare"] = [2, 0]

        fake_booster = MagicMock()
        fake_shap = pd.DataFrame([[0.1] * len(feature_names), [0.2] * len(feature_names)])

        with patch.object(mod, "PROJECT_ROOT", tmp_path), \
             patch.object(mod, "load_feature_names", return_value=feature_names), \
             patch.object(mod, "load_dataset", return_value=raw_df), \
             patch.object(mod, "ProductionFeatureEngineer") as mock_engineer_cls, \
             patch.object(mod.xgb, "Booster", return_value=fake_booster), \
             patch.object(mod, "save_shap_beeswarm", return_value=fake_shap), \
             patch("sys.argv", ["generate_shap_beeswarm.py"]):
            mock_engineer = MagicMock()
            mock_engineer.extract_features.return_value = engineered
            mock_engineer_cls.return_value = mock_engineer

            result = mod.main()

        assert result == 0
        assert (outputs_dir / "shap_beeswarm_top_features.csv").exists()
