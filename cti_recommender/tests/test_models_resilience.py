"""Deterministic model-module coverage tests."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest


class TestBaselines:
    def test_compute_cvss_only_scores_fills_missing(self):
        from src.models.baselines import compute_cvss_only_scores

        df = pd.DataFrame({"cvss_norm": [0.9, np.nan]})
        scores = compute_cvss_only_scores(df)

        assert np.allclose(scores, np.array([0.9, 0.5]))

    def test_compute_heuristic_scores_uses_defaults_for_optional_columns(self):
        from src.models.baselines import compute_heuristic_scores

        df = pd.DataFrame(
            {
                "cvss_norm": [1.0],
                "epss_score": [0.2],
                "kev_flag": [1],
            }
        )
        score = compute_heuristic_scores(df)

        expected = 0.35 * 1.0 + 0.30 * 0.2 + 0.20 * 1 + 0.10 * 0.5 + 0.05 * 0
        assert np.allclose(score, np.array([expected]))

    def test_compute_legacy_label_scores_supports_fallback_and_error(self):
        from src.models.baselines import compute_legacy_label_scores

        df_with_soft = pd.DataFrame({"soft_label": [2, np.nan]})
        assert np.allclose(compute_legacy_label_scores(df_with_soft), np.array([2.0, 0.0]))

        df_with_label = pd.DataFrame({"label": [1, np.nan]})
        assert np.allclose(compute_legacy_label_scores(df_with_label), np.array([1.0, 0.0]))

        with pytest.raises(ValueError, match="Column 'soft_label' not found"):
            compute_legacy_label_scores(pd.DataFrame({"x": [1]}))

    def test_compute_epss_only_scores_fills_missing(self):
        from src.models.baselines import compute_epss_only_scores

        df = pd.DataFrame({"epss_score": [0.7, np.nan]})
        series = compute_epss_only_scores(df)

        assert np.allclose(series.values, np.array([0.7, 0.0]))


class TestBootstrapEnsemble:
    def test_train_predict_and_risk_aware_paths(self):
        from src.models.bootstrap_ensemble import BootstrapEnsemble

        train_df = pd.DataFrame(
            {
                "published_week": ["2024-W01", "2024-W01", "2024-W02", "2024-W02"],
                "f1": [0.1, 0.2, 0.3, 0.4],
            }
        )

        fake_model_1 = MagicMock()
        fake_model_1.predict.return_value = np.array([0.2, 0.6])
        fake_model_2 = MagicMock()
        fake_model_2.predict.return_value = np.array([0.4, 0.8])

        train_returns = [fake_model_1, fake_model_2]

        def prep_ranking_data(df, feature_cols):
            return df[feature_cols].values, np.array([0] * len(df)), np.array([1.0] * len(df)), [len(df)], df

        with patch("src.models.bootstrap_ensemble.lgb.Dataset", return_value=MagicMock()), \
             patch("src.models.bootstrap_ensemble.lgb.train", side_effect=train_returns), \
             patch("numpy.random.choice", side_effect=lambda groups, size, replace: np.array(list(groups)[:size])):
            ensemble = BootstrapEnsemble(K=2, seed=7)
            stats = ensemble.train(train_df, ["f1"], prep_ranking_data, verbose=False)

            pred_df = pd.DataFrame({"f1": [0.5, 0.9]})
            mean_scores, std_scores = ensemble.predict(pred_df, ["f1"])
            risk_scores = ensemble.predict_risk_aware(pred_df, ["f1"], lambda_val=0.25)

        assert stats["num_models"] == 2
        assert np.allclose(mean_scores, np.array([0.3, 0.7]))
        assert np.allclose(std_scores, np.array([0.1, 0.1]))
        assert np.allclose(risk_scores, np.array([0.275, 0.675]))


class TestLTRHelpers:
    def test_diagnose_feature_matrix_reports_and_validates(self):
        from src.models.ltr import diagnose_feature_matrix

        df = pd.DataFrame({"f_zero": [0, 0, 0], "f_sparse": [0, 0, 1], "f_dense": [1, 2, 3]})
        out = diagnose_feature_matrix(df, ["f_zero", "f_sparse", "f_dense"], label="unit")

        assert "f_zero" in out["zero_variance"]
        assert "f_sparse" not in out["mostly_zero"]

        with pytest.raises(KeyError, match="Missing feature columns"):
            diagnose_feature_matrix(df, ["missing"], label="unit")

    def test_coerce_pair_to_numeric_handles_strings_and_categories(self):
        from src.models.ltr import _coerce_pair_to_numeric

        train_df = pd.DataFrame({"num_like": ["1", "2"], "cat": ["a", "b"]})
        val_df = pd.DataFrame({"num_like": ["3", "4"], "cat": ["b", "c"]})

        t_out, v_out = _coerce_pair_to_numeric(train_df, val_df, ["num_like", "cat"])

        assert pd.api.types.is_numeric_dtype(t_out["num_like"])
        assert pd.api.types.is_numeric_dtype(t_out["cat"])
        assert pd.api.types.is_numeric_dtype(v_out["cat"])

    def test_prepare_ranking_data_sorts_and_groups(self):
        from src.models.ltr import prepare_ranking_data

        df = pd.DataFrame(
            {
                "published_week": ["W2", "W1", "W1"],
                "soft_label": [0, 2, 1],
                "label_confidence": [0.1, 0.9, 0.5],
                "f1": [3.0, 1.0, 2.0],
            }
        )

        X, y, w, groups, sorted_df = prepare_ranking_data(df, ["f1"])

        assert groups == [2, 1]
        assert list(sorted_df["soft_label"]) == [2, 1, 0]
        assert len(X) == len(y) == len(w) == 3

    def test_train_lambdarank_returns_model_with_mocked_lightgbm(self):
        from src.models.ltr import train_lambdarank

        train_df = pd.DataFrame(
            {
                "published_week": ["W1", "W1", "W2"],
                "soft_label": [2, 1, 0],
                "label_confidence": [0.9, 0.6, 0.2],
                "f1": ["1", "2", "3"],
            }
        )
        val_df = pd.DataFrame(
            {
                "published_week": ["W3", "W3"],
                "soft_label": [1, 0],
                "label_confidence": [0.5, 0.3],
                "f1": ["4", "5"],
            }
        )

        fake_model = MagicMock()
        fake_model.best_iteration = 12
        fake_model.best_score = {"valid": {"ndcg@10": 0.77}}

        with patch("src.models.ltr.lgb.Dataset", return_value=MagicMock()), \
             patch("src.models.ltr.lgb.early_stopping", return_value=MagicMock()), \
             patch("src.models.ltr.lgb.log_evaluation", return_value=MagicMock()), \
             patch("src.models.ltr.lgb.train", return_value=fake_model):
            model = train_lambdarank(train_df, val_df, ["f1"], params={"num_leaves": 7}, random_seed=1)

        assert model is fake_model

    def test_save_load_and_default_params(self):
        from src.models.ltr import get_default_ltr_params, load_model, save_model

        fake_model = MagicMock()
        save_model(fake_model, "dummy.model")
        fake_model.save_model.assert_called_once_with("dummy.model")

        with patch("src.models.ltr.lgb.Booster", return_value=MagicMock()) as booster_ctor:
            loaded = load_model("dummy.model")

        assert loaded is not None
        booster_ctor.assert_called_once_with(model_file="dummy.model")

        params = get_default_ltr_params()
        assert params["objective"] == "lambdarank"
        assert "ndcg_eval_at" in params
