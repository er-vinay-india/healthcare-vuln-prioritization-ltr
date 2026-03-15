"""Resilience tests for protocol/evaluation scripts in sequential hardening wave."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest


class TestScientificProtocol:
    def test_main_returns_nonzero_when_features_missing(self):
        import scripts.evaluation.run_scientific_protocol as mod

        with patch.object(mod, "_load_latest_features", return_value=pd.DataFrame({"published": []})), \
             patch("sys.argv", ["run_scientific_protocol.py"]):
            result = mod.main()

        assert result == 1

    def test_prepare_common_columns_adds_expected_fields(self):
        import scripts.evaluation.run_scientific_protocol as mod

        df = pd.DataFrame(
            {
                "published": pd.to_datetime(["2024-01-01", "2024-02-01"], utc=True),
                "cvss": [9.0, None],
                "attack_flag": [1, 0],
                "cvss_severity_category": ["HIGH", "LOW"],
                "cwe_category": ["injection", "other"],
                "curated_severity": ["critical", "medium"],
            }
        )

        out = mod._prepare_common_columns(df)

        assert "cvss_norm" in out.columns
        assert "recency_score" in out.columns
        assert "soft_label" in out.columns
        assert "label_confidence" in out.columns
        assert list(out["has_attack"]) == [1, 0]
        assert float(out.iloc[1]["cvss"]) == 5.0

    def test_split_helpers_create_expected_shapes(self):
        import scripts.evaluation.run_scientific_protocol as mod

        df = pd.DataFrame(
            {
                "published": pd.date_range("2024-01-01", periods=20, tz="UTC"),
                "soft_label": [0] * 20,
            }
        )

        temporal = mod._split_complete_temporal(df)
        assert len(temporal.train_df) == 14
        assert len(temporal.val_df) == 3
        assert len(temporal.test_df) == 3

        year = mod._split_year_based(df, "2024-01-10")
        assert not year.train_df.empty
        assert not year.val_df.empty
        assert not year.test_df.empty

    def test_search_confidence_scale_returns_best_scale(self):
        import scripts.evaluation.run_scientific_protocol as mod

        train_df = pd.DataFrame(
            {
                "f1": [0.1, 0.2, 0.3],
                "soft_label": [0, 1, 1],
                "label_confidence": [0.2, 0.4, 0.6],
            }
        )
        val_df = pd.DataFrame(
            {
                "f1": [0.1, 0.2, 0.3],
                "soft_label": [0, 1, 1],
                "label_confidence": [0.2, 0.4, 0.6],
            }
        )

        class _FakeModel:
            def __init__(self, preds):
                self._preds = preds

            def predict(self, _x):
                return self._preds

        models = [
            _FakeModel(np.array([0.1, 0.2, 0.3])),
            _FakeModel(np.array([0.2, 0.6, 0.7])),
            _FakeModel(np.array([0.4, 0.5, 0.6])),
            _FakeModel(np.array([0.3, 0.4, 0.5])),
        ]

        with patch.object(mod, "train_lambdarank", side_effect=models):
            best_scale, search_df, best_model = mod._search_confidence_scale(
                train_df, val_df, ["f1"], params={"dummy": True}
            )

        assert best_scale in [0.5, 1.0, 1.5, 2.0]
        assert len(search_df) == 4
        assert best_model is not None

    def test_write_report_and_split_summary_emit_content(self, tmp_path):
        import scripts.evaluation.run_scientific_protocol as mod

        split = mod.SplitBundle(
            name="demo",
            train_df=pd.DataFrame({"published": pd.to_datetime(["2024-01-01"], utc=True), "soft_label": [2]}),
            val_df=pd.DataFrame({"published": pd.to_datetime(["2024-01-02"], utc=True), "soft_label": [1]}),
            test_df=pd.DataFrame({"published": pd.to_datetime(["2024-01-03"], utc=True), "soft_label": [0]}),
        )

        summary = mod._build_split_summary([split])
        assert len(summary) == 3

        final_df = pd.DataFrame(
            [
                {"split": "demo", "model": "LambdaMART", "metric": "NDCG@10", "value": 0.7},
                {"split": "demo", "model": "CVSS", "metric": "NDCG@10", "value": 0.5},
            ]
        )
        report_path = tmp_path / "report.md"
        mod._write_report(final_df, summary, report_path)

        content = report_path.read_text(encoding="utf-8")
        assert "Scientific Protocol Report" in content
        assert "split_summary.csv" in content

    def test_main_happy_path_writes_manifest_and_returns_zero(self, tmp_path):
        import scripts.evaluation.run_scientific_protocol as mod

        df = pd.DataFrame(
            {
                "published": pd.to_datetime(["2024-01-01", "2024-06-01", "2024-10-01"], utc=True),
                "soft_label": [0, 1, 2],
                "label_confidence": [0.2, 0.4, 0.8],
                "kev_flag": [0, 1, 1],
                "epss_score": [0.1, 0.5, 0.9],
            }
        )
        split = mod.SplitBundle(name="unit", train_df=df.iloc[:1], val_df=df.iloc[1:2], test_df=df.iloc[2:3])

        fake_eval = pd.DataFrame(
            [
                {
                    "split": "unit",
                    "model": "LambdaMART",
                    "metric": "NDCG@10",
                    "value": 0.8,
                    "best_confidence_scale": 1.0,
                }
            ]
        )

        with patch.object(mod, "PROJECT_ROOT", tmp_path), \
             patch.object(mod, "_load_latest_features", return_value=df), \
             patch.object(mod, "_prepare_common_columns", return_value=df), \
             patch.object(mod, "_split_complete_temporal", return_value=split), \
             patch.object(mod, "_split_year_based", return_value=split), \
             patch.object(mod, "_evaluate_split", return_value=fake_eval), \
             patch.object(mod, "_write_report", return_value=None), \
             patch("sys.argv", ["run_scientific_protocol.py", "--features-dir", "unused", "--output-dir", "out"]):
            result = mod.main()

        assert result == 0
        manifest = tmp_path / "out" / "manifest.json"
        assert manifest.exists()


class TestEvaluateProductionImproved:
    def test_load_data_from_db_re_raises_and_closes_db(self):
        import scripts.evaluation.evaluate_production_improved as mod

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("query failed")):
            with pytest.raises(RuntimeError, match="query failed"):
                mod.load_data_from_db()

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_load_fails(self):
        import scripts.evaluation.evaluate_production_improved as mod

        with patch.object(mod, "load_data_from_db", side_effect=RuntimeError("db offline")):
            result = mod.main()

        assert result == 1

    def test_main_returns_nonzero_when_output_write_fails(self):
        import scripts.evaluation.evaluate_production_improved as mod

        base_df = pd.DataFrame(
            {
                "cve_id": ["CVE-1", "CVE-2", "CVE-3"],
                "published": pd.to_datetime(["2024-01-01", "2024-08-15", "2024-10-20"]),
                "cvss": [5.0, 8.0, 9.0],
                "kev_flag": [0, 1, 1],
                "temporal_label": [0, 1, 1],
            }
        )

        fake_results_old = {
            "NDCG@5": 0.5,
            "NDCG@10": 0.5,
            "NDCG@20": 0.5,
            "P@10": 0.5,
            "P@20": 0.5,
            "P@50": 0.5,
            "KEV_captured_top20": 1,
            "KEV_total": 2,
        }
        fake_results_new = {
            "NDCG@5": 0.6,
            "NDCG@10": 0.6,
            "NDCG@20": 0.6,
            "P@10": 0.6,
            "P@20": 0.6,
            "P@50": 0.6,
            "KEV_captured_top20": 2,
            "KEV_total": 2,
        }

        with patch.object(mod, "load_data_from_db", return_value=base_df), \
             patch.object(mod, "prepare_labels_and_splits", return_value=(base_df, base_df, base_df)), \
             patch.object(mod, "extract_old_production_features", return_value=(base_df, base_df, base_df, ["cvss"])), \
             patch.object(mod, "extract_new_production_features", return_value=(base_df, base_df, base_df, ["cvss"])), \
             patch.object(mod, "train_model", return_value=MagicMock()), \
             patch.object(mod, "evaluate_model", side_effect=[(fake_results_old, [0.1, 0.2, 0.3]), (fake_results_new, [0.3, 0.4, 0.5])]), \
             patch.object(mod, "run_ablation_study", return_value={"CVSS Only": 0.5}), \
             patch("pandas.DataFrame.to_csv", side_effect=OSError("disk full")):
            result = mod.main()

        assert result == 1
