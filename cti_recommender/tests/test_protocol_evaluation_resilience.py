"""Resilience tests for protocol/evaluation scripts in sequential hardening wave."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


class TestScientificProtocol:
    def test_main_returns_nonzero_when_features_missing(self):
        import scripts.run_scientific_protocol as mod

        with patch.object(mod, "_load_latest_features", return_value=pd.DataFrame({"published": []})), \
             patch("sys.argv", ["run_scientific_protocol.py"]):
            result = mod.main()

        assert result == 1


class TestEvaluateProductionImproved:
    def test_load_data_from_db_re_raises_and_closes_db(self):
        import scripts.evaluate_production_improved as mod

        mock_db = MagicMock()
        with patch.object(mod, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("query failed")):
            with pytest.raises(RuntimeError, match="query failed"):
                mod.load_data_from_db()

        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_when_load_fails(self):
        import scripts.evaluate_production_improved as mod

        with patch.object(mod, "load_data_from_db", side_effect=RuntimeError("db offline")):
            result = mod.main()

        assert result == 1

    def test_main_returns_nonzero_when_output_write_fails(self):
        import scripts.evaluate_production_improved as mod

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
