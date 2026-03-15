"""Resilience tests for leakage-free evaluation and ablation study scripts."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

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
