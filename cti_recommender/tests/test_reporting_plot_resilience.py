"""Resilience tests for report and CVSS temporal plot scripts."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


class TestGenerateReport:
    def test_main_returns_nonzero_when_create_report_fails(self):
        import scripts.evaluation.generate_report as mod

        with patch.object(mod, "create_report", side_effect=RuntimeError("save failed")):
            result = mod.main()

        assert result == 1


class TestGenerateCvssTemporalPlot:
    def test_load_data_re_raises_and_closes_connection(self):
        import scripts.evaluation.generate_cvss_temporal_plot as mod

        mock_conn = MagicMock()
        with patch("sqlite3.connect", return_value=mock_conn), \
             patch("pandas.read_sql_query", side_effect=RuntimeError("db error")):
            with pytest.raises(RuntimeError, match="db error"):
                mod.load_cvss_temporal_data()

        mock_conn.close.assert_called_once()

    def test_main_returns_nonzero_when_data_load_fails(self):
        import scripts.evaluation.generate_cvss_temporal_plot as mod

        with patch.object(mod, "load_cvss_temporal_data", side_effect=RuntimeError("broken")):
            result = mod.main()

        assert result == 1

    def test_main_returns_nonzero_for_empty_dataset(self):
        import scripts.evaluation.generate_cvss_temporal_plot as mod

        empty_df = pd.DataFrame(columns=["year", "total_cves", "avg_cvss"])
        with patch.object(mod, "load_cvss_temporal_data", return_value=empty_df):
            result = mod.main()

        assert result == 1
