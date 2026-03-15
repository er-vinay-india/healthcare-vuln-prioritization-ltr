"""Resilience tests for DB status and enrichment monitor scripts."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestCheckDbStatus:
    def test_main_returns_nonzero_when_status_check_fails(self):
        import scripts.check_db_status as mod

        with patch.object(mod, "check_db_status", side_effect=RuntimeError("query fail")):
            result = mod.main()

        assert result == 1

    def test_check_db_status_closes_db_on_failure(self):
        import scripts.check_db_status as mod

        mock_cursor = MagicMock()
        mock_cursor.execute.side_effect = RuntimeError("sql error")
        mock_db = MagicMock()
        mock_db.conn.cursor.return_value = mock_cursor

        with patch.object(mod, "CVEDatabase", return_value=mock_db):
            with pytest.raises(RuntimeError, match="sql error"):
                mod.check_db_status()

        mock_db.close.assert_called_once()


class TestMonitorEnrichment:
    def test_main_returns_nonzero_when_monitor_raises(self):
        import scripts.monitor_enrichment as mod

        with patch.object(mod, "monitor_enrichment", side_effect=RuntimeError("db down")):
            with patch("sys.argv", ["monitor_enrichment.py"]):
                result = mod.main()

        assert result == 1

    def test_monitor_closes_db_on_query_failure(self):
        import scripts.monitor_enrichment as mod

        mock_conn = MagicMock()
        mock_conn.execute.side_effect = RuntimeError("stats query failed")
        mock_db = MagicMock()
        mock_db.conn = mock_conn

        with patch.object(mod, "CVEDatabase", return_value=mock_db):
            with pytest.raises(RuntimeError, match="stats query failed"):
                mod.monitor_enrichment(watch_mode=False, interval=1)

        mock_db.close.assert_called_once()
