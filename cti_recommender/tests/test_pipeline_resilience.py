from unittest.mock import MagicMock, patch

import pytest


def test_refresh_cves_raises_and_closes_db_on_fetch_failure():
    from scripts.refresh_cves import refresh_cves

    with patch("scripts.refresh_cves.CVEDatabase") as mock_db_cls, patch(
        "scripts.refresh_cves.cti_recommender.fetch_nvd_date_range"
    ) as mock_fetch:
        db = MagicMock()
        db.get_last_fetch_date.return_value = None
        mock_db_cls.return_value = db
        mock_fetch.side_effect = RuntimeError("nvd unavailable")

        with pytest.raises(RuntimeError, match="nvd unavailable"):
            refresh_cves(api_key="x", days_back=1)

        assert db.log_fetch.called
        assert db.close.called


def test_fetch_healthcare_osint_main_returns_nonzero_on_failure():
    from scripts.fetch_healthcare_osint import main

    with patch("scripts.fetch_healthcare_osint.get_cisa_ics_cached") as mock_ics:
        mock_ics.side_effect = RuntimeError("ics down")
        assert main() == 1


def test_update_is_healthcare_flags_rolls_back_on_failure():
    from scripts.update_is_healthcare_flags import main

    conn = MagicMock()
    conn.execute.return_value.fetchone.return_value = 0

    with patch("scripts.update_is_healthcare_flags.sqlite3.connect", return_value=conn), patch(
        "scripts.update_is_healthcare_flags.settings", new=MagicMock(get_database_path=MagicMock(return_value="/tmp/fake.db"))
    ), patch("scripts.update_is_healthcare_flags.pd.read_sql", side_effect=RuntimeError("read failed")):
        assert main() == 1
        assert conn.rollback.called
        assert conn.close.called


def test_backfill_by_month_returns_failure_code_when_month_fetch_fails():
    from scripts.backfill_cves import backfill_by_month

    with patch("scripts.backfill_cves.CVEDatabase") as mock_db_cls, patch(
        "scripts.backfill_cves.cti_recommender.fetch_nvd_date_range"
    ) as mock_fetch:
        db = MagicMock()
        mock_db_cls.return_value = db
        mock_fetch.side_effect = RuntimeError("month fetch failed")

        code = backfill_by_month(2025, 2025, api_key="x")

        assert code == 1
        assert db.log_fetch.called
        assert db.close.called
