"""Resilience tests for src/core/cve_database.py and src/core/cti_recommender.py."""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


# ---------------------------------------------------------------------------
# CVEDatabase
# ---------------------------------------------------------------------------

def _make_db(tmp_path: Path):
    """Return a CVEDatabase backed by a temp file."""
    from src.core.cve_database import CVEDatabase
    return CVEDatabase(db_path=tmp_path / "test.db")


def test_upsert_enrichments_rolls_back_on_commit_failure(tmp_path):
    db = _make_db(tmp_path)
    enr_df = pd.DataFrame([{"cve_id": "CVE-2024-9999", "kev_flag": 1}])

    mock_conn = MagicMock()
    mock_conn.commit.side_effect = Exception("disk full")
    db.conn = mock_conn

    with pytest.raises(Exception, match="disk full"):
        db.upsert_enrichments(enr_df)

    assert mock_conn.rollback.called


def test_log_fetch_does_not_raise_on_commit_failure(tmp_path):
    """log_fetch must catch its own commit failure rather than propagating it."""
    db = _make_db(tmp_path)

    mock_conn = MagicMock()
    mock_conn.commit.side_effect = Exception("io error")
    db.conn = mock_conn

    # Should not raise; the exception is caught and logged
    db.log_fetch("2024-01-01", "2024-01-02", 0, status="success")
    assert mock_conn.rollback.called


def test_query_cves_raises_on_read_failure(tmp_path):
    db = _make_db(tmp_path)
    with patch("pandas.read_sql_query", side_effect=RuntimeError("query failed")):
        with pytest.raises(RuntimeError, match="query failed"):
            db.query_cves(limit=5)
    db.close()


def test_upsert_cves_rolls_back_and_raises_on_commit_failure(tmp_path):
    db = _make_db(tmp_path)
    df = pd.DataFrame([{"cve_id": "CVE-2024-0001", "published": "2024-01-01", "description": "x"}])

    mock_conn = MagicMock()
    mock_conn.commit.side_effect = Exception("commit err")
    db.conn = mock_conn

    with pytest.raises(Exception, match="commit err"):
        db.upsert_cves(df)

    assert mock_conn.rollback.called


# ---------------------------------------------------------------------------
# cti_recommender
# ---------------------------------------------------------------------------

def test_save_cache_does_not_raise_on_write_failure(tmp_path):
    """save_cache must swallow write failures gracefully."""
    from src.core.cti_recommender import save_cache
    df = pd.DataFrame([{"a": 1}])
    with patch("pandas.DataFrame.to_pickle", side_effect=OSError("no space")):
        # Must not raise
        save_cache(df, "test_key")


def test_fetch_nvd_date_range_raises_on_request_error():
    """fetch_nvd_date_range must re-raise RequestException after logging it."""
    import requests
    from src.core.cti_recommender import fetch_nvd_date_range

    with patch("src.core.cti_recommender._requests_session") as mock_sess_cls:
        session = MagicMock()
        session.get.side_effect = requests.exceptions.ConnectionError("timeout")
        mock_sess_cls.return_value = session

        with pytest.raises(requests.exceptions.ConnectionError):
            fetch_nvd_date_range("2024-01-01", "2024-01-02", session=session)
