"""Resilience tests for healthcare_osint.py cache layer and api/main.py prepare_features."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pandas as pd
import pytest


# ---------------------------------------------------------------------------
# healthcare_osint – _save_cache
# ---------------------------------------------------------------------------

def test_save_cache_does_not_raise_on_write_failure():
    """_save_cache must silently log and continue on write errors."""
    from src.core.healthcare_osint import _save_cache

    df = pd.DataFrame([{"advisory_id": "ICSA-24-001-01"}])
    with patch("pandas.DataFrame.to_pickle", side_effect=OSError("disk full")):
        # Must not propagate the exception
        _save_cache(df, "cisa_ics_advisories")


def test_get_cisa_ics_cached_returns_empty_on_fetch_failure():
    """get_cisa_ics_cached must return an empty DataFrame when the live fetch fails and cache is absent."""
    from src.core.healthcare_osint import get_cisa_ics_cached

    with patch("src.core.healthcare_osint._is_valid", return_value=False), \
         patch("src.core.healthcare_osint.fetch_cisa_ics_advisories", return_value=pd.DataFrame()), \
         patch("src.core.healthcare_osint._save_cache"):
        result = get_cisa_ics_cached()
        assert isinstance(result, pd.DataFrame)


def test_get_openfda_enforcement_cached_returns_df_on_stale_cache():
    """get_openfda_enforcement_cached must fall through to the live fetch when cache is stale."""
    from src.core.healthcare_osint import get_openfda_enforcement_cached

    expected = pd.DataFrame([{"product_description": "infusion pump"}])
    with patch("src.core.healthcare_osint._is_valid", return_value=False), \
         patch("src.core.healthcare_osint.fetch_openfda_device_enforcement", return_value=expected), \
         patch("src.core.healthcare_osint._save_cache"):
        result = get_openfda_enforcement_cached()
        assert len(result) == 1


# ---------------------------------------------------------------------------
# api/main.py – prepare_features
# ---------------------------------------------------------------------------

def test_prepare_features_raises_value_error_on_unknown_schema():
    """prepare_features raises ValueError when feature_names cannot be satisfied."""
    from src.api.main import prepare_features

    df = pd.DataFrame([{
        "cve_id": "CVE-2024-9999",
        "cvss": 7.5,
        "published_str": "2024-01-01",
        "kev_flag": 1,
        "epss_score": 0.05,
        "epss_percentile": 0.5,
        "is_healthcare": 1,
        "is_curated": 0,
        "chpl_flag": 0,
        "attack_flag": 0,
        "attack_technique_count": 0,
        "cwe": "CWE-79",
        "description": "test",
    }])

    with pytest.raises(ValueError, match="Unable to prepare expected model features"):
        prepare_features(df, feature_names=["nonexistent_feature_xyz"])


def test_prepare_features_succeeds_with_no_feature_names():
    """prepare_features returns a non-empty DataFrame when feature_names is None."""
    from src.api.main import prepare_features

    df = pd.DataFrame([{
        "cve_id": "CVE-2024-9999",
        "cvss": 7.5,
        "published": "2024-01-01",
        "published_str": "2024-01-01",
        "kev_flag": 1,
        "epss_score": 0.05,
        "epss_percentile": 0.5,
        "is_healthcare": 1,
        "is_curated": 0,
        "chpl_flag": 0,
        "attack_flag": 0,
        "attack_technique_count": 0,
        "cwe": "CWE-79",
        "description": "A test vulnerability",
    }])

    result = prepare_features(df, feature_names=None)
    assert not result.empty
    assert result.shape[0] == 1
