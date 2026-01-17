"""Unit tests for configuration module"""
import pytest
from pathlib import Path
from config.settings import Settings


def test_settings_initialization():
    """Test settings can be initialized with defaults"""
    settings = Settings()
    assert settings.PROJECT_ROOT.exists()
    assert settings.LOG_LEVEL in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]


def test_database_path_resolution():
    """Test database path resolution"""
    settings = Settings()
    db_path = settings.get_database_path()
    assert isinstance(db_path, Path)
    assert str(db_path).endswith("cve_database.db")


def test_cache_dir_resolution():
    """Test cache directory resolution"""
    settings = Settings()
    cache_dir = settings.get_cache_dir()
    assert isinstance(cache_dir, Path)


def test_model_path_resolution():
    """Test model path resolution"""
    settings = Settings()
    
    # Original model
    model_path = settings.get_model_path(pruned=False)
    assert str(model_path).endswith("ltr_ranker.model")
    
    # Pruned model
    pruned_path = settings.get_model_path(pruned=True)
    assert str(pruned_path).endswith("ltr_ranker_pruned.model")


def test_nvd_rate_limit_with_key():
    """Test NVD rate limit calculation with API key"""
    settings = Settings(NVD_API_KEY="test_key")
    rate_limit = settings.get_nvd_rate_limit()
    assert rate_limit == settings.NVD_RATE_LIMIT_WITH_KEY


def test_nvd_rate_limit_without_key():
    """Test NVD rate limit calculation without API key"""
    settings = Settings(NVD_API_KEY=None)
    rate_limit = settings.get_nvd_rate_limit()
    assert rate_limit == settings.NVD_RATE_LIMIT_NO_KEY


def test_ensure_directories(tmp_path):
    """Test directory creation"""
    settings = Settings(
        DATABASE_PATH=tmp_path / "test_data" / "test.db",
        CACHE_DIR=tmp_path / "test_cache",
        LOG_DIR=tmp_path / "test_logs"
    )
    
    settings.ensure_directories()
    
    assert (tmp_path / "test_data").exists()
    assert (tmp_path / "test_cache").exists()
    assert (tmp_path / "test_logs").exists()


def test_xgboost_hyperparameters():
    """Test XGBoost hyperparameters are properly set"""
    settings = Settings()
    assert 0 < settings.XGBOOST_ETA <= 1
    assert settings.XGBOOST_MAX_DEPTH > 0
    assert settings.XGBOOST_MIN_CHILD_WEIGHT > 0
    assert 0 < settings.XGBOOST_SUBSAMPLE <= 1
    assert 0 < settings.XGBOOST_COLSAMPLE_BYTREE <= 1


def test_feature_thresholds():
    """Test feature engineering thresholds"""
    settings = Settings()
    assert 0 <= settings.CVSS_CRITICAL_THRESHOLD <= 10
    assert 0 <= settings.EPSS_HIGH_THRESHOLD <= 1
    assert 0 <= settings.EPSS_VERY_HIGH_THRESHOLD <= 1


def test_validation_ranges():
    """Test validation ranges"""
    settings = Settings()
    assert settings.MIN_CVSS_SCORE == 0.0
    assert settings.MAX_CVSS_SCORE == 10.0
    assert settings.MIN_EPSS_SCORE == 0.0
    assert settings.MAX_EPSS_SCORE == 1.0
    assert settings.VALID_LABEL_VALUES == (0, 1, 2, 3, 4, 5)
