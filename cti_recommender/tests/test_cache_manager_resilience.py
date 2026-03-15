"""Resilience tests for src/utils/cache_manager.py."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


def _make_manager(tmp_path: Path):
    from src.utils.cache_manager import CacheManager
    return CacheManager(cache_root=tmp_path)


def test_get_cache_info_survives_stat_failure(tmp_path):
    """get_cache_info must return partial results even if one source's stat() raises."""
    # Create a fake nvd file so the nvd branch is exercised
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    fake_file = nvd_dir / "nvd_30d.pkl.gz"
    fake_file.write_bytes(b"x")

    cm = _make_manager(tmp_path)

    # Force stat to fail for the nvd glob files
    original_stat = Path.stat

    def broken_stat(self, *args, **kwargs):
        if self == fake_file:
            raise OSError("permission denied")
        return original_stat(self, *args, **kwargs)

    with patch.object(Path, "stat", broken_stat):
        info = cm.get_cache_info()

    # Should still return a dict for all sources without raising
    assert isinstance(info, dict)
    assert "nvd" in info
    # nvd entry should indicate an error state (exists=False)
    assert info["nvd"].get("exists") is False


def test_get_cache_info_returns_all_sources_absent(tmp_path):
    """get_cache_info returns exists=False for all sources when cache dir is empty."""
    cm = _make_manager(tmp_path)
    info = cm.get_cache_info()
    for source in ("nvd", "epss", "kev", "attack", "chpl"):
        assert source in info
        assert info[source]["exists"] is False


def test_clear_specific_cache_handles_unlink_failure(tmp_path):
    """clear_specific_cache must not raise when unlink fails for individual files."""
    # The NVD clear path globs tmp_path (cache_root) for nvd*.pkl.gz
    fake_file = tmp_path / "nvd_test.pkl.gz"
    fake_file.write_bytes(b"data")

    # Also seed the nvd sub-dir so get_cache_info sees it as existing
    nvd_dir = tmp_path / "nvd"
    nvd_dir.mkdir()
    (nvd_dir / "nvd_30d.pkl.gz").write_bytes(b"data")

    cm = _make_manager(tmp_path)

    with patch.object(Path, "unlink", side_effect=OSError("busy")):
        # Should not raise, just log
        result = cm.clear_specific_cache("nvd", confirm=True)

    # Returns True regardless (operation attempted)
    assert result is True


def test_is_cache_stale_returns_true_when_absent(tmp_path):
    """is_cache_stale returns True when no cache exists for a source."""
    cm = _make_manager(tmp_path)
    assert cm.is_cache_stale("kev") is True


def test_get_cache_age_returns_none_when_absent(tmp_path):
    """get_cache_age returns None when no cache exists."""
    cm = _make_manager(tmp_path)
    assert cm.get_cache_age("attack") is None
