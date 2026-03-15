"""Resilience tests for enrich/backfill script entrypoints."""
from __future__ import annotations

from unittest.mock import patch


def test_enrich_main_returns_nonzero_on_enrich_failure():
    import scripts.data.enrich_cves as mod

    with patch.object(mod, "enrich_database", side_effect=RuntimeError("boom")), \
         patch("sys.argv", ["enrich_cves.py"]):
        assert mod.main() == 1


def test_enrich_main_validate_only_returns_nonzero_on_db_failure():
    import scripts.data.enrich_cves as mod

    with patch.object(mod, "CVEDatabase", side_effect=RuntimeError("db init failed")), \
         patch("sys.argv", ["enrich_cves.py", "--validate-only"]):
        assert mod.main() == 1


def test_backfill_main_returns_nonzero_when_runner_raises():
    import scripts.data.backfill_cves as mod

    with patch.object(mod, "backfill_by_month", side_effect=RuntimeError("nvd down")):
        assert mod.main() == 1
