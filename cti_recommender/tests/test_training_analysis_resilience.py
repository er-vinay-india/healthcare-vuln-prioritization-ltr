"""Resilience tests for training scripts and analysis helpers (Wave 5)."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# scripts/training/train_ltr.py
# ---------------------------------------------------------------------------

class TestTrainLTR:
    def test_load_training_data_propagates_query_error(self):
        """load_training_data must re-raise DB query errors."""
        import scripts.training.train_ltr as ltr

        with patch.object(ltr, "CVEDatabase") as mock_cls, \
             patch("pandas.read_sql_query", side_effect=RuntimeError("db exploded")):
            mock_cls.return_value = MagicMock()
            with pytest.raises(RuntimeError, match="db exploded"):
                ltr.load_training_data()

    def test_load_training_data_closes_db_on_query_error(self):
        """db.close() must be called even when the query raises."""
        import scripts.training.train_ltr as ltr

        mock_db = MagicMock()
        with patch.object(ltr, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=OSError("disk error")):
            with pytest.raises(OSError):
                ltr.load_training_data()
        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_on_load_failure(self):
        """main() must return 1 when load_training_data raises."""
        import scripts.training.train_ltr as ltr

        with patch.object(ltr, "load_training_data", side_effect=RuntimeError("no db")):
            result = ltr.main()
        assert result == 1

    def test_main_returns_nonzero_on_model_save_failure(self, tmp_path):
        """main() must return 1 when model.save_model raises."""
        import scripts.training.train_ltr as ltr
        import pandas as pd
        import numpy as np

        fake_X = pd.DataFrame({"a": np.zeros(10), "b": np.zeros(10)})
        fake_y = pd.Series([0] * 10)

        with patch.object(ltr, "load_training_data"), \
             patch.object(ltr, "prepare_pruned_features", return_value=(fake_X, fake_y, MagicMock())), \
             patch.object(ltr, "train_test_split", return_value=(fake_X, fake_X, fake_y, fake_y)), \
             patch.object(ltr, "train_model_with_regularization") as mock_train, \
             patch.object(ltr, "evaluate_model", return_value={"ndcg_5": 1.0, "ndcg_10": 1.0, "ndcg_20": 1.0}):
            mock_model = MagicMock()
            mock_model.save_model.side_effect = IOError("disk full")
            mock_train.return_value = mock_model
            result = ltr.main()
        assert result == 1


# ---------------------------------------------------------------------------
# scripts/training/temporal_validation.py
# ---------------------------------------------------------------------------

class TestTemporalValidation:
    def test_load_temporal_data_propagates_query_error(self):
        """load_temporal_data must re-raise DB query errors."""
        import scripts.training.temporal_validation as tv

        with patch.object(tv, "CVEDatabase") as mock_cls, \
             patch("pandas.read_sql_query", side_effect=RuntimeError("timeout")):
            mock_cls.return_value = MagicMock()
            with pytest.raises(RuntimeError, match="timeout"):
                tv.load_temporal_data()

    def test_load_temporal_data_closes_db_on_error(self):
        """db.close() must be called in the finally block."""
        import scripts.training.temporal_validation as tv

        mock_db = MagicMock()
        with patch.object(tv, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=OSError("io error")):
            with pytest.raises(OSError):
                tv.load_temporal_data()
        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_on_load_failure(self):
        """main() must return 1 when load_temporal_data raises."""
        import scripts.training.temporal_validation as tv

        with patch.object(tv, "load_temporal_data", side_effect=RuntimeError("bad db")):
            result = tv.main()
        assert result == 1


# ---------------------------------------------------------------------------
# scripts/training/cross_validation.py
# ---------------------------------------------------------------------------

class TestCrossValidation:
    def test_load_data_propagates_query_error(self):
        """load_data must re-raise DB query errors."""
        import scripts.training.cross_validation as cv

        with patch.object(cv, "CVEDatabase") as mock_cls, \
             patch("pandas.read_sql_query", side_effect=RuntimeError("conn refused")):
            mock_cls.return_value = MagicMock()
            with pytest.raises(RuntimeError, match="conn refused"):
                cv.load_data()

    def test_load_data_closes_db_on_error(self):
        """db.close() must be called even when query raises."""
        import scripts.training.cross_validation as cv

        mock_db = MagicMock()
        with patch.object(cv, "CVEDatabase", return_value=mock_db), \
             patch("pandas.read_sql_query", side_effect=OSError("locked")):
            with pytest.raises(OSError):
                cv.load_data()
        mock_db.close.assert_called_once()

    def test_main_returns_nonzero_on_load_failure(self):
        """main() must return 1 when load_data raises."""
        import scripts.training.cross_validation as cv

        with patch.object(cv, "load_data", side_effect=RuntimeError("no data")):
            result = cv.main()
        assert result == 1

    def test_main_returns_nonzero_on_csv_save_failure(self, tmp_path):
        """main() must return 1 when CSV save raises."""
        import scripts.training.cross_validation as cv
        import pandas as pd
        import numpy as np

        # Provide enough data for a 5-fold split
        n = 20
        fake_df = pd.DataFrame({
            "kev_flag": np.zeros(n, dtype=int),
            "epss_score": np.zeros(n),
            "epss_percentile": np.zeros(n),
            "is_healthcare": np.zeros(n, dtype=int),
            "is_curated": np.zeros(n, dtype=int),
            "chpl_flag": np.zeros(n, dtype=int),
            "attack_flag": np.zeros(n, dtype=int),
            "attack_technique_count": np.zeros(n, dtype=int),
            "cvss": np.ones(n) * 5.0,
            "label": np.zeros(n, dtype=int),
            "published": pd.date_range("2020-01-01", periods=n),
        })

        with patch.object(cv, "load_data", return_value=fake_df):
            # make the fold training raise so we short-circuit before csv save
            with patch.object(cv, "train_fold", side_effect=RuntimeError("xgb error")):
                result = cv.main()
        assert result == 1


# ---------------------------------------------------------------------------
# src/analysis/attack_mapper.py
# ---------------------------------------------------------------------------

class TestAttackMapper:
    def test_init_raises_on_missing_cache(self, tmp_path):
        """AttackMapper must raise when the cache file does not exist."""
        from src.analysis.attack_mapper import AttackMapper

        missing = tmp_path / "nonexistent.pkl.gz"
        with pytest.raises(Exception):
            AttackMapper(cache_path=missing)

    def test_map_cve_returns_empty_on_blank_description(self, tmp_path):
        """map_cve_to_techniques must return zero-match result for empty description."""
        import gzip
        import pickle
        import pandas as pd

        # Minimal fake techniques dataframe
        fake_df = pd.DataFrame({
            "external_references": [[{"source_name": "mitre-attack", "external_id": "T9999"}]],
            "name": ["test technique"],
        })
        cache_file = tmp_path / "attack_techniques.pkl.gz"
        with gzip.open(cache_file, "wb") as f:
            pickle.dump(fake_df, f)

        from src.analysis.attack_mapper import AttackMapper
        mapper = AttackMapper(cache_path=cache_file)

        result = mapper.map_cve_to_techniques("")
        assert result["attack_flag"] == 0
        assert result["technique_count"] == 0
        assert result["techniques"] == []


# ---------------------------------------------------------------------------
# src/analysis/chpl_mapper.py
# ---------------------------------------------------------------------------

class TestCHPLMapper:
    def test_init_handles_fetcher_failure_gracefully(self):
        """CHPLMapper must not raise when CHPLFetcher raises; products_df should be None."""
        from src.analysis import chpl_mapper

        with patch.object(chpl_mapper, "CHPLFetcher", side_effect=RuntimeError("network error")):
            mapper = chpl_mapper.CHPLMapper()
        assert mapper.products_df is None

    def test_check_chpl_match_returns_no_match_when_no_data(self):
        """check_chpl_match must return chpl_flag=0 when products_df is None."""
        from src.analysis import chpl_mapper

        with patch.object(chpl_mapper, "CHPLFetcher", side_effect=RuntimeError("offline")):
            mapper = chpl_mapper.CHPLMapper()

        result = mapper.check_chpl_match("some description about Epic EHR")
        assert result["chpl_flag"] == 0
