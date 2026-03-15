"""Resilience tests for analysis mapper entrypoints."""
from __future__ import annotations

from unittest.mock import patch


def test_attack_mapper_main_returns_nonzero_on_constructor_failure():
    from src.analysis import attack_mapper as mod

    with patch.object(mod, "AttackMapper", side_effect=RuntimeError("cache missing")):
        assert mod.main() == 1


def test_chpl_mapper_main_returns_nonzero_on_constructor_failure():
    from src.analysis import chpl_mapper as mod

    with patch.object(mod, "CHPLMapper", side_effect=RuntimeError("fetch failed")):
        assert mod.main() == 1
