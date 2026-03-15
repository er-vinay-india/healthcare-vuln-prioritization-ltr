"""Resilience tests for analysis module entrypoints and file outputs."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pandas as pd


def test_healthcare_mapping_main_returns_nonzero_on_export_failure():
    from src.analysis import healthcare_mapping as mod

    with patch.object(mod.HealthcareMapper, "export_mapping_csv", side_effect=RuntimeError("write fail")):
        assert mod.main() == 1


def test_data_quality_main_returns_zero_on_help_print():
    from src.analysis import data_quality as mod

    assert mod.main() == 0


def test_generate_quality_report_raises_when_output_write_fails(tmp_path):
    from src.analysis import data_quality as mod

    nvd_df = pd.DataFrame(
        {
            "cve_id": ["CVE-2024-0001"],
            "published": ["2024-01-01"],
            "cvss": [7.5],
            "description": ["sample"],
        }
    )

    out_file = tmp_path / "quality" / "report.txt"
    with patch("builtins.open", side_effect=OSError("disk full")):
        try:
            mod.generate_quality_report(nvd_df, output_path=out_file)
            assert False, "Expected OSError"
        except OSError:
            pass
