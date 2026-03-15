#!/usr/bin/env python
"""Fetch and cache additional healthcare open-source intelligence feeds."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.healthcare_osint import (
    get_cisa_ics_cached,
    get_openfda_enforcement_cached,
    get_openfda_events_cached,
)

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


def main() -> int:
    logger.info("=" * 70)
    logger.info("HEALTHCARE OSINT FETCH")
    logger.info("=" * 70)

    try:
        ics_df = get_cisa_ics_cached()
        enf_df = get_openfda_enforcement_cached()
        evt_df = get_openfda_events_cached()

        out_dir = Path("outputs") / "healthcare_osint"
        out_dir.mkdir(parents=True, exist_ok=True)

        ics_path = out_dir / "cisa_ics_advisories.csv"
        enf_path = out_dir / "openfda_device_enforcement.csv"
        evt_path = out_dir / "openfda_device_events.csv"

        ics_df.to_csv(ics_path, index=False)
        enf_df.to_csv(enf_path, index=False)
        evt_df.to_csv(evt_path, index=False)

        logger.info(f"CISA ICS advisories:       {len(ics_df):,}")
        logger.info(f"openFDA enforcement rows:  {len(enf_df):,}")
        logger.info(f"openFDA event rows:        {len(evt_df):,}")
        logger.info(f"Saved outputs to:          {out_dir}")
        return 0
    except Exception as exc:
        logger.exception(f"Healthcare OSINT fetch failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
