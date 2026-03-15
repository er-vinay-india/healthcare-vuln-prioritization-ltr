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


def main() -> None:
    print("=" * 70)
    print("HEALTHCARE OSINT FETCH")
    print("=" * 70)

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

    print(f"CISA ICS advisories:       {len(ics_df):,}")
    print(f"openFDA enforcement rows:  {len(enf_df):,}")
    print(f"openFDA event rows:        {len(evt_df):,}")
    print(f"Saved outputs to:          {out_dir}")


if __name__ == "__main__":
    main()
