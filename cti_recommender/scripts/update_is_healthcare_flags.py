#!/usr/bin/env python3
"""Backward-compatible wrapper for relocated script."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.data.update_is_healthcare_flags import main


if __name__ == "__main__":
    sys.exit(main())
