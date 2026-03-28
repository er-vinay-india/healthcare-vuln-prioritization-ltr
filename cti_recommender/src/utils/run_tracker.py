"""
Run Tracker — structured trace logging for training notebooks.

Replaces inline trace_event / trace_stage_done / register_artifact
function definitions in STEP_4 notebook.
"""
from __future__ import annotations

import json
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class RunTracker:
    """Lightweight run-scoped trace logger.

    Usage in notebook::

        from src.utils.run_tracker import RunTracker
        _tracker = RunTracker(run_id=RUN_ID, log_dir=TRACE_LOG_DIR,
                              notebook='STEP_4_All_Models_Training.ipynb')
        trace_event    = _tracker.trace_event
        trace_stage_done  = _tracker.trace_stage_done
        register_artifact = _tracker.register_artifact
        RUN_MANIFEST = _tracker.manifest
    """

    def __init__(self, run_id: str, log_dir: Path, notebook: str) -> None:
        self.run_id = run_id
        self.log_dir = Path(log_dir)
        self.trace_file = self.log_dir / "trace_events.jsonl"
        self.manifest_file = self.log_dir / "run_manifest.json"
        self.manifest: dict[str, Any] = {
            "run_id": run_id,
            "notebook": notebook,
            "started_at_utc": datetime.now(timezone.utc).isoformat(),
            "python_version": platform.python_version(),
            "artifacts": {},
            "stages": [],
        }

    # ------------------------------------------------------------------
    def trace_event(self, stage: str, status: str = "info", **kwargs) -> None:
        """Append a structured event to the JSONL trace log."""
        event: dict[str, Any] = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "notebook": self.manifest["notebook"],
            "stage": stage,
            "status": status,
            "host": socket.gethostname(),
        }
        event.update(kwargs)
        with open(self.trace_file, "a") as fh:
            fh.write(json.dumps(event, default=str) + "\n")
        print(f"[TRACE] {stage} | {status} | {kwargs if kwargs else ''}")

    def trace_stage_done(self, stage: str, status: str = "ok", **kwargs) -> None:
        """Record stage completion in the run manifest and trace log."""
        stage_row: dict[str, Any] = {
            "stage": stage,
            "status": status,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
        }
        stage_row.update(kwargs)
        self.manifest["stages"].append(stage_row)
        self.manifest_file.write_text(
            json.dumps(self.manifest, indent=2, default=str)
        )
        self.trace_event(stage, status=status, **kwargs)

    def register_artifact(self, name: str, path_like: Any) -> None:
        """Record an artifact path and its disk state in the manifest."""
        path_obj = Path(path_like)
        if not path_obj.is_absolute():
            path_obj = path_obj.resolve()
        exists = path_obj.exists()
        self.manifest["artifacts"][name] = {
            "path": str(path_obj),
            "exists": bool(exists),
            "size_bytes": int(path_obj.stat().st_size) if exists else 0,
        }
        self.manifest_file.write_text(
            json.dumps(self.manifest, indent=2, default=str)
        )
