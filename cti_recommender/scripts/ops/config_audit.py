#!/usr/bin/env python3
"""
Config audit checks for configuration governance.

Fails when:
1) YAML experiment profiles contain unknown/unused keys
2) Runtime settings keys are duplicated in experiment config schema
"""

from __future__ import annotations

import sys
import ast
from pathlib import Path
from typing import Any, Dict, Set

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANY_MAPPING = "__ANY_MAPPING__"


def _build_schema_map() -> Dict[str, Dict[str, Any]]:
    """Build expected top-level and nested schema for experiment YAML."""
    return {
        "experiment": {
            "name": None,
            "version": None,
            "description": None,
        },
        "data": {
            "min_cve_date": None,
            "train_test_split_date": None,
            "feature_cols": None,
            "similarity_features": None,
        },
        "feature_engineering": {
            "audit": None,
            "plot": None,
            "plot_top_missing": None,
            "reference_date": None,
            "cvss_missing_fill": None,
            "epss_missing_fill": None,
        },
        "sampling": {
            "graph_sample_size": None,
            "rgcn_sample_size": None,
            "test_sample_size": None,
        },
        "temporal_splits": {
            "strategy": None,
            "date_split": ANY_MAPPING,
            "percentage_split": ANY_MAPPING,
            "year_split": ANY_MAPPING,
        },
        "rgcn": {
            "hidden_channels": None,
            "num_layers": None,
            "dropout": None,
            "learning_rate": None,
            "epochs": None,
            "early_stopping_patience": None,
            "max_neighbors": None,
            "use_minibatch": None,
            "batch_size": None,
            "num_neighbors": None,
        },
        "diffusion": {
            "alpha": None,
            "max_iter": None,
            "tolerance": None,
        },
        "similarity": {
            "k_neighbors": None,
            "threshold": None,
        },
        "evaluation": {
            "k_values": None,
            "precision_threshold": None,
        },
        "models": {
            "baseline_path": None,
            "rgcn_path": None,
            "ensemble_path": None,
        },
        "output": {
            "dir": None,
            "save_predictions": None,
            "save_plots": None,
        },
        "device": {
            "training": None,
            "inference": None,
            "force_cpu": None,
        },
    }


def _validate_unknown_keys(data: Dict[str, Any], schema_map: Dict[str, Dict[str, Any]], source_name: str) -> Set[str]:
    """Return unknown keys discovered in YAML against expected dataclass schema."""
    errors: Set[str] = set()

    for top_key, top_value in data.items():
        if top_key == "_inherit":
            continue
        if top_key not in schema_map:
            errors.add(f"{source_name}: unknown top-level key '{top_key}'")
            continue

        expected_section = schema_map[top_key]
        if not isinstance(top_value, dict):
            errors.add(f"{source_name}: section '{top_key}' must be a mapping")
            continue

        for nested_key, nested_value in top_value.items():
            if nested_key not in expected_section:
                errors.add(f"{source_name}: unknown key '{top_key}.{nested_key}'")
                continue

            rule = expected_section[nested_key]
            if rule == ANY_MAPPING and not isinstance(nested_value, dict):
                errors.add(f"{source_name}: key '{top_key}.{nested_key}' must be a mapping")

    return errors


def _collect_experiment_leaf_keys(schema_map: Dict[str, Dict[str, Any]]) -> Set[str]:
    keys: Set[str] = set()
    for nested_schema in schema_map.values():
        keys.update(nested_schema.keys())
    return keys


def _collect_runtime_setting_keys() -> Set[str]:
    settings_path = PROJECT_ROOT / "config" / "settings.py"
    source = settings_path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    runtime_keys: Set[str] = set()
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Settings":
            continue
        for class_stmt in node.body:
            if isinstance(class_stmt, ast.AnnAssign) and isinstance(class_stmt.target, ast.Name):
                runtime_keys.add(class_stmt.target.id.lower())
        break

    return runtime_keys


def _load_profiles(config_dir: Path) -> Dict[str, Dict[str, Any]]:
    default_cfg = _load_yaml(config_dir / "default.yaml")
    result: Dict[str, Dict[str, Any]] = {"default": default_cfg}

    for profile_name in ("debug", "production"):
        profile_path = config_dir / f"{profile_name}.yaml"
        if not profile_path.exists():
            continue
        profile_data = _load_yaml(profile_path)
        profile_data.pop("_inherit", None)
        result[profile_name] = _merge_dicts(default_cfg, profile_data)

    return result


def run_audit() -> int:
    config_dir = PROJECT_ROOT / "config" / "experiments"
    schema_map = _build_schema_map()

    failures: Set[str] = set()

    for profile, data in _load_profiles(config_dir).items():
        failures.update(_validate_unknown_keys(data, schema_map, f"profile={profile}"))

    runtime_keys = _collect_runtime_setting_keys()
    experiment_leaf_keys = _collect_experiment_leaf_keys(schema_map)
    duplicated_keys = sorted(runtime_keys & experiment_leaf_keys)

    if duplicated_keys:
        failures.add(
            "duplicated ownership keys between runtime settings and experiment schema: "
            + ", ".join(duplicated_keys)
        )

    if failures:
        print("[FAIL] Config audit failed:")
        for failure in sorted(failures):
            print(f"  - {failure}")
        return 1

    print("[OK] Config audit passed")
    return 0


def _load_yaml(path: Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


if __name__ == "__main__":
    raise SystemExit(run_audit())
