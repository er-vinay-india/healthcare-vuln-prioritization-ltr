#!/usr/bin/env python3
"""Quick code-level check of STEP_5 feature utilization using shared ltr defaults."""

from pathlib import Path
import sys
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.models.ltr import get_default_ltr_params, train_lambdarank


def main() -> int:
    features_dir = Path("outputs/features")
    latest = sorted(features_dir.glob("features_with_labels_*.csv"))[-1]
    print(f"Loading: {latest.name}")

    df = pd.read_csv(latest, low_memory=False)
    df["published"] = pd.to_datetime(df["published"], errors="coerce", utc=True)

    basic_features = [
        "kev_flag",
        "epss_score",
        "epss_percentile",
        "is_healthcare",
        "healthcare_score",
        "attack_flag",
        "attack_technique_count",
        "chpl_flag",
        "is_curated",
        "curated_severity",
    ]
    cvss_features = [
        "cvss_av",
        "cvss_ac",
        "cvss_pr",
        "cvss_ui",
        "cvss_s",
        "cvss_c",
        "cvss_i",
        "cvss_a",
        "cvss_score_derived",
        "cvss_severity_category",
    ]
    cwe_features = [
        "cwe_is_top25",
        "cwe_is_injection",
        "cwe_is_crypto",
        "cwe_is_access_control",
        "cwe_is_input_validation",
        "cwe_is_memory_corruption",
        "cwe_category",
        "cwe_severity_score",
    ]
    nlp_features = [
        "desc_has_rce",
        "desc_has_auth_bypass",
        "desc_has_priv_esc",
        "desc_has_sqli",
        "desc_has_xss",
        "desc_has_dos",
        "desc_has_buffer_overflow",
        "desc_has_path_traversal",
        "desc_has_csrf",
        "desc_has_xxe",
    ]
    vendor_features = ["vendor_is_high_risk", "vendor_is_healthcare", "vendor_risk_score"]
    interaction_features = [
        "ultimate_risk",
        "critical_exploitable",
        "network_accessible",
        "auth_not_required",
        "high_impact_network",
        "healthcare_critical",
    ]
    feature_cols = (
        basic_features
        + cvss_features
        + cwe_features
        + nlp_features
        + vendor_features
        + interaction_features
    )

    # Deterministic temporal-ish split
    cutoff = df["published"].quantile(0.7)
    train = df[df["published"] <= cutoff].copy()
    val = df[df["published"] > cutoff].copy()

    train["published_week"] = train["published"].dt.tz_localize(None).dt.to_period("W").astype(str)
    val["published_week"] = val["published"].dt.tz_localize(None).dt.to_period("W").astype(str)

    params = get_default_ltr_params()
    params["seed"] = 42
    params["force_row_wise"] = True
    params["verbose"] = -1

    model = train_lambdarank(train, val, feature_cols, params=params, random_seed=42)

    gains = model.feature_importance(importance_type="gain")
    used = int((gains > 0).sum())

    print(f"Used features: {used}/{len(feature_cols)}")
    zero = [f for f, g in zip(feature_cols, gains) if g == 0]
    print(f"Unused features: {len(zero)}")
    if zero:
        print("Examples:", ", ".join(zero[:10]))

    top = sorted(zip(feature_cols, gains), key=lambda x: x[1], reverse=True)[:12]
    print("Top features:")
    for name, score in top:
        print(f"  {name:30s} {int(score)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
