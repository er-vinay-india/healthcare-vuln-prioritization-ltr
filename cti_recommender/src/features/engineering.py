"""
Feature Engineering Module

This module handles feature extraction and transformation for CVE prioritization.
Includes CVSS, EPSS, KEV, ATT&CK, CHPL, and healthcare-related features.

Upgrades added:
- Defensive dtype coercion (published datetime, numeric CVSS/EPSS, flags)
- Missingness auditing (before/after fill) + delta table
- Optional plots (missingness bar, feature distributions)
- Single source of truth feature builder (reduces duplication)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Literal

import numpy as np
import pandas as pd


# -------------------------
# Reporting data structures
# -------------------------

@dataclass
class MissingnessReport:
    before: pd.DataFrame
    after: pd.DataFrame
    delta: pd.DataFrame


# -------------------------
# Helpers: validation & audit
# -------------------------

def _ensure_columns(df: pd.DataFrame, required: List[str]) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise KeyError(f"Missing required columns: {missing}")


def _coerce_datetime_utc(s: pd.Series) -> pd.Series:
    """
    Coerce series to timezone-aware UTC datetime.
    Bad parses -> NaT.
    """
    return pd.to_datetime(s, errors="coerce", utc=True)


def _coerce_numeric(s: pd.Series, default: float = np.nan) -> pd.Series:
    """
    Coerce series to numeric.
    Bad parses -> NaN.
    """
    if s is None:
        return pd.Series(default)
    return pd.to_numeric(s, errors="coerce")


def missingness_table(df: pd.DataFrame, cols: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Missingness summary table:
    - missing_count
    - missing_pct
    - dtype
    """
    if cols is None:
        cols = list(df.columns)

    tbl = pd.DataFrame({
        "missing_count": df[cols].isna().sum(),
        "missing_pct": (df[cols].isna().mean() * 100).round(2),
        "dtype": df[cols].dtypes.astype(str),
    }).sort_values(["missing_pct", "missing_count"], ascending=False)

    return tbl


def missingness_delta(before: pd.DataFrame, after: pd.DataFrame) -> pd.DataFrame:
    """
    Join before/after missingness tables and compute reductions.
    """
    joined = (
        before[["missing_count", "missing_pct"]]
        .join(after[["missing_count", "missing_pct"]], lsuffix="_before", rsuffix="_after")
    )
    joined["missing_count_reduced"] = joined["missing_count_before"] - joined["missing_count_after"]
    joined["missing_pct_reduced"] = (joined["missing_pct_before"] - joined["missing_pct_after"]).round(2)
    return joined.sort_values(["missing_count_reduced", "missing_pct_reduced"], ascending=False)


def plot_missingness_bar(miss_tbl: pd.DataFrame, top_n: int = 25, title: str = "Missingness % (Top Columns)") -> None:
    """
    Optional plotting helper using plotly for interactive visualization.
    Kept inside module to avoid notebook-only code.
    """
    import plotly.express as px

    data = miss_tbl.head(top_n).copy()
    data = data.iloc[::-1]  # nicer ordering for display
    data['column'] = data.index.astype(str)

    fig = px.bar(
        data,
        y='column',
        x='missing_pct',
        orientation='h',
        title=title,
        labels={'missing_pct': 'Missing %', 'column': 'Column'},
        color='missing_pct',
        color_continuous_scale='Reds'
    )
    fig.update_layout(height=max(400, 20 * len(data)), showlegend=False)
    fig.show()


def plot_feature_histograms(df: pd.DataFrame, cols: List[str], bins: int = 40, max_cols: int = 10) -> None:
    """
    Optional plotting helper using plotly for interactive histograms.
    """
    import plotly.express as px

    show_cols = cols[:max_cols]
    for c in show_cols:
        if c in df.columns and pd.api.types.is_numeric_dtype(df[c]):
            data_clean = df[c].dropna()
            if len(data_clean) > 0:
                fig = px.histogram(
                    data_clean,
                    nbins=bins,
                    title=f"Distribution: {c}",
                    labels={'value': c, 'count': 'Count'}
                )
                fig.update_layout(height=400, showlegend=False)
                fig.show()


# -------------------------
# Core feature builder
# -------------------------

def build_features(
    df: pd.DataFrame,
    reference_date: Optional[str] = None,
    *,
    cvss_missing_fill: float = 5.0,   # medium severity on 0..10
    epss_missing_fill: float = 0.0,   # no observed exploit likelihood on 0..1
    audit: bool = True,
    plot: bool = False,
    plot_top_missing: int = 25
) -> Tuple[pd.DataFrame, Optional[MissingnessReport]]:
    """
    Build comprehensive feature set for CVE ranking with defensive handling + optional audit.

    Args:
        df: DataFrame with raw CVE data and enrichments
        reference_date: Reference date for recency calculation (YYYY-MM-DD).
                        If None, uses "now" in UTC.
        cvss_missing_fill: fill value for missing CVSS base score (0..10)
        epss_missing_fill: fill value for missing EPSS values (0..1)
        audit: if True, returns MissingnessReport (before/after/delta)
        plot: if True, show missingness plots + feature histograms
        plot_top_missing: top N columns for missingness bar plot

    Returns:
        (features_df, missingness_report_or_None)
    """
    features = df.copy(deep=True)

    # Base columns expected for temporal calculations and CVSS
    _ensure_columns(features, ["published"])

    # Audit snapshot BEFORE
    before_tbl = missingness_table(features) if audit else None

    # --- Coerce / normalize raw columns safely ---

    # published -> datetime UTC
    features["published"] = _coerce_datetime_utc(features["published"])
    features["published_missing"] = features["published"].isna().astype(int)

    # CVSS numeric (0..10)
    if "cvss" not in features.columns:
        features["cvss"] = np.nan
    features["cvss"] = _coerce_numeric(features["cvss"])

    # EPSS numeric (0..1)
    if "epss_score" not in features.columns:
        features["epss_score"] = np.nan
    if "epss_percentile" not in features.columns:
        features["epss_percentile"] = np.nan

    features["epss_score"] = _coerce_numeric(features["epss_score"])
    features["epss_percentile"] = _coerce_numeric(features["epss_percentile"])

    # Keep “missing flags” BEFORE filling (super useful for LTR models)
    features["cvss_missing_flag"] = features["cvss"].isna().astype(int)
    features["epss_missing_flag"] = features["epss_score"].isna().astype(int)
    features["epss_percentile_missing_flag"] = features["epss_percentile"].isna().astype(int)

    # --- Fill missing values with chosen defaults ---
    features["cvss_norm"] = features["cvss"].fillna(cvss_missing_fill) / 10.0
    features["epss_score"] = features["epss_score"].fillna(epss_missing_fill)
    features["epss_percentile"] = features["epss_percentile"].fillna(epss_missing_fill)

    # KEV flag (binary)
    if "kev_flag" not in features.columns:
        features["kev_flag"] = 0
    features["kev_flag"] = _coerce_numeric(features["kev_flag"]).fillna(0).astype(int)

    # ATT&CK features
    if "attack_technique_count" not in features.columns:
        features["attack_technique_count"] = 0
    features["attack_technique_count"] = _coerce_numeric(features["attack_technique_count"]).fillna(0).astype(int)

    # has_attack derived
    features["has_attack"] = (features["attack_technique_count"] > 0).astype(int)
    if "attack_flag" in features.columns:
        features["attack_flag"] = _coerce_numeric(features["attack_flag"]).fillna(0).astype(int)
        features["has_attack"] = (
            (features["attack_technique_count"] > 0) | (features["attack_flag"] == 1)
        ).astype(int)

    # CHPL and healthcare flags
    if "chpl_flag" not in features.columns:
        features["chpl_flag"] = 0
    if "is_healthcare" not in features.columns:
        features["is_healthcare"] = 0

    features["chpl_flag"] = _coerce_numeric(features["chpl_flag"]).fillna(0).astype(int)
    features["is_healthcare"] = _coerce_numeric(features["is_healthcare"]).fillna(0).astype(int)

    # --- Temporal features ---
    if reference_date is None:
        ref_date = pd.Timestamp.now(tz="UTC")
    else:
        ref_date = pd.Timestamp(reference_date).tz_localize("UTC") if pd.Timestamp(reference_date).tzinfo is None else pd.Timestamp(reference_date)

    # days_since_published: if published missing -> NaN; clip lower=0 to avoid negative
    features["days_since_published"] = (ref_date - features["published"]).dt.days
    features.loc[features["days_since_published"] < 0, "days_since_published"] = 0

    max_days = features["days_since_published"].max(skipna=True)
    if pd.isna(max_days) or max_days <= 0:
        features["recency_score"] = 1.0
    else:
        features["recency_score"] = 1.0 - (features["days_since_published"] / max_days)

    # --- Interaction features ---
    features["cvss_epss_product"] = features["cvss_norm"] * features["epss_score"]
    features["kev_healthcare_interaction"] = features["kev_flag"] * features["is_healthcare"]

    # --- Week grouping for ranking ---
    features["published_week"] = features["published"].dt.strftime("%Y-%U")

    # Audit snapshot AFTER
    report: Optional[MissingnessReport] = None
    if audit:
        after_tbl = missingness_table(features)
        delta_tbl = missingness_delta(before_tbl, after_tbl)  # type: ignore[arg-type]
        report = MissingnessReport(before=before_tbl, after=after_tbl, delta=delta_tbl)  # type: ignore[arg-type]

        # quick prints (safe to keep)
        print(f"Feature engineering complete: {len(features):,} rows")
        print(f"Columns: {len(before_tbl)} original -> {len(after_tbl)} total (+{len(after_tbl) - len(before_tbl)} new features)")
        
        # Show NEW columns created (not in before)
        new_cols = set(after_tbl.index) - set(before_tbl.index)
        if new_cols:
            print(f"\n[OK] {len(new_cols)} NEW features created (0% missing):")
            for col in sorted(new_cols):
                print(f"   - {col}")
        
        # Show columns with reduced missingness
        improved = delta_tbl[delta_tbl["missing_count_reduced"] > 0].head(10)
        if len(improved) > 0:
            print("\n Top missingness reductions (original columns cleaned):")
            print(improved[["missing_count_reduced", "missing_pct_reduced"]])
        else:
            print("\n[STATS] No missingness in original columns (data already clean)")

    # Optional plots
    if plot and report is not None:
        plot_missingness_bar(report.before, top_n=plot_top_missing, title="Missingness % BEFORE")
        plot_missingness_bar(report.after, top_n=plot_top_missing, title="Missingness % AFTER")

        # Quick histograms for key numeric features
        plot_feature_histograms(
            features,
            cols=[
                "cvss_norm", "epss_score", "epss_percentile",
                "days_since_published", "recency_score",
                "attack_technique_count", "cvss_epss_product",
            ],
            bins=40,
            max_cols=10
        )

    return features, report


# -------------------------
# Backward-compatible wrapper
# -------------------------

def create_all_features(df: pd.DataFrame, feature_cols: List[str]) -> pd.DataFrame:
    """
    Backward compatible wrapper.
    Builds features and prints statistics for feature_cols (if present).
    """
    features, report = build_features(df, reference_date=None, audit=True, plot=False)

    # Validate provided feature_cols exist
    missing = [c for c in feature_cols if c not in features.columns]
    if missing:
        raise KeyError(f"feature_cols contains missing columns: {missing}")

    print(f"Feature engineering complete: {len(features):,} rows, {len(feature_cols)} features")
    print("\nFeature statistics:")
    desc = features[feature_cols].describe().T
    keep = [c for c in ["mean", "std", "min", "max"] if c in desc.columns]
    print(desc[keep].round(4))

    return features


# -------------------------
# Normalization / scaling
# -------------------------

def normalize_features(
    df: pd.DataFrame,
    feature_cols: List[str],
    method: Literal["minmax", "standard"] = "minmax",
    *,
    clip_minmax: bool = True
) -> Tuple[pd.DataFrame, Dict[str, Dict[str, float]]]:
    """
    Normalize/scale selected numeric features.

    Args:
        df: DataFrame with engineered features
        feature_cols: feature columns to normalize
        method: 'minmax' -> [0,1], 'standard' -> (x-mean)/std
        clip_minmax: if True, clip minmax output to [0,1] (guards outliers)

    Returns:
        (normalized_df, params)
        params contains per-column scaling info for reproducibility.
    """
    out = df.copy(deep=True)
    _ensure_columns(out, feature_cols)

    params: Dict[str, Dict[str, float]] = {}

    for c in feature_cols:
        if not pd.api.types.is_numeric_dtype(out[c]):
            out[c] = _coerce_numeric(out[c])

        s = out[c].astype(float)

        if method == "minmax":
            vmin = float(np.nanmin(s.values)) if np.isfinite(np.nanmin(s.values)) else 0.0
            vmax = float(np.nanmax(s.values)) if np.isfinite(np.nanmax(s.values)) else 0.0
            denom = (vmax - vmin) if (vmax - vmin) != 0 else 1.0
            out[c] = (s - vmin) / denom
            if clip_minmax:
                out[c] = out[c].clip(0.0, 1.0)

            params[c] = {"method": "minmax", "min": vmin, "max": vmax}

        elif method == "standard":
            mean = float(np.nanmean(s.values)) if np.isfinite(np.nanmean(s.values)) else 0.0
            std = float(np.nanstd(s.values)) if np.isfinite(np.nanstd(s.values)) else 1.0
            if std == 0:
                std = 1.0
            out[c] = (s - mean) / std

            params[c] = {"method": "standard", "mean": mean, "std": std}

        else:
            raise ValueError("method must be 'minmax' or 'standard'")

    return out, params


# -------------------------
# Interaction features helper
# -------------------------

def add_interaction_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add interaction features (e.g., CVSS×EPSS, KEV×Healthcare).
    Assumes base engineered columns exist.
    """
    out = df.copy(deep=True)
    needed = ["cvss_norm", "epss_score", "kev_flag", "is_healthcare"]
    _ensure_columns(out, needed)

    out["cvss_epss_product"] = out["cvss_norm"] * out["epss_score"]
    out["kev_healthcare_interaction"] = out["kev_flag"] * out["is_healthcare"]
    return out


# -------------------------
# Default features list
# -------------------------

def get_default_feature_cols() -> List[str]:
    """
    Return default list of feature columns for training.
    NOTE: Updated to match columns actually created in build_features().
    """
    return [
        "cvss_norm",
        "epss_score",
        "epss_percentile",
        "kev_flag",
        "days_since_published",
        "recency_score",
        "attack_technique_count",
        "has_attack",
        "chpl_flag",
        "is_healthcare",
        "cvss_epss_product",
        "kev_healthcare_interaction",
        "published_missing",
        "cvss_missing_flag",
        "epss_missing_flag",
        "epss_percentile_missing_flag",
    ]


# -------------------------
# Categorical encoding helpers
# -------------------------

def fit_categorical_mapping(
    df_ref: pd.DataFrame,
    cat_cols: List[str],
) -> Dict[str, Dict]:
    """Fit a value-to-integer mapping from a reference split (train only).

    Args:
        df_ref:   Reference DataFrame (e.g. train split) to derive categories from.
        cat_cols: Column names to encode.

    Returns:
        mapping dict: {col: {'map': {str_val -> int}, 'unknown_code': int}}
    """
    mapping: Dict[str, Dict] = {}
    for col in cat_cols:
        if col not in df_ref.columns:
            continue
        vals = df_ref[col].astype(str).fillna("unknown")
        col_map = {v: i for i, v in enumerate(vals.unique())}
        mapping[col] = {"map": col_map, "unknown_code": len(col_map)}
    return mapping


def apply_categorical_mapping(
    df_in: pd.DataFrame,
    mapping: Dict[str, Dict],
) -> pd.DataFrame:
    """Apply a train-fitted categorical mapping to any split.

    Unseen category values are assigned the ``unknown_code`` from the mapping.

    Args:
        df_in:   DataFrame to encode.
        mapping: Output of :func:`fit_categorical_mapping`.

    Returns:
        New DataFrame with encoded integer columns.
    """
    df_out = df_in.copy()
    for col, spec in mapping.items():
        if col not in df_out.columns:
            continue
        vals = df_out[col].astype(str).fillna("unknown")
        df_out[col] = (
            vals.map(spec["map"]).fillna(spec["unknown_code"]).astype(int)
        )
    return df_out
