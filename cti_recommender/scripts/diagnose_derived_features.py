from pathlib import Path

import numpy as np
import pandas as pd


def main() -> None:
    features_dir = Path("outputs/features")
    latest = sorted(features_dir.glob("features_with_labels_*.csv"))[-1]

    df = pd.read_csv(latest)
    df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    df["year"] = df["published"].dt.year

    derived = [
        "ultimate_risk",
        "critical_exploitable",
        "network_accessible",
        "auth_not_required",
        "high_impact_network",
        "healthcare_critical",
        "vendor_risk_score",
        "vendor_is_high_risk",
        "vendor_is_healthcare",
        "curated_severity",
    ]

    for col in derived + ["soft_label"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Overall sparsity + label lift.
    rows = []
    for col in derived:
        s = df[col]
        nz = s.fillna(0) != 0
        nz_count = int(nz.sum())
        n = len(df)

        mean_label_nz = float(df.loc[nz, "soft_label"].mean()) if nz_count > 0 else np.nan
        mean_label_z = float(df.loc[~nz, "soft_label"].mean()) if (~nz).sum() > 0 else np.nan
        lift = mean_label_nz - mean_label_z if pd.notna(mean_label_nz) and pd.notna(mean_label_z) else np.nan

        corr = np.nan
        if df[col].notna().sum() > 3:
            corr = float(df[[col, "soft_label"]].corr(numeric_only=True).iloc[0, 1])

        rows.append(
            {
                "feature": col,
                "non_zero_count": nz_count,
                "non_zero_pct": round((nz_count / n) * 100, 3) if n else 0.0,
                "mean_label_when_nonzero": round(mean_label_nz, 4) if pd.notna(mean_label_nz) else np.nan,
                "mean_label_when_zero": round(mean_label_z, 4) if pd.notna(mean_label_z) else np.nan,
                "label_lift_nonzero_minus_zero": round(lift, 4) if pd.notna(lift) else np.nan,
                "pearson_corr_with_label": round(corr, 4) if pd.notna(corr) else np.nan,
            }
        )

    summary = pd.DataFrame(rows).sort_values("non_zero_pct")

    # Temporal prevalence by year and windows.
    years = sorted(int(y) for y in df["year"].dropna().unique() if y >= 2018)
    temporal_rows = []
    for col in derived:
        for year in years:
            d = df[df["year"] == year]
            if len(d) == 0:
                continue
            pct = (d[col].fillna(0) != 0).mean() * 100
            temporal_rows.append(
                {
                    "year": year,
                    "feature": col,
                    "non_zero_pct": round(float(pct), 3),
                    "rows": len(d),
                }
            )
    temporal_df = pd.DataFrame(temporal_rows)

    windows = [
        ("2018-2020", (df["year"] >= 2018) & (df["year"] <= 2020)),
        ("2021-2023", (df["year"] >= 2021) & (df["year"] <= 2023)),
        ("2024-2025", (df["year"] >= 2024) & (df["year"] <= 2025)),
    ]
    window_rows = []
    for col in derived:
        for window_name, mask in windows:
            d = df.loc[mask]
            if len(d) == 0:
                continue
            pct = (d[col].fillna(0) != 0).mean() * 100
            window_rows.append(
                {
                    "feature": col,
                    "window": window_name,
                    "non_zero_pct": round(float(pct), 3),
                    "rows": len(d),
                }
            )
    window_df = pd.DataFrame(window_rows)

    out_dir = Path("outputs")
    summary_path = out_dir / "derived_feature_diagnostic_summary.csv"
    temporal_path = out_dir / "derived_feature_temporal_prevalence.csv"
    window_path = out_dir / "derived_feature_window_prevalence.csv"

    summary.to_csv(summary_path, index=False)
    temporal_df.to_csv(temporal_path, index=False)
    window_df.to_csv(window_path, index=False)

    print(f"Using dataset: {latest}")
    print(f"Total rows: {len(df):,}")
    print("\n=== Derived Feature Diagnostic Summary ===")
    print(summary.to_string(index=False))

    print("\n=== Window prevalence (non-zero %) ===")
    pivot = window_df.pivot(index="feature", columns="window", values="non_zero_pct")
    print(pivot.to_string())

    print(f"\nSaved: {summary_path}")
    print(f"Saved: {temporal_path}")
    print(f"Saved: {window_path}")


if __name__ == "__main__":
    main()
