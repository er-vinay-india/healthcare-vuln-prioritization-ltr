"""
Exploratory Data Analysis (EDA) Visualization Functions

This module provides interactive plotly-based visualizations for CVE data analysis.
All functions accept a pandas DataFrame and display interactive charts.

Functions:
    - plot_temporal_trends: CVEs published over time (yearly and monthly)
    - plot_cvss_distribution: CVSS score distribution and statistics
    - plot_kev_analysis: KEV vs Non-KEV comparison with box plots
    - plot_attack_coverage: ATT&CK technique coverage distribution
    - plot_label_distribution: Priority label distribution pie chart
"""

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from typing import Optional


def plot_temporal_trends(df: pd.DataFrame, recent_months: int = 24) -> None:
    """
    Plot temporal trends of CVE publications.
    
    Displays two charts:
    1. Bar chart: CVEs published per year
    2. Line chart: Monthly trend for recent period
    
    Args:
        df: DataFrame with 'published' column (datetime or str)
        recent_months: Number of recent months to show in monthly trend (default: 24)
    """
    # Prepare temporal data
    df = df.copy()
    df['published_date'] = pd.to_datetime(df['published'])
    df['year'] = df['published_date'].dt.year
    df['year_month'] = df['published_date'].dt.to_period('M').astype(str)
    
    # Chart 1: CVEs per Year (Bar Chart)
    cves_per_year = df.groupby('year').size().reset_index(name='count')
    
    fig1 = px.bar(
        cves_per_year,
        x='year',
        y='count',
        title='CVEs Published Per Year',
        labels={'year': 'Year', 'count': 'Number of CVEs'},
        color='count',
        color_continuous_scale='Viridis'
    )
    fig1.update_layout(showlegend=False, height=400)
    fig1.show()
    
    peak_year = cves_per_year.loc[cves_per_year['count'].idxmax(), 'year']
    peak_count = cves_per_year['count'].max()
    print(f"[STATS] TREND: Peak year: {peak_year} with {peak_count:,} CVEs")
    
    # Chart 2: Monthly Trend (Line Chart) - Recent period
    # Calculate cutoff date for recent period
    max_date = df['published_date'].max()
    cutoff_date = max_date - pd.DateOffset(months=recent_months)
    recent_df = df[df['published_date'] >= cutoff_date]
    
    monthly_trend = recent_df.groupby('year_month').size().reset_index(name='count')
    
    fig2 = px.line(
        monthly_trend,
        x='year_month',
        y='count',
        title=f'CVEs Published Per Month (Last {recent_months} Months)',
        labels={'year_month': 'Month', 'count': 'Number of CVEs'},
        markers=True
    )
    fig2.update_layout(height=400)
    fig2.show()
    
    avg_monthly = monthly_trend['count'].mean()
    print(f" INFO: Average CVEs per month (recent period): {avg_monthly:.0f}")


def plot_cvss_distribution(df: pd.DataFrame, cvss_column: str = 'cvss') -> None:
    """
    Plot CVSS score distribution with histogram and statistics.
    
    Args:
        df: DataFrame with CVSS score column
        cvss_column: Name of the CVSS column (default: 'cvss')
    """
    if cvss_column not in df.columns:
        print(f"[FAIL] ERROR: Column '{cvss_column}' not found in DataFrame")
        return
    
    # Filter out null values
    df_clean = df[df[cvss_column].notna()].copy()
    
    if len(df_clean) == 0:
        print(f"[FAIL] ERROR: No non-null values in '{cvss_column}' column")
        return
    
    # Create histogram
    fig = px.histogram(
        df_clean,
        x=cvss_column,
        nbins=50,
        title=f'CVSS Score Distribution (n={len(df_clean):,})',
        labels={cvss_column: 'CVSS Score', 'count': 'Number of CVEs'},
        color_discrete_sequence=['steelblue']
    )
    fig.update_layout(height=400, showlegend=False)
    fig.show()
    
    # Statistics
    stats = df_clean[cvss_column].describe()
    print(f"\n[STATS] CVSS Statistics:")
    print(f"   Mean: {stats['mean']:.2f}")
    print(f"   Median: {stats['50%']:.2f}")
    print(f"   Std Dev: {stats['std']:.2f}")
    print(f"   Range: [{stats['min']:.2f}, {stats['max']:.2f}]")
    
    # Severity categories (CVSS v3.0 standard)
    critical = (df_clean[cvss_column] >= 9.0).sum()
    high = ((df_clean[cvss_column] >= 7.0) & (df_clean[cvss_column] < 9.0)).sum()
    medium = ((df_clean[cvss_column] >= 4.0) & (df_clean[cvss_column] < 7.0)).sum()
    low = (df_clean[cvss_column] < 4.0).sum()
    
    print(f"\n[TARGET] Severity Breakdown:")
    print(f"   Critical (9.0-10.0): {critical:,} ({critical/len(df_clean)*100:.1f}%)")
    print(f"   High (7.0-8.9): {high:,} ({high/len(df_clean)*100:.1f}%)")
    print(f"   Medium (4.0-6.9): {medium:,} ({medium/len(df_clean)*100:.1f}%)")
    print(f"   Low (0.0-3.9): {low:,} ({low/len(df_clean)*100:.1f}%)")


def plot_kev_analysis(df: pd.DataFrame, cvss_column: str = 'cvss', kev_column: str = 'kev_flag') -> None:
    """
    Compare KEV vs Non-KEV vulnerabilities with box plots and statistics.
    
    Args:
        df: DataFrame with CVSS and KEV flag columns
        cvss_column: Name of the CVSS column (default: 'cvss')
        kev_column: Name of the KEV flag column (default: 'kev_flag')
    """
    if cvss_column not in df.columns or kev_column not in df.columns:
        print(f"[FAIL] ERROR: Required columns not found")
        return
    
    # Prepare data
    df_clean = df[[cvss_column, kev_column]].dropna().copy()
    df_clean['KEV_Status'] = df_clean[kev_column].map({0: 'Non-KEV', 1: 'KEV (Known Exploited)'})
    
    # Box plot comparison
    fig = px.box(
        df_clean,
        x='KEV_Status',
        y=cvss_column,
        title='CVSS Score Comparison: KEV vs Non-KEV Vulnerabilities',
        labels={'KEV_Status': 'Status', cvss_column: 'CVSS Score'},
        color='KEV_Status',
        color_discrete_map={'KEV (Known Exploited)': 'red', 'Non-KEV': 'steelblue'}
    )
    fig.update_layout(height=450, showlegend=False)
    fig.show()
    
    # Statistical comparison
    kev_data = df_clean[df_clean[kev_column] == 1][cvss_column]
    non_kev_data = df_clean[df_clean[kev_column] == 0][cvss_column]
    
    print(f"\n[TARGET] KEV Analysis:")
    print(f"   KEV CVEs: {len(kev_data):,} ({len(kev_data)/len(df_clean)*100:.2f}%)")
    print(f"   Non-KEV CVEs: {len(non_kev_data):,} ({len(non_kev_data)/len(df_clean)*100:.2f}%)")
    print(f"\n[STATS] CVSS Comparison:")
    print(f"   KEV Mean: {kev_data.mean():.2f} (Median: {kev_data.median():.2f})")
    print(f"   Non-KEV Mean: {non_kev_data.mean():.2f} (Median: {non_kev_data.median():.2f})")
    print(f"   Difference: {kev_data.mean() - non_kev_data.mean():.2f} points")


def plot_attack_coverage(df: pd.DataFrame, attack_count_column: str = 'attack_technique_count') -> None:
    """
    Plot ATT&CK technique coverage distribution.
    
    Args:
        df: DataFrame with ATT&CK technique count column
        attack_count_column: Name of the technique count column (default: 'attack_technique_count')
    """
    if attack_count_column not in df.columns:
        print(f"[FAIL] ERROR: Column '{attack_count_column}' not found")
        return
    
    # Filter CVEs with ATT&CK mapping
    attack_cves = df[df[attack_count_column] > 0].copy()
    attack_total = len(attack_cves)
    attack_pct = (attack_total / len(df) * 100)
    
    print(f" INFO: CVEs with ATT&CK Mapping: {attack_total:,} ({attack_pct:.2f}%)")
    
    if attack_total == 0:
        print("[WARN]  No CVEs with ATT&CK mappings found")
        return
    
    # Technique count distribution (top 10)
    technique_dist = attack_cves[attack_count_column].value_counts().sort_index().head(10)
    
    fig = px.bar(
        x=technique_dist.index,
        y=technique_dist.values,
        title='Distribution of ATT&CK Technique Count per CVE (Top 10)',
        labels={'x': 'Number of Techniques', 'y': 'Number of CVEs'},
        color=technique_dist.values,
        color_continuous_scale='Reds'
    )
    fig.update_layout(height=400, showlegend=False)
    fig.show()
    
    print(f"[STATS] INFO: Average techniques per mapped CVE: {attack_cves[attack_count_column].mean():.2f}")
    print(f"[STATS] INFO: Max techniques for a single CVE: {attack_cves[attack_count_column].max()}")


def plot_label_distribution(df: pd.DataFrame, label_column: str = 'label') -> None:
    """
    Plot priority label distribution as pie chart with statistics.
    
    Args:
        df: DataFrame with priority label column
        label_column: Name of the label column (default: 'label')
    """
    if label_column not in df.columns:
        print(f"[FAIL] ERROR: Column '{label_column}' not found")
        return
    
    # Filter out null labels
    df_labeled = df[df[label_column].notna()].copy()
    
    if len(df_labeled) == 0:
        print("[FAIL] ERROR: No labeled CVEs found")
        return
    
    # Label counts
    label_counts = df_labeled[label_column].value_counts().sort_index()
    
    # Pie chart
    fig = px.pie(
        values=label_counts.values,
        names=[f'Priority {int(i)}' for i in label_counts.index],
        title='Distribution of Priority Labels (0=Lowest, 5=Highest)',
        color_discrete_sequence=px.colors.sequential.Reds
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    fig.update_layout(height=450)
    fig.show()
    
    # Statistics table
    print(f"\n  Label Distribution Summary:")
    print(f"   Total Labeled CVEs: {len(df_labeled):,}")
    
    # Priority buckets
    high_priority = ((df_labeled[label_column] >= 4) & (df_labeled[label_column] <= 5)).sum()
    medium_priority = ((df_labeled[label_column] >= 2) & (df_labeled[label_column] < 4)).sum()
    low_priority = ((df_labeled[label_column] >= 0) & (df_labeled[label_column] < 2)).sum()
    
    print(f"\n[STATS] Priority Buckets:")
    print(f"   High Priority (4-5): {high_priority:,} ({high_priority/len(df_labeled)*100:.1f}%)")
    print(f"   Medium Priority (2-3): {medium_priority:,} ({medium_priority/len(df_labeled)*100:.1f}%)")
    print(f"   Low Priority (0-1): {low_priority:,} ({low_priority/len(df_labeled)*100:.1f}%)")


def plot_all_eda(df: pd.DataFrame, 
                 cvss_column: str = 'cvss',
                 kev_column: str = 'kev_flag',
                 attack_column: str = 'attack_technique_count',
                 label_column: str = 'label',
                 recent_months: int = 24) -> None:
    """
    Run all EDA visualizations in sequence.
    
    Args:
        df: DataFrame with CVE data
        cvss_column: Name of CVSS score column (default: 'cvss')
        kev_column: Name of KEV flag column (default: 'kev_flag')
        attack_column: Name of ATT&CK count column (default: 'attack_technique_count')
        label_column: Name of priority label column (default: 'label')
        recent_months: Number of recent months for temporal trend (default: 24)
    """
    print("=" * 80)
    print(" EXPLORATORY DATA ANALYSIS")
    print("=" * 80)
    
    print("\n1⃣  Temporal Trends")
    print("-" * 80)
    plot_temporal_trends(df, recent_months=recent_months)
    
    print("\n\n2⃣  CVSS Distribution")
    print("-" * 80)
    plot_cvss_distribution(df, cvss_column=cvss_column)
    
    print("\n\n3⃣  KEV Analysis")
    print("-" * 80)
    plot_kev_analysis(df, cvss_column=cvss_column, kev_column=kev_column)
    
    print("\n\n4⃣  ATT&CK Coverage")
    print("-" * 80)
    plot_attack_coverage(df, attack_count_column=attack_column)
    
    print("\n\n5⃣  Label Distribution")
    print("-" * 80)
    plot_label_distribution(df, label_column=label_column)
    
    print("\n" + "=" * 80)
    print("[OK] EDA Complete")
    print("=" * 80)
