"""
Multi-Level Labeling System for Healthcare CVE Prioritization
Implements 0-5 scale using curated dataset, EPSS, KEV, and healthcare signals
"""

import pandas as pd
from typing import Optional
import logging

logger = logging.getLogger("multi_level_labels")


def compute_multi_level_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Assign multi-level labels (0-5 scale) based on multiple signals
    
    Label Scale:
    - 5 (Critical): Curated + KEV + High EPSS (>0.5) + Healthcare
    - 4 (High): Curated + KEV OR (High EPSS + Healthcare)
    - 3 (Medium): KEV OR (Curated) OR (EPSS>0.3 + Healthcare) OR (CVSS>=9.0 + Healthcare)
    - 2 (Low): Healthcare relevant OR EPSS>0.1 OR CVSS>=7.0
    - 1 (Informational): Some signal present but low priority
    - 0 (Irrelevant): No significant signals
    
    Args:
        df: DataFrame with columns: is_curated, kev_flag, epss_score, 
            is_healthcare, cvss, curated_exploited
    
    Returns:
        DataFrame with added 'label' column (0-5)
    """
    df = df.copy()
    
    # Ensure all required columns exist with defaults
    if 'is_curated' not in df.columns:
        df['is_curated'] = 0
    df['is_curated'] = df['is_curated'].fillna(0).astype(int)
    
    if 'kev_flag' not in df.columns:
        df['kev_flag'] = 0
    df['kev_flag'] = df['kev_flag'].fillna(0).astype(int)
    
    if 'epss_score' not in df.columns:
        df['epss_score'] = 0.0
    df['epss_score'] = df['epss_score'].fillna(0.0)
    
    if 'is_healthcare' not in df.columns:
        df['is_healthcare'] = 0
    df['is_healthcare'] = df['is_healthcare'].fillna(0).astype(int)
    
    if 'cvss' not in df.columns:
        df['cvss'] = 0.0
    df['cvss'] = pd.to_numeric(df['cvss'], errors='coerce').fillna(0.0)
    
    if 'curated_exploited' not in df.columns:
        df['curated_exploited'] = 0
    df['curated_exploited'] = df['curated_exploited'].fillna(0).astype(int)
    
    # Initialize labels to 0
    df['label'] = 0
    
    # Count CVEs in each category for reporting
    counts = {'total': len(df)}
    
    # Level 5 (Critical): Curated + KEV + High EPSS + Healthcare
    # These are confirmed healthcare breaches with active exploitation
    mask_5 = (
        (df['is_curated'] == 1) & 
        (df['kev_flag'] == 1) & 
        (df['epss_score'] > 0.5) & 
        (df['is_healthcare'] == 1)
    )
    df.loc[mask_5, 'label'] = 5
    counts['critical'] = mask_5.sum()
    
    # Level 4 (High): Multiple strong signals
    # - Curated + KEV (confirmed healthcare breach with active exploitation)
    # - High EPSS + Healthcare (likely to be exploited in healthcare)
    # - Curated + High EPSS (confirmed breach with high exploit probability)
    mask_4 = (
        (df['label'] == 0) &  # Not already labeled
        (
            ((df['is_curated'] == 1) & (df['kev_flag'] == 1)) |
            ((df['epss_score'] > 0.5) & (df['is_healthcare'] == 1)) |
            ((df['is_curated'] == 1) & (df['epss_score'] > 0.5))
        )
    )
    df.loc[mask_4, 'label'] = 4
    counts['high'] = mask_4.sum()
    
    # Level 3 (Medium): Single strong signal or multiple moderate signals
    # - KEV flag (actively exploited, regardless of healthcare relevance)
    # - Curated dataset (confirmed healthcare breach)
    # - EPSS>0.3 + Healthcare (moderate exploit risk in healthcare)
    # - CVSS>=9.0 + Healthcare (critical severity + healthcare relevant)
    # - High EPSS alone (>0.6)
    mask_3 = (
        (df['label'] == 0) &
        (
            (df['kev_flag'] == 1) |
            (df['is_curated'] == 1) |
            ((df['epss_score'] > 0.3) & (df['is_healthcare'] == 1)) |
            ((df['cvss'] >= 9.0) & (df['is_healthcare'] == 1)) |
            (df['epss_score'] > 0.6)
        )
    )
    df.loc[mask_3, 'label'] = 3
    counts['medium'] = mask_3.sum()
    
    # Level 2 (Low): Weak signals indicating some relevance
    # - Healthcare relevant (sector match but no other signals)
    # - EPSS>0.1 (some exploit activity)
    # - CVSS>=7.0 (high severity but not healthcare-specific)
    # - Moderate EPSS (0.2-0.3)
    mask_2 = (
        (df['label'] == 0) &
        (
            (df['is_healthcare'] == 1) |
            (df['epss_score'] > 0.1) |
            (df['cvss'] >= 7.0) |
            (df['epss_score'] > 0.2)
        )
    )
    df.loc[mask_2, 'label'] = 2
    counts['low'] = mask_2.sum()
    
    # Level 1 (Informational): Minimal signals
    # - CVSS>=5.0 (medium severity)
    # - EPSS>0.01 (minimal exploit activity)
    mask_1 = (
        (df['label'] == 0) &
        (
            (df['cvss'] >= 5.0) |
            (df['epss_score'] > 0.01)
        )
    )
    df.loc[mask_1, 'label'] = 1
    counts['informational'] = mask_1.sum()
    
    # Level 0 (Irrelevant): No significant signals (remaining CVEs)
    counts['irrelevant'] = (df['label'] == 0).sum()
    
    # Log distribution
    logger.info(f"Label distribution: L5={counts['critical']}, L4={counts['high']}, " +
                f"L3={counts['medium']}, L2={counts['low']}, L1={counts['informational']}, " +
                f"L0={counts['irrelevant']}")
    
    # Add label descriptions
    label_descriptions = {
        5: "Critical - Curated breach + KEV + High EPSS + Healthcare",
        4: "High - Multiple strong signals (Curated+KEV or EPSS+Healthcare)",
        3: "Medium - Single strong signal (KEV, Curated, or high exploit risk)",
        2: "Low - Healthcare relevant or elevated exploit activity",
        1: "Informational - Minimal signals (medium severity or low EPSS)",
        0: "Irrelevant - No significant signals"
    }
    df['label_description'] = df['label'].map(label_descriptions)
    
    return df


def get_label_description(label: int) -> str:
    """Get human-readable description for a label value"""
    descriptions = {
        5: "Critical - Curated breach + KEV + High EPSS + Healthcare",
        4: "High - Multiple strong signals (Curated+KEV or EPSS+Healthcare)",
        3: "Medium - Single strong signal (KEV, Curated, or high exploit risk)",
        2: "Low - Healthcare relevant or elevated exploit activity",
        1: "Informational - Minimal signals (medium severity or low EPSS)",
        0: "Irrelevant - No significant signals"
    }
    return descriptions.get(label, "Unknown label")


def get_label_stats(df: pd.DataFrame) -> dict:
    """
    Get statistics about label distribution
    
    Args:
        df: DataFrame with 'label' column
    
    Returns:
        Dictionary with label counts and percentages
    """
    if 'label' not in df.columns:
        return {}
    
    total = len(df)
    stats = {}
    
    for label in range(6):
        count = (df['label'] == label).sum()
        pct = count / total * 100 if total > 0 else 0
        stats[label] = {
            'count': count,
            'percentage': pct,
            'description': get_label_description(label)
        }
    
    return stats


def print_label_summary(df: pd.DataFrame):
    """Print summary of label distribution"""
    stats = get_label_stats(df)
    
    print("\n" + "="*70)
    print("MULTI-LEVEL LABEL DISTRIBUTION")
    print("="*70)
    print(f"\nTotal CVEs: {len(df):,}\n")
    
    for label in sorted(stats.keys(), reverse=True):
        info = stats[label]
        bar_length = int(info['percentage'] / 2)
        bar = "█" * bar_length
        print(f"Level {label} ({info['count']:>6,} | {info['percentage']:>5.1f}%) {bar}")
        print(f"        {info['description']}\n")
    
    print("="*70 + "\n")


if __name__ == "__main__":
    # Test with sample data
    import numpy as np
    
    print("Testing Multi-Level Labeling System...")
    
    # Create test data with various signal combinations
    test_data = pd.DataFrame({
        'cve_id': [f'CVE-2024-{i:05d}' for i in range(1, 21)],
        'is_curated': [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'kev_flag': [1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        'epss_score': [0.8, 0.6, 0.7, 0.4, 0.2, 0.6, 0.4, 0.2, 0.15, 0.05, 0.3, 0.1, 0.02, 0.01, 0, 0, 0, 0, 0, 0],
        'is_healthcare': [1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0],
        'cvss': [9.8, 9.5, 8.0, 7.5, 9.0, 8.5, 7.0, 6.5, 8.0, 9.0, 7.5, 7.0, 6.0, 5.5, 9.5, 8.0, 7.0, 6.0, 5.0, 4.0],
        'curated_exploited': [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    })
    
    # Compute labels
    labeled = compute_multi_level_labels(test_data)
    
    # Print results
    print_label_summary(labeled)
    
    print("Sample CVEs by label:")
    for label in sorted(labeled['label'].unique(), reverse=True):
        samples = labeled[labeled['label'] == label][['cve_id', 'is_curated', 'kev_flag', 'epss_score', 'is_healthcare', 'cvss']].head(2)
        print(f"\nLabel {label}: {get_label_description(label)}")
        print(samples.to_string(index=False))
