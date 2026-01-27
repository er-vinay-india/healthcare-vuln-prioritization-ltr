"""
Weak Label Construction Module

This module implements weak supervision for CVE prioritization,
building soft labels with confidence scores based on multiple signals.
"""

from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np


def build_weak_labels(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build soft labels and confidence scores using weak supervision.
    
    This is the CORE INNOVATION: Labels are weighted by their trustworthiness.
    
    Labeling Rules:
    - **Label 3 (Critical)**: KEV=1 AND (is_healthcare=1 OR chpl_flag=1) - Confirmed exploit + healthcare context
    - **Label 2 (High)**: KEV=1 OR (High EPSS AND ATT&CK mapping)
    - **Label 1 (Medium)**: Medium EPSS OR ATT&CK OR (High CVSS AND Recent)
    - **Label 0 (Low)**: Everything else
    
    Confidence Rules:
    - KEV signals get confidence = 1.0 (ground truth)
    - High EPSS gets confidence = 0.75
    - Medium EPSS gets confidence = 0.55
    - ATT&CK/Healthcare add +0.10 bonus
    - CVSS/recency-only labels capped at 0.40 (noisy)
    
    Returns:
        DataFrame with added columns: soft_label, label_confidence, label_source
    """
    result = df.copy()
    n = len(result)
    
    # Initialize
    soft_label = np.zeros(n, dtype=int)
    label_confidence = np.full(n, 0.2)  # Base confidence
    label_source = np.full(n, 'default', dtype=object)
    
    # Extract signals (with defensive handling)
    kev = result.get('kev_flag', pd.Series(0, index=result.index)).fillna(0).values.astype(int)
    epss = result.get('epss_score', pd.Series(0.0, index=result.index)).fillna(0.0).values
    epss_pct = result.get('epss_percentile', pd.Series(0.0, index=result.index)).fillna(0.0).values
    attack_count = result.get('attack_technique_count', pd.Series(0, index=result.index)).fillna(0).values.astype(int)
    has_attack = result.get('has_attack', pd.Series(0, index=result.index)).fillna(0).values.astype(int)
    healthcare = result.get('is_healthcare', pd.Series(0, index=result.index)).fillna(0).values.astype(int)
    chpl = result.get('chpl_flag', pd.Series(0, index=result.index)).fillna(0).values.astype(int)
    cvss_norm = result.get('cvss_norm', pd.Series(0.5, index=result.index)).fillna(0.5).values
    recency = result.get('recency_score', pd.Series(0.5, index=result.index)).fillna(0.5).values
    
    # === LABEL ASSIGNMENT (graded 0-3) ===
    
    # Label 3: KEV + Healthcare context (strongest signal)
    mask_label3 = (kev == 1) & ((healthcare == 1) | (chpl == 1))
    soft_label[mask_label3] = 3
    label_source[mask_label3] = 'kev_healthcare'
    
    # Label 2: KEV alone OR (High EPSS AND ATT&CK)
    high_epss = (epss >= 0.50) | (epss_pct >= 0.90)
    has_attack_signal = (attack_count >= 1) | (has_attack == 1)
    mask_label2 = (soft_label == 0) & ((kev == 1) | (high_epss & has_attack_signal))
    soft_label[mask_label2] = 2
    label_source[mask_label2] = np.where(kev[mask_label2] == 1, 'kev_only', 'epss_attack')
    
    # Label 1: Medium EPSS OR ATT&CK mapping OR (High CVSS + Recent)
    medium_epss = ((epss >= 0.10) & (epss < 0.50)) | ((epss_pct >= 0.70) & (epss_pct < 0.90))
    cvss_recency_signal = (cvss_norm >= 0.70) & (recency >= 0.40)
    mask_label1 = (soft_label == 0) & (medium_epss | (attack_count >= 1) | cvss_recency_signal)
    soft_label[mask_label1] = 1
    
    # Track source for label 1
    label1_sources = np.full(n, '', dtype=object)
    label1_sources[mask_label1 & medium_epss] = 'medium_epss'
    label1_sources[mask_label1 & (attack_count >= 1) & ~medium_epss] = 'attack_mapping'
    label1_sources[mask_label1 & cvss_recency_signal & ~medium_epss & (attack_count < 1)] = 'cvss_recency'
    label_source[mask_label1] = label1_sources[mask_label1]
    
    # === CONFIDENCE ASSIGNMENT ===
    
    # KEV signals: highest confidence
    label_confidence[kev == 1] = 1.0
    
    # High EPSS (non-KEV): high confidence
    high_epss_non_kev = high_epss & (kev == 0)
    label_confidence[high_epss_non_kev] = np.maximum(label_confidence[high_epss_non_kev], 0.75)
    
    # Medium EPSS (non-KEV, non-high-EPSS): medium confidence
    medium_epss_only = medium_epss & (kev == 0) & ~high_epss
    label_confidence[medium_epss_only] = np.maximum(label_confidence[medium_epss_only], 0.55)
    
    # ATT&CK bonus: +0.10
    attack_bonus = (attack_count >= 1) | (has_attack == 1)
    label_confidence[attack_bonus] = np.minimum(label_confidence[attack_bonus] + 0.10, 1.0)
    
    # Healthcare/CHPL bonus: +0.10
    healthcare_bonus = (healthcare == 1) | (chpl == 1)
    label_confidence[healthcare_bonus] = np.minimum(label_confidence[healthcare_bonus] + 0.10, 1.0)
    
    # CVSS/recency-only labels: CAP at 0.40 (these are noisy!)
    cvss_recency_only = (label_source == 'cvss_recency')
    label_confidence[cvss_recency_only] = np.minimum(label_confidence[cvss_recency_only], 0.40)
    
    # Ensure minimum confidence
    label_confidence = np.maximum(label_confidence, 0.1)
    
    # Add to dataframe
    result['soft_label'] = soft_label
    result['label_confidence'] = label_confidence
    result['label_source'] = label_source
    
    return result


def print_label_diagnostics(df: pd.DataFrame) -> None:
    """
    Print comprehensive diagnostics for weak labels and confidence scores.
    
    Includes:
    - Label distribution
    - Label source breakdown
    - Confidence statistics and histogram
    - Cross-tabulations with KEV, EPSS, healthcare
    - High-confidence and low-confidence examples
    
    Args:
        df: DataFrame with soft_label, label_confidence, label_source columns
    """
    print("=" * 70)
    print("LABEL DISTRIBUTION DIAGNOSTICS")
    print("=" * 70)
    
    # 1. Soft label distribution
    print("\n1. SOFT LABEL DISTRIBUTION")
    print("-" * 40)
    label_counts = df['soft_label'].value_counts().sort_index()
    total = len(df)
    for label, count in label_counts.items():
        pct = 100 * count / total
        bar = "#" * int(pct)
        print(f"  Label {label}: {count:>8,} ({pct:>5.2f}%) {bar}")
    
    # 2. Label source breakdown
    print("\n2. LABEL SOURCE BREAKDOWN")
    print("-" * 40)
    source_counts = df['label_source'].value_counts()
    for source, count in source_counts.items():
        print(f"  {source:20s}: {count:>8,} ({100*count/total:>5.2f}%)")
    
    # 3. Confidence statistics
    print("\n3. LABEL CONFIDENCE STATISTICS")
    print("-" * 40)
    conf = df['label_confidence']
    print(f"  Min:    {conf.min():.3f}")
    print(f"  Mean:   {conf.mean():.3f}")
    print(f"  Median: {conf.median():.3f}")
    print(f"  Max:    {conf.max():.3f}")
    print(f"  Std:    {conf.std():.3f}")
    
    # Confidence histogram
    print("\n  Confidence Distribution:")
    bins = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0, 1.01]
    bin_labels = ['0.0-0.2', '0.2-0.4', '0.4-0.6', '0.6-0.8', '0.8-1.0', '1.0']
    hist, _ = np.histogram(conf, bins=bins)
    for label, count in zip(bin_labels, hist):
        pct = 100 * count / total
        bar = "#" * int(pct / 2)
        print(f"    {label}: {count:>8,} ({pct:>5.2f}%) {bar}")
    
    # 4. Cross-tabulation: soft_label vs kev_flag
    if 'kev_flag' in df.columns:
        print("\n4. CROSS-TAB: soft_label vs kev_flag")
        print("-" * 40)
        crosstab_kev = pd.crosstab(df['soft_label'], df['kev_flag'], margins=True)
        print(crosstab_kev.to_string())
    
    # 5. Cross-tabulation: soft_label vs EPSS buckets
    if 'epss_score' in df.columns:
        print("\n5. CROSS-TAB: soft_label vs EPSS buckets")
        print("-" * 40)
        df_temp = df.copy()
        df_temp['epss_bucket'] = pd.cut(df_temp['epss_score'], 
                                   bins=[-0.01, 0.10, 0.50, 0.90, 1.01],
                                   labels=['<0.10', '0.10-0.50', '0.50-0.90', '>0.90'])
        crosstab_epss = pd.crosstab(df_temp['soft_label'], df_temp['epss_bucket'], margins=True)
        print(crosstab_epss.to_string())
    
    # 6. Cross-tabulation: soft_label vs is_healthcare
    if 'is_healthcare' in df.columns:
        print("\n6. CROSS-TAB: soft_label vs is_healthcare")
        print("-" * 40)
        crosstab_health = pd.crosstab(df['soft_label'], df['is_healthcare'], margins=True)
        print(crosstab_health.to_string())
    
    # 7. High-confidence label-3 examples
    print("\n7. TOP 20 HIGHEST-CONFIDENCE LABEL-3 EXAMPLES")
    print("-" * 40)
    label3 = df[df['soft_label'] == 3].nlargest(20, 'label_confidence')
    if len(label3) > 0:
        cols = ['cve_id', 'published', 'soft_label', 'label_confidence', 'kev_flag', 
                'epss_score', 'is_healthcare', 'label_source']
        cols = [c for c in cols if c in label3.columns]
        print(label3[cols].to_string(index=False))
    else:
        print("  No label-3 samples found")
    
    # 8. Low-confidence label-1 examples
    print("\n8. TOP 20 LOWEST-CONFIDENCE LABEL-1 EXAMPLES")
    print("-" * 40)
    label1 = df[df['soft_label'] == 1].nsmallest(20, 'label_confidence')
    if len(label1) > 0:
        cols = ['cve_id', 'published', 'soft_label', 'label_confidence', 'cvss_norm',
                'recency_score', 'label_source']
        cols = [c for c in cols if c in label1.columns]
        print(label1[cols].to_string(index=False))
    else:
        print("  No label-1 samples found")
    
    print("\n" + "=" * 70)


def validate_label_quality(
    labels: pd.Series,
    confidence: pd.Series,
    ground_truth: Optional[pd.Series] = None
) -> Dict:
    """
    Validate weak label quality metrics.
    
    Args:
        labels: Weak labels
        confidence: Confidence scores
        ground_truth: Optional ground truth labels for validation
    
    Returns:
        Dict with quality metrics
    """
    # TODO: Implement quality validation
    # - Check label distribution balance
    # - Confidence calibration
    # - If ground_truth available, compute agreement
    raise NotImplementedError("To be implemented")


def get_default_label_weights() -> Dict[str, float]:
    """
    Return default weights for weak label signals.
    
    Returns:
        Dict mapping signal names to weights
    """
    return {
        'kev_flag': 1.0,          # Strong positive signal
        'healthcare_flag': 0.8,    # Strong positive signal
        'cvss_high': 0.5,          # Moderate signal (CVSS >= 9.0)
        'epss_high': 0.4,          # Moderate signal (EPSS >= 0.5)
        'attack_mapped': 0.3,      # Weak signal (has ATT&CK mappings)
    }
