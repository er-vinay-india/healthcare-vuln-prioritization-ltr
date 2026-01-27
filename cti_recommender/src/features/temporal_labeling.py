"""
Temporal Label Construction Module - Leakage-Free

This module implements temporal labeling for CVE prioritization that simulates
real-world prediction scenarios by:
1. Looking FORWARD from CVE publish date to construct labels
2. Using only information available at prediction time T for features

Key Principle: At time T (CVE published), predict if CVE becomes high-risk
in the NEXT 30-60 days based on future KEV addition or EPSS spike.
"""

from typing import Dict, List, Optional, Tuple
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
from pathlib import Path


def load_kev_with_dates(cache_dir: Path = None) -> pd.DataFrame:
    """
    Load KEV catalog with dateAdded information.
    
    Returns:
        DataFrame with columns: cve_id, kev_date_added
    """
    if cache_dir is None:
        cache_dir = Path(__file__).parent.parent.parent / 'cache' / 'kev'
    
    kev_path = cache_dir / 'kev_catalog.pkl.gz'
    
    if kev_path.exists():
        import pickle
        import gzip
        with gzip.open(kev_path, 'rb') as f:
            kev_data = pickle.load(f)
        
        # Handle different formats
        if isinstance(kev_data, pd.DataFrame):
            # Already a DataFrame - look for date column
            if 'dateadded' in kev_data.columns:
                result = kev_data[['cve_id', 'dateadded']].copy()
                result.columns = ['cve_id', 'kev_date_added']
                result['kev_date_added'] = pd.to_datetime(result['kev_date_added'], errors='coerce')
                return result
            elif 'dateAdded' in kev_data.columns:
                result = kev_data[['cve_id', 'dateAdded']].copy()
                result.columns = ['cve_id', 'kev_date_added']
                result['kev_date_added'] = pd.to_datetime(result['kev_date_added'], errors='coerce')
                return result
            elif 'kev_date_added' in kev_data.columns:
                result = kev_data[['cve_id', 'kev_date_added']].copy()
                result['kev_date_added'] = pd.to_datetime(result['kev_date_added'], errors='coerce')
                return result
            else:
                print(f"Warning: KEV DataFrame has no date column. Columns: {kev_data.columns.tolist()}")
                return pd.DataFrame(columns=['cve_id', 'kev_date_added'])
        
        # KEV catalog typically has 'vulnerabilities' list with 'cveID' and 'dateAdded'
        if isinstance(kev_data, dict) and 'vulnerabilities' in kev_data:
            kev_list = kev_data['vulnerabilities']
        elif isinstance(kev_data, list):
            kev_list = kev_data
        else:
            kev_list = []
        
        records = []
        for vuln in kev_list:
            cve_id = vuln.get('cveID') or vuln.get('cve_id')
            date_added = vuln.get('dateAdded') or vuln.get('date_added') or vuln.get('dateadded')
            if cve_id and date_added:
                records.append({
                    'cve_id': cve_id,
                    'kev_date_added': pd.to_datetime(date_added)
                })
        
        return pd.DataFrame(records)
    
    return pd.DataFrame(columns=['cve_id', 'kev_date_added'])


def load_epss_historical(cache_dir: Path = None) -> pd.DataFrame:
    """
    Load EPSS scores with date information.
    
    For proper temporal evaluation, we need EPSS scores at different points in time.
    This function loads available EPSS snapshots.
    
    Returns:
        DataFrame with columns: cve_id, epss_score, epss_date
    """
    if cache_dir is None:
        cache_dir = Path(__file__).parent.parent.parent / 'cache' / 'epss'
    
    records = []
    
    # Load all available EPSS snapshots
    for epss_file in cache_dir.glob('epss_*.json'):
        try:
            with open(epss_file, 'r') as f:
                epss_data = json.load(f)
            
            # Parse EPSS data - handle different formats
            if isinstance(epss_data, dict):
                if 'data' in epss_data:
                    # Format: {"data": [{"cve": "CVE-xxx", "epss": 0.1, ...}, ...]}
                    for item in epss_data['data']:
                        cve_id = item.get('cve')
                        epss_score = float(item.get('epss', 0))
                        epss_date = item.get('date')
                        if cve_id:
                            records.append({
                                'cve_id': cve_id,
                                'epss_score': epss_score,
                                'epss_date': pd.to_datetime(epss_date) if epss_date else datetime.now()
                            })
                else:
                    # Format: {"CVE-xxx": {"epss_score": 0.1, "date": "2026-01-16"}, ...}
                    for cve_id, score_data in epss_data.items():
                        if not cve_id.startswith('CVE-'):
                            continue
                        if isinstance(score_data, dict):
                            epss_score = float(score_data.get('epss_score', score_data.get('epss', 0)))
                            epss_date = score_data.get('date')
                        else:
                            epss_score = float(score_data)
                            epss_date = None
                        
                        records.append({
                            'cve_id': cve_id,
                            'epss_score': epss_score,
                            'epss_date': pd.to_datetime(epss_date) if epss_date else datetime.now()
                        })
                        
        except Exception as e:
            print(f"Warning: Could not load {epss_file}: {e}")
            continue
    
    if records:
        df = pd.DataFrame(records)
        print(f"Loaded EPSS data: {len(df):,} records for {df['cve_id'].nunique():,} unique CVEs")
        return df
    
    return pd.DataFrame(columns=['cve_id', 'epss_score', 'epss_date'])


def build_temporal_labels(
    df: pd.DataFrame,
    kev_df: pd.DataFrame = None,
    epss_df: pd.DataFrame = None,
    horizon_days: int = 30,
    current_date: datetime = None
) -> pd.DataFrame:
    """
    Build LEAKAGE-FREE temporal labels for CVE prioritization.
    
    For each CVE published at time T, look forward `horizon_days` to determine
    if it becomes high-risk (KEV addition or EPSS spike).
    
    Labeling Rules:
    - **Label 3 (Critical)**: CVE added to KEV within horizon window
    - **Label 2 (High)**: EPSS >= 0.5 within horizon window (but not KEV)
    - **Label 1 (Medium)**: EPSS in [0.1, 0.5) within horizon OR CVSS >= 7.0
    - **Label 0 (Low)**: Everything else
    
    Confidence Rules:
    - KEV-based labels: confidence = 1.0 (ground truth)
    - High EPSS labels: confidence = 0.80 (strong signal)
    - Medium EPSS labels: confidence = 0.60
    - CVSS-only labels: confidence = 0.35 (noisy baseline)
    
    Args:
        df: DataFrame with columns: cve_id, published, cvss, etc.
        kev_df: DataFrame with KEV dates (cve_id, kev_date_added)
        epss_df: DataFrame with EPSS history (cve_id, epss_score, epss_date)
        horizon_days: Days to look forward for label construction
        current_date: Current date for filtering (default: now)
    
    Returns:
        DataFrame with added columns: temporal_label, label_confidence, label_source
    """
    result = df.copy()
    n = len(result)
    
    if current_date is None:
        current_date = datetime.now()
    
    # Ensure published is datetime
    if 'published' in result.columns:
        result['published'] = pd.to_datetime(result['published'], errors='coerce')
    
    # Load KEV and EPSS data if not provided
    if kev_df is None:
        kev_df = load_kev_with_dates()
    
    if epss_df is None:
        epss_df = load_epss_historical()
    
    # Initialize labels
    temporal_label = np.zeros(n, dtype=int)
    label_confidence = np.full(n, 0.20)  # Base confidence
    label_source = np.full(n, 'default', dtype=object)
    
    # Create KEV lookup: cve_id -> kev_date_added
    kev_dates = {}
    if not kev_df.empty and 'kev_date_added' in kev_df.columns:
        for _, row in kev_df.iterrows():
            kev_dates[row['cve_id']] = pd.to_datetime(row['kev_date_added'])
    
    # Create EPSS lookup: cve_id -> list of (date, score)
    epss_history = {}
    if not epss_df.empty:
        for _, row in epss_df.iterrows():
            cve_id = row['cve_id']
            if cve_id not in epss_history:
                epss_history[cve_id] = []
            epss_history[cve_id].append((row['epss_date'], row['epss_score']))
    
    # Process each CVE
    for idx, row in result.iterrows():
        cve_id = row['cve_id']
        published = row.get('published')
        cvss = row.get('cvss', 0) or 0
        
        if pd.isna(published):
            continue
        
        # Define the horizon window: [published, published + horizon_days]
        horizon_end = published + timedelta(days=horizon_days)
        
        # Check 1: Was this CVE added to KEV within the horizon?
        kev_added_date = kev_dates.get(cve_id)
        if kev_added_date is not None:
            if published <= kev_added_date <= horizon_end:
                temporal_label[idx] = 3
                label_confidence[idx] = 1.0
                label_source[idx] = 'kev_within_horizon'
                continue
            elif kev_added_date < published:
                # KEV was already known at publish time - still critical
                temporal_label[idx] = 3
                label_confidence[idx] = 1.0
                label_source[idx] = 'kev_prior'
                continue
        
        # Check 2: Did EPSS spike within the horizon?
        cve_epss_history = epss_history.get(cve_id, [])
        max_epss_in_horizon = 0.0
        for epss_date, epss_score in cve_epss_history:
            if published <= epss_date <= horizon_end:
                max_epss_in_horizon = max(max_epss_in_horizon, epss_score)
        
        if max_epss_in_horizon >= 0.5:
            temporal_label[idx] = 2
            label_confidence[idx] = 0.80
            label_source[idx] = 'epss_high_horizon'
            continue
        
        if max_epss_in_horizon >= 0.1:
            temporal_label[idx] = 1
            label_confidence[idx] = 0.60
            label_source[idx] = 'epss_medium_horizon'
            continue
        
        # Check 3: CVSS-based baseline (noisy, but available at time T)
        if cvss >= 9.0:
            temporal_label[idx] = 1
            label_confidence[idx] = 0.40
            label_source[idx] = 'cvss_critical'
        elif cvss >= 7.0:
            temporal_label[idx] = 1
            label_confidence[idx] = 0.35
            label_source[idx] = 'cvss_high'
        else:
            temporal_label[idx] = 0
            label_confidence[idx] = 0.25
            label_source[idx] = 'default'
    
    # Add to dataframe
    result['temporal_label'] = temporal_label
    result['label_confidence'] = label_confidence
    result['label_source'] = label_source
    
    return result


def extract_temporal_features(
    df: pd.DataFrame,
    prediction_date: datetime = None
) -> pd.DataFrame:
    """
    Extract features using ONLY information available at prediction time T.
    
    This ensures no leakage from future KEV/EPSS status.
    
    Features available at time T (CVE published):
    - cvss: CVSS score (available at publish)
    - is_healthcare: Healthcare relevance (text-based, available at publish)
    - attack_technique_count: ATT&CK mapping (available shortly after publish)
    - days_since_published: Age of the CVE
    - cvss_severity_*: CVSS severity buckets
    
    Features NOT available at time T (EXCLUDED to prevent leakage):
    - kev_flag: Future KEV status (this is what we're predicting!)
    - epss_score: Future EPSS score (this is what we're predicting!)
    
    Args:
        df: DataFrame with CVE data
        prediction_date: Date at which prediction is made (default: now)
    
    Returns:
        DataFrame with leakage-free features
    """
    result = df.copy()
    
    if prediction_date is None:
        prediction_date = datetime.now()
    
    # Ensure published is datetime
    if 'published' in result.columns:
        result['published'] = pd.to_datetime(result['published'], errors='coerce')
    
    # === SAFE FEATURES (available at publish time) ===
    
    # CVSS (available when CVE is published)
    result['cvss_norm'] = result['cvss'].fillna(5.0) / 10.0
    result['cvss_critical'] = (result['cvss'] >= 9.0).astype(int)
    result['cvss_high'] = (result['cvss'] >= 7.0).astype(int)
    result['cvss_medium'] = ((result['cvss'] >= 4.0) & (result['cvss'] < 7.0)).astype(int)
    
    # Healthcare relevance (text-based, available at publish)
    result['is_healthcare'] = result.get('is_healthcare', pd.Series(0, index=result.index)).fillna(0).astype(int)
    
    # ATT&CK mapping (typically available shortly after publish)
    result['attack_technique_count'] = result.get('attack_technique_count', pd.Series(0, index=result.index)).fillna(0).astype(int)
    result['has_attack'] = (result['attack_technique_count'] > 0).astype(int)
    result['attack_multi'] = (result['attack_technique_count'] > 1).astype(int)
    
    # Temporal features (recency at prediction time)
    if 'published' in result.columns:
        result['days_since_published'] = (prediction_date - result['published']).dt.days.fillna(0).astype(int)
        result['recency_score'] = 1.0 / (1.0 + result['days_since_published'] / 365.0)
        result['is_recent'] = (result['days_since_published'] <= 90).astype(int)
    else:
        result['days_since_published'] = 0
        result['recency_score'] = 0.5
        result['is_recent'] = 0
    
    # Interaction features (safe - derived from safe features)
    result['healthcare_critical'] = (result['is_healthcare'] & result['cvss_critical']).astype(int)
    result['attack_healthcare'] = (result['has_attack'] & result['is_healthcare']).astype(int)
    
    # === EXPLICITLY EXCLUDE LEAKY FEATURES ===
    # Do NOT include: kev_flag, epss_score, epss_percentile
    # These are what we're trying to predict!
    
    return result


def get_temporal_feature_columns() -> List[str]:
    """
    Return list of leakage-free feature columns for model training.
    
    These features are available at CVE publish time and do not
    contain information about future KEV/EPSS status.
    """
    return [
        # Core CVSS features (available at publish)
        'cvss_norm',
        'cvss_critical',
        'cvss_high',
        'cvss_medium',
        
        # Healthcare relevance (text-based)
        'is_healthcare',
        
        # ATT&CK features (available shortly after publish)
        'attack_technique_count',
        'has_attack',
        'attack_multi',
        
        # Temporal features
        'days_since_published',
        'recency_score',
        'is_recent',
        
        # Interaction features
        'healthcare_critical',
        'attack_healthcare',
    ]


def print_temporal_label_diagnostics(df: pd.DataFrame) -> Dict:
    """
    Print comprehensive diagnostics for temporal labels.
    
    Args:
        df: DataFrame with temporal_label, label_confidence, label_source
    
    Returns:
        Dict with diagnostic statistics
    """
    print("=" * 70)
    print("TEMPORAL LABEL DIAGNOSTICS (Leakage-Free)")
    print("=" * 70)
    
    total = len(df)
    stats = {}
    
    # 1. Label distribution
    print("\n1. TEMPORAL LABEL DISTRIBUTION")
    print("-" * 40)
    label_counts = df['temporal_label'].value_counts().sort_index()
    for label, count in label_counts.items():
        pct = 100 * count / total
        bar = "#" * int(pct / 2)
        print(f"  Label {label}: {count:>8,} ({pct:>5.2f}%) {bar}")
        stats[f'label_{label}_count'] = count
        stats[f'label_{label}_pct'] = pct
    
    # 2. Label source breakdown
    print("\n2. LABEL SOURCE BREAKDOWN")
    print("-" * 40)
    source_counts = df['label_source'].value_counts()
    for source, count in source_counts.items():
        pct = 100 * count / total
        print(f"  {source:25s}: {count:>8,} ({pct:>5.2f}%)")
        stats[f'source_{source}'] = count
    
    # 3. Confidence distribution
    print("\n3. CONFIDENCE DISTRIBUTION")
    print("-" * 40)
    print(f"  Min:    {df['label_confidence'].min():.3f}")
    print(f"  Mean:   {df['label_confidence'].mean():.3f}")
    print(f"  Median: {df['label_confidence'].median():.3f}")
    print(f"  Max:    {df['label_confidence'].max():.3f}")
    
    stats['confidence_mean'] = df['label_confidence'].mean()
    stats['confidence_median'] = df['label_confidence'].median()
    
    # 4. High-confidence labels
    high_conf = df[df['label_confidence'] >= 0.8]
    print(f"\n4. HIGH-CONFIDENCE LABELS (≥0.8): {len(high_conf):,} ({100*len(high_conf)/total:.2f}%)")
    if len(high_conf) > 0:
        print(f"   Label distribution: {high_conf['temporal_label'].value_counts().to_dict()}")
    
    stats['high_conf_count'] = len(high_conf)
    
    print("\n" + "=" * 70)
    
    return stats


def create_temporal_train_test_split(
    df: pd.DataFrame,
    train_end_date: str = '2024-10-01',
    test_start_date: str = '2024-10-01',
    horizon_days: int = 30
) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Create train/test split ensuring temporal validity.
    
    For valid evaluation:
    - Training data: CVEs published before train_end_date
    - Test data: CVEs published after test_start_date
    - Gap between train and test >= horizon_days to prevent leakage
    
    Args:
        df: DataFrame with temporal labels and features
        train_end_date: End date for training data
        test_start_date: Start date for test data
        horizon_days: Label horizon (ensures gap)
    
    Returns:
        Tuple of (train_df, test_df)
    """
    df = df.copy()
    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    
    train_end = pd.to_datetime(train_end_date)
    test_start = pd.to_datetime(test_start_date)
    
    # Ensure gap between train and test
    min_gap = timedelta(days=horizon_days)
    if test_start - train_end < min_gap:
        print(f"Warning: Gap between train_end and test_start < {horizon_days} days")
        print(f"  Adjusting test_start to {train_end + min_gap}")
        test_start = train_end + min_gap
    
    train_df = df[df['published'] < train_end].copy()
    test_df = df[df['published'] >= test_start].copy()
    
    print(f"Temporal Train/Test Split:")
    print(f"  Train: {len(train_df):,} CVEs (published < {train_end.date()})")
    print(f"  Test:  {len(test_df):,} CVEs (published >= {test_start.date()})")
    print(f"  Gap:   {(test_start - train_end).days} days (≥{horizon_days} required)")
    
    return train_df, test_df
