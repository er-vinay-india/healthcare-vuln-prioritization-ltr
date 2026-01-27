"""
CVE Data Loading Module

This module handles loading CVE data from the SQLite database,
including all enrichments (EPSS, KEV, ATT&CK, CHPL, healthcare mappings).
"""

import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import pandas as pd
from src.core.cve_database import CVEDatabase


def load_cves_from_db(
    db_path: Optional[str] = None,
    filters: Optional[Dict] = None,
    include_enrichments: bool = True
) -> pd.DataFrame:
    """
    Load CVEs from SQLite database with all enrichments.
    
    Args:
        db_path: Path to SQLite database (if None, uses CVEDatabase default)
        filters: Optional dict of filters (e.g., {'cvss_min': 7.0})
        include_enrichments: Whether to include EPSS, KEV, ATT&CK, etc.
    
    Returns:
        DataFrame with CVE data and enrichments
    """
    # Connect to database
    db = CVEDatabase() if db_path is None else CVEDatabase(db_path=db_path)
    
    # Load CVEs table
    cves_df = pd.read_sql("SELECT * FROM cves", db.conn)
    
    if include_enrichments:
        # Load enrichments table
        enrichments_df = pd.read_sql("SELECT * FROM enrichments", db.conn)
        
        # Merge CVEs with enrichments
        df = cves_df.merge(enrichments_df, on='cve_id', how='left')
    else:
        df = cves_df
    
    # Convert dates to datetime
    df['published'] = pd.to_datetime(df['published'])
    if 'modified' in df.columns:
        df['modified'] = pd.to_datetime(df['modified'], errors='coerce')
    
    # Apply filters if provided
    if filters:
        if 'cvss_min' in filters:
            df = df[df['cvss'] >= filters['cvss_min']]
        if 'cvss_max' in filters:
            df = df[df['cvss'] <= filters['cvss_max']]
        if 'kev_only' in filters and filters['kev_only']:
            df = df[df['kev_flag'] == 1]
        if 'healthcare_only' in filters and filters['healthcare_only']:
            df = df[df['is_healthcare'] == 1]
    
    print(f"Loaded {len(df):,} CVEs from database")
    
    return df


def get_data_summary(df: pd.DataFrame) -> Dict:
    """
    Generate summary statistics for loaded CVE data.
    
    Args:
        df: DataFrame with CVE data
    
    Returns:
        Dict with summary statistics
    """
    summary = {
        'total_cves': len(df),
        'date_range': {
            'min': df['published'].min(),
            'max': df['published'].max()
        }
    }
    
    # Enrichment coverage
    enrichment_cols = ['kev_flag', 'epss_score', 'is_healthcare', 'attack_technique_count', 'chpl_flag']
    for col in enrichment_cols:
        if col in df.columns:
            non_null = df[col].notna().sum()
            summary[f'{col}_coverage'] = {
                'count': non_null,
                'percentage': 100 * non_null / len(df)
            }
    
    # Print summary
    print("=" * 50)
    print("DATA SUMMARY")
    print("=" * 50)
    print(f"Total CVEs: {summary['total_cves']:,}")
    print(f"Date range: {summary['date_range']['min'].date()} to {summary['date_range']['max'].date()}")
    print("\nEnrichment Coverage:")
    for col in enrichment_cols:
        if f'{col}_coverage' in summary:
            cov = summary[f'{col}_coverage']
            print(f"  {col}: {cov['count']:,} ({cov['percentage']:.1f}%)")
    
    return summary


def query_cves_by_date_range(
    db_path: str,
    start_date: str,
    end_date: str
) -> pd.DataFrame:
    """
    Query CVEs within a specific date range.
    
    Args:
        db_path: Path to SQLite database
        start_date: Start date (ISO format: YYYY-MM-DD)
        end_date: End date (ISO format: YYYY-MM-DD)
    
    Returns:
        DataFrame with CVEs in date range
    """
    # TODO: Implement date-based query
    raise NotImplementedError("To be implemented")
