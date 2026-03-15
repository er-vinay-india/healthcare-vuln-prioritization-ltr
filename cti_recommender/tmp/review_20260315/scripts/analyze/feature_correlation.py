#!/usr/bin/env python3
"""
Feature Correlation Analysis.
Identifies redundant features that can be removed.
"""
import sys
from pathlib import Path
# Add project root to path (scripts/analyze/ -> scripts/ -> project root)
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from scipy.stats import spearmanr

from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def load_data():
    """Load enriched CVE data."""
    logger.info("Loading data from database...")
    db = CVEDatabase()
    
    # Disable automatic timestamp conversion
    import sqlite3
    sqlite3.register_adapter(type(None), lambda x: None)
    
    query = """
    SELECT 
        e.kev_flag,
        e.epss_score,
        e.epss_percentile,
        e.is_healthcare,
        e.is_curated,
        e.chpl_flag,
        e.attack_flag,
        e.attack_technique_count,
        e.label,
        c.cvss,
        CAST(c.published AS TEXT) as published
    FROM enrichments e
    LEFT JOIN cves c ON e.cve_id = c.cve_id
    WHERE c.cvss IS NOT NULL
    """
    
    df = pd.read_sql_query(query, db.conn)
    db.close()
    
    df['published'] = pd.to_datetime(df['published'], errors='coerce')
    logger.info(f"Loaded {len(df):,} CVEs", extra={'cve_count': len(df)})
    return df

def prepare_features(df):
    """Extract all features for correlation analysis."""
    features = pd.DataFrame({
        'kev_flag': df['kev_flag'],
        'epss_score': df['epss_score'].fillna(0.0),
        'epss_percentile': df['epss_percentile'].fillna(0.0),
        'is_healthcare': df['is_healthcare'],
        'is_curated': df['is_curated'],
        'chpl_flag': df['chpl_flag'].fillna(0).astype(int),
        'attack_flag': df['attack_flag'].fillna(0).astype(int),
        'attack_technique_count': df['attack_technique_count'].fillna(0).astype(int),
        'cvss': df['cvss'].fillna(0.0),
    })
    
    # Engineered features
    features['cvss_high'] = (features['cvss'] >= 7.0).astype(int)
    features['cvss_critical'] = (features['cvss'] >= 9.0).astype(int)
    features['epss_high'] = (features['epss_score'] >= 0.1).astype(int)
    features['healthcare_critical'] = (features['is_healthcare'] & features['cvss_critical']).astype(int)
    features['kev_healthcare'] = (features['kev_flag'] & features['is_healthcare']).astype(int)
    features['chpl_healthcare'] = (features['chpl_flag'] & features['is_healthcare']).astype(int)
    features['attack_healthcare'] = (features['attack_flag'] & features['is_healthcare']).astype(int)
    features['attack_multi'] = (features['attack_technique_count'] > 1).astype(int)
    
    # Interaction features
    features['healthcare_x_cvss'] = features['is_healthcare'] * features['cvss']
    features['kev_x_epss'] = features['kev_flag'] * features['epss_score']
    features['chpl_x_attack'] = features['chpl_flag'] * features['attack_flag']
    features['attack_count_x_healthcare'] = features['attack_technique_count'] * features['is_healthcare']
    
    # Recency
    baseline_date = pd.to_datetime('2018-01-01')
    features['days_since_2018'] = (df['published'] - baseline_date).dt.days.fillna(0).astype(int)
    features['is_recent'] = (features['days_since_2018'] > 2500).astype(int)
    
    return features

def analyze_correlations(features):
    """Compute and analyze feature correlations."""
    logger.info("="*70)
    logger.info("FEATURE CORRELATION ANALYSIS")
    logger.info("="*70)
    
    # Compute correlation matrix (Spearman for robustness to non-linear relationships)
    corr_matrix = features.corr(method='spearman')
    
    # Find highly correlated pairs
    logger.info(" Highly Correlated Feature Pairs (|r| > 0.8):")
    logger.info("-" * 70)
    
    high_corr_pairs = []
    n_features = len(features.columns)
    
    for i in range(n_features):
        for j in range(i + 1, n_features):
            corr = corr_matrix.iloc[i, j]
            if abs(corr) > 0.8:
                feat1 = features.columns[i]
                feat2 = features.columns[j]
                high_corr_pairs.append((feat1, feat2, corr))
                logger.info(f"  {feat1:30s} <-> {feat2:30s}  r={corr:6.3f}")
    
    if not high_corr_pairs:
        logger.info("  [OK] No highly correlated pairs found!")
    
    # Analyze EPSS-related features
    logger.info("EPSS Feature Correlations:")
    logger.info("-" * 70)
    epss_features = ['epss_score', 'epss_percentile', 'epss_high', 'kev_x_epss']
    for feat in epss_features:
        if feat in corr_matrix.columns:
            logger.info(f"  {feat}:")
            correlations = corr_matrix[feat].drop(feat).sort_values(ascending=False)
            for other_feat, corr in correlations.head(5).items():
                logger.info(f"    {other_feat:30s}: {corr:6.3f}")
    
    # Analyze healthcare-related features
    logger.info(" Healthcare Feature Correlations:")
    logger.info("-" * 70)
    healthcare_features = ['is_healthcare', 'healthcare_critical', 'healthcare_x_cvss', 
                           'kev_healthcare', 'chpl_healthcare', 'attack_healthcare']
    for feat in healthcare_features:
        if feat in corr_matrix.columns:
            logger.info(f"  {feat}:")
            correlations = corr_matrix[feat].drop(feat).sort_values(ascending=False)
            for other_feat, corr in correlations.head(3).items():
                logger.info(f"    {other_feat:30s}: {corr:6.3f}")
    
    return corr_matrix, high_corr_pairs

def plot_correlation_heatmap(corr_matrix):
    """Create interactive correlation heatmap visualization using plotly."""
    logger.info("Generating correlation heatmap...")
    
    # Create interactive heatmap with plotly
    fig = go.Figure(data=go.Heatmap(
        z=corr_matrix.values,
        x=corr_matrix.columns,
        y=corr_matrix.columns,
        colorscale='RdBu',
        zmid=0,
        zmin=-1,
        zmax=1,
        colorbar=dict(title="Correlation"),
        hoverongaps=False,
        hovertemplate='%{x}<br>%{y}<br>Correlation: %{z:.3f}<extra></extra>'
    ))
    
    fig.update_layout(
        title='Feature Correlation Matrix (Spearman)',
        xaxis_title='',
        yaxis_title='',
        width=1200,
        height=1100,
        xaxis={'side': 'bottom'},
        yaxis={'autorange': 'reversed'}
    )
    
    # Save as HTML for interactivity and PNG for static view
    output_dir = Path(__file__).parent.parent / 'outputs'
    output_dir.mkdir(parents=True, exist_ok=True)
    
    html_path = output_dir / 'feature_correlation_heatmap.html'
    fig.write_html(html_path)
    logger.info(f"  Saved interactive: {html_path}")
    
    # Also save static image
    try:
        png_path = output_dir / 'feature_correlation_heatmap.png'
        fig.write_image(png_path, width=1200, height=1100)
        logger.info(f"  Saved static: {png_path}")
    except Exception as e:
        logger.warning(f"  Could not save PNG (requires kaleido): {e}")

def recommend_removals(high_corr_pairs, features):
    """Recommend which features to remove."""
    logger.info("="*70)
    logger.info("RECOMMENDATIONS")
    logger.info("="*70)
    
    if not high_corr_pairs:
        logger.info("[OK] No highly correlated features found.")
        logger.info("   All features provide unique information.")
        return
    
    logger.info("[TIP] Consider removing one from each correlated pair:")
    logger.info("-" * 70)
    
    for feat1, feat2, corr in high_corr_pairs:
        # Heuristic: Keep the simpler feature
        if 'x' in feat2 or '_' in feat2:
            keep, remove = feat1, feat2
        else:
            keep, remove = feat2, feat1
        
        logger.info(f"  Pair: {feat1} <-> {feat2} (r={corr:.3f})")
        logger.info(f"    -> Keep:   {keep}")
        logger.info(f"    -> Remove: {remove} (redundant)")
    
    # Feature variance analysis
    logger.info(" Low Variance Features (may not be useful):")
    logger.info("-" * 70)
    variances = features.var().sort_values()
    low_var = variances[variances < 0.01]
    
    if len(low_var) > 0:
        for feat, var in low_var.items():
            logger.info(f"  {feat:30s}: variance = {var:.6f}")
    else:
        logger.info("  [OK] All features have sufficient variance")

def main():
    logger.info("="*70)
    logger.info("FEATURE CORRELATION ANALYSIS")
    logger.info("="*70)
    
    # Load and prepare data
    df = load_data()
    features = prepare_features(df)
    
    logger.info(f"Analyzing {len(features.columns)} features:", extra={'feature_count': len(features.columns)})
    for i, col in enumerate(features.columns, 1):
        logger.info(f"  {i:2d}. {col}")
    
    # Analyze correlations
    corr_matrix, high_corr_pairs = analyze_correlations(features)
    
    # Plot heatmap
    try:
        plot_correlation_heatmap(corr_matrix)
    except Exception as e:
        logger.warning(f"Could not generate heatmap: {e}")
        logger.warning("(plotly may not be configured for display)")
    
    # Recommendations
    recommend_removals(high_corr_pairs, features)
    
    # Save correlation matrix
    output_path = Path(__file__).parent.parent / 'outputs' / 'feature_correlations.csv'
    corr_matrix.to_csv(output_path)
    logger.info(f"Correlation matrix saved: {output_path}")
    
    print("\n" + "="*70)
    print("[OK] Correlation analysis complete!")
    print("="*70)

if __name__ == "__main__":
    main()
