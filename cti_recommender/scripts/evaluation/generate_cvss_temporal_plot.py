"""
Generate CVSS temporal trend plot showing CVE distribution by year with average CVSS scores
"""
import sys
import sqlite3
from pathlib import Path
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)


def load_cvss_temporal_data(db_path: str = 'data/cve_database.db') -> pd.DataFrame:
    query = """
    SELECT 
        strftime('%Y', published) as year,
        COUNT(*) as total_cves,
        COUNT(cvss) as has_cvss,
        ROUND(AVG(cvss), 2) as avg_cvss,
        ROUND(MIN(cvss), 2) as min_cvss,
        ROUND(MAX(cvss), 2) as max_cvss
    FROM cves
    WHERE published IS NOT NULL
    GROUP BY year
    ORDER BY year
    """

    conn = sqlite3.connect(db_path)
    try:
        df = pd.read_sql_query(query, conn)
    except Exception:
        logger.exception("Failed to load CVSS temporal data from %s", db_path)
        raise
    finally:
        conn.close()

    return df


def build_cvss_temporal_plot(df: pd.DataFrame):
    fig = make_subplots(specs=[[{"secondary_y": True}]])

    fig.add_trace(
        go.Bar(
            x=df['year'],
            y=df['total_cves'],
            name='Total CVEs',
            marker_color='lightblue',
            opacity=0.7
        ),
        secondary_y=False,
    )

    fig.add_trace(
        go.Scatter(
            x=df['year'],
            y=df['avg_cvss'],
            name='Average CVSS',
            mode='lines+markers',
            line=dict(color='red', width=3),
            marker=dict(size=8)
        ),
        secondary_y=True,
    )

    fig.update_layout(
        title='CVE Distribution by Year with CVSS Score Trends (2018-2025)',
        xaxis_title='Year',
        hovermode='x unified',
        height=500,
        showlegend=True,
        legend=dict(x=0.02, y=0.98),
        template='plotly_white'
    )

    fig.update_yaxes(title_text="<b>Number of CVEs</b>", secondary_y=False)
    fig.update_yaxes(title_text="<b>Average CVSS Score</b>", secondary_y=True, range=[0, 10])
    return fig


def main() -> int:
    try:
        df = load_cvss_temporal_data()
        if df.empty:
            logger.warning("No rows returned for CVSS temporal plot")
            return 1

        fig = build_cvss_temporal_plot(df)

        output_path = Path('outputs/plots/cvss_temporal_trends.html')
        output_path.parent.mkdir(parents=True, exist_ok=True)
        fig.write_html(str(output_path))

        logger.info("✓ Plot saved to: %s", output_path)
        logger.info("Dataset: %s total CVEs", f"{df['total_cves'].sum():,}")
        logger.info("CVSS Range: %.2f - %.2f (yearly averages)", df['avg_cvss'].min(), df['avg_cvss'].max())
        logger.info("Trend: %.2f (2018) → %.2f (2025)", df.iloc[0]['avg_cvss'], df.iloc[-1]['avg_cvss'])
        return 0
    except Exception:
        logger.exception("Failed to generate CVSS temporal plot")
        return 1


if __name__ == '__main__':
    sys.exit(main())
