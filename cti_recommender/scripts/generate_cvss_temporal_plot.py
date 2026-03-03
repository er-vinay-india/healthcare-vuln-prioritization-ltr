"""
Generate CVSS temporal trend plot showing CVE distribution by year with average CVSS scores
"""
import sqlite3
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import pandas as pd

# Connect to database
conn = sqlite3.connect('data/cve_database.db')

# Query CVE distribution by year with CVSS statistics
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

df = pd.read_sql_query(query, conn)
conn.close()

# Create figure with secondary y-axis
fig = make_subplots(specs=[[{"secondary_y": True}]])

# Add bar chart for CVE count
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

# Add line chart for average CVSS
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

# Add layout
fig.update_layout(
    title='CVE Distribution by Year with CVSS Score Trends (2018-2025)',
    xaxis_title='Year',
    hovermode='x unified',
    height=500,
    showlegend=True,
    legend=dict(x=0.02, y=0.98),
    template='plotly_white'
)

# Update y-axes
fig.update_yaxes(title_text="<b>Number of CVEs</b>", secondary_y=False)
fig.update_yaxes(title_text="<b>Average CVSS Score</b>", secondary_y=True, range=[0, 10])

# Save to outputs/plots
output_path = 'outputs/plots/cvss_temporal_trends.html'
fig.write_html(output_path)
print(f"✓ Plot saved to: {output_path}")
print(f"\nDataset: {df['total_cves'].sum():,} total CVEs")
print(f"CVSS Range: {df['avg_cvss'].min():.2f} - {df['avg_cvss'].max():.2f} (yearly averages)")
print(f"Trend: {df.iloc[0]['avg_cvss']:.2f} (2018) → {df.iloc[-1]['avg_cvss']:.2f} (2025)")
