#!/bin/bash
# Monitor enrichment progress in real-time

echo "==================================================================="
echo "           CHPL ENRICHMENT PROGRESS MONITOR"
echo "==================================================================="
echo ""

# Check if process is running
if ps aux | grep -q "[p]ython scripts/enrich_cves.py"; then
    echo "✅ Enrichment process is RUNNING"
    echo ""
else
    echo "⚠️  Enrichment process NOT FOUND"
    echo ""
fi

# Show latest log entries
echo "📊 Latest Progress:"
echo "-------------------------------------------------------------------"
tail -20 /tmp/enrich_cves.log | grep -E "(Batch|PHASE|enriched|CHPL:)"
echo ""

# Show database CHPL count
echo "📈 Current Database Status:"
echo "-------------------------------------------------------------------"
cd /Users/vinayksharma/AirDnd/cti_recommender
source venv/bin/activate 2>/dev/null
python -c "
import sqlite3
conn = sqlite3.connect('data/cve_database.db')
cursor = conn.cursor()
cursor.execute('SELECT COUNT(*) as total, SUM(CASE WHEN chpl_flag=1 THEN 1 ELSE 0 END) as chpl_count FROM enrichments')
total, chpl = cursor.fetchone()
conn.close()
print(f'   Total CVEs: {total:,}')
print(f'   CHPL flags: {chpl:,} ({chpl/total*100:.2f}%)')
" 2>/dev/null

echo ""
echo "==================================================================="
echo "Run: watch -n 5 bash scripts/monitor_enrichment.sh"
echo "===================================================================" 
