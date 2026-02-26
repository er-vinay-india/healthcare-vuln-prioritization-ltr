#!/bin/bash
# Real-time enrichment monitoring with auto-refresh

LOG_FILE=$(ls -t logs/enrichment_full_*.log 2>/dev/null | head -1)

if [ -z "$LOG_FILE" ]; then
    echo "❌ No enrichment log file found"
    exit 1
fi

echo "================================================================================
"
echo "ENRICHMENT REAL-TIME MONITOR"
echo "================================================================================
"
echo "Log file: $LOG_FILE"
echo "Process: $(ps aux | grep 'enrich_cves.py' | grep -v grep | awk '{print $2}' || echo 'Not running')"
echo ""

# Check current phase
echo "Current Phase:"
echo "--------------------------------------------------------------------------------"
tail -100 "$LOG_FILE" | grep -E "PHASE [1-3]:" | tail -1

echo ""
echo "Recent Progress:"
echo "--------------------------------------------------------------------------------"
tail -20 "$LOG_FILE" | grep -v "Cache hit" | grep -v "Using cached" | grep -E "(Processed|Batch|upsert|Complete|INFO -  )"

echo ""
echo "Database Status:"
echo "--------------------------------------------------------------------------------"
bash scripts/check_progress.sh | grep -A 10 "Field Population"

echo ""
echo "================================================================================
"
echo "To monitor continuously, run: watch -n 10 'bash scripts/watch_enrichment.sh'"
echo "To stop enrichment: pkill -f enrich_cves.py"
echo "================================================================================
"
