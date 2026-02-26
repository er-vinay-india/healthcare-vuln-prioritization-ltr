#!/bin/bash
# Continuous enrichment monitoring with live updates

LOG_FILE=$(ls -t logs/enrichment_full_*.log 2>/dev/null | head -1)
DB_PATH="data/cve_database.db"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

while true; do
    clear
    
    # Header
    echo -e "${BLUE}================================================================================${NC}"
    echo -e "${BLUE}          ENRICHMENT CONTINUOUS MONITOR - $(date '+%H:%M:%S')${NC}"
    echo -e "${BLUE}================================================================================${NC}"
    echo ""
    
    # Process status
    PID=$(ps aux | grep 'enrich_cves.py' | grep -v grep | awk '{print $2}')
    if [ -n "$PID" ]; then
        echo -e "${GREEN}✅ Status: RUNNING${NC} (PID: $PID)"
    else
        echo -e "${RED}❌ Status: NOT RUNNING${NC}"
        echo ""
        echo "Enrichment may have completed or stopped."
        echo "Check final results with: bash scripts/check_progress.sh"
        break
    fi
    
    echo "📝 Log: $LOG_FILE"
    echo ""
    
    # Current Phase from log
    echo -e "${YELLOW}Current Phase:${NC}"
    echo "--------------------------------------------------------------------------------"
    PHASE=$(tail -200 "$LOG_FILE" 2>/dev/null | grep -E "PHASE [1-3]:" | tail -1)
    if [ -n "$PHASE" ]; then
        echo "$PHASE"
    else
        echo "Initializing..."
    fi
    
    # Progress indicators
    echo ""
    echo -e "${YELLOW}Recent Progress (last 10 seconds):${NC}"
    echo "--------------------------------------------------------------------------------"
    tail -30 "$LOG_FILE" 2>/dev/null | grep -v "Cache hit" | grep -v "Using cached" | grep -E "(Batch|Processed|upsert|Complete|PHASE)" | tail -5
    
    # Database statistics
    echo ""
    echo -e "${YELLOW}Database Update Status:${NC}"
    echo "--------------------------------------------------------------------------------"
    
    TOTAL=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments;")
    EPSS_DATE=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE epss_date IS NOT NULL;")
    HEALTH_SCORE=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE healthcare_score IS NOT NULL;")
    
    EPSS_PCT=$(echo "scale=1; $EPSS_DATE * 100 / $TOTAL" | bc)
    HEALTH_PCT=$(echo "scale=1; $HEALTH_SCORE * 100 / $TOTAL" | bc)
    
    # Progress bars
    EPSS_BAR=$(printf '#%.0s' $(seq 1 $((${EPSS_PCT%.*} / 2))))
    HEALTH_BAR=$(printf '#%.0s' $(seq 1 $((${HEALTH_PCT%.*} / 2))))
    
    if (( $(echo "$EPSS_PCT > 50" | bc -l) )); then
        EPSS_COLOR=$GREEN
    elif (( $(echo "$EPSS_PCT > 0" | bc -l) )); then
        EPSS_COLOR=$YELLOW
    else
        EPSS_COLOR=$RED
    fi
    
    if (( $(echo "$HEALTH_PCT > 50" | bc -l) )); then
        HEALTH_COLOR=$GREEN
    elif (( $(echo "$HEALTH_PCT > 0" | bc -l) )); then
        HEALTH_COLOR=$YELLOW
    else
        HEALTH_COLOR=$RED
    fi
    
    echo -e "${EPSS_COLOR}epss_date:        $EPSS_DATE / $TOTAL ($EPSS_PCT%)${NC}"
    echo "  [$EPSS_BAR]"
    echo ""
    echo -e "${HEALTH_COLOR}healthcare_score: $HEALTH_SCORE / $TOTAL ($HEALTH_PCT%)${NC}"
    echo "  [$HEALTH_BAR]"
    
    # ETA calculation (rough estimate)
    if [ "$EPSS_DATE" -gt 100 ]; then
        echo ""
        echo -e "${BLUE}Database updates detected! Phase 3 in progress or completed.${NC}"
    fi
    
    echo ""
    echo -e "${BLUE}================================================================================${NC}"
    echo "Refreshing in 10 seconds... (Press Ctrl+C to stop)"
    echo -e "${BLUE}================================================================================${NC}"
    
    sleep 10
done

echo ""
echo "Monitoring stopped. Run final check with: bash scripts/check_progress.sh"
