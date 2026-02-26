#!/bin/bash
# Quick enrichment progress check using SQL only

DB_PATH="data/cve_database.db"

echo "================================================================================"
echo "ENRICHMENT PROGRESS MONITOR - $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================================================================"
echo ""

# Total CVEs
echo -n "Total CVEs: "
sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments;"

echo ""
echo "Field Population Status:"
echo "--------------------------------------------------------------------------------"

# EPSS Date
TOTAL=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments;")
EPSS_DATE=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE epss_date IS NOT NULL;")
EPSS_PCT=$(echo "scale=1; $EPSS_DATE * 100 / $TOTAL" | bc)
echo "epss_date:         $EPSS_DATE / $TOTAL ($EPSS_PCT%)"

# Healthcare Score
HEALTH_SCORE=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE healthcare_score IS NOT NULL;")
HEALTH_PCT=$(echo "scale=1; $HEALTH_SCORE * 100 / $TOTAL" | bc)
echo "healthcare_score:  $HEALTH_SCORE / $TOTAL ($HEALTH_PCT%)"

# Curated Severity
CURATED=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE curated_severity IS NOT NULL;")
CURATED_PCT=$(echo "scale=2; $CURATED * 100 / $TOTAL" | bc)
echo "curated_severity:  $CURATED / $TOTAL ($CURATED_PCT%) [Expected: ~0.02%]"

echo ""
echo "Consistency Checks:"
echo "--------------------------------------------------------------------------------"

# Check EPSS consistency
MISSING_EPSS_DATE=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE epss_score > 0 AND epss_date IS NULL;")
if [ "$MISSING_EPSS_DATE" -eq 0 ]; then
    echo "✅ All records with EPSS score have epss_date"
else
    echo "⚠️  $MISSING_EPSS_DATE records have EPSS score but missing epss_date"
fi

# Check healthcare score
MISSING_HEALTH=$(sqlite3 $DB_PATH "SELECT COUNT(*) FROM enrichments WHERE healthcare_score IS NULL;")
if [ "$MISSING_HEALTH" -eq 0 ]; then
    echo "✅ All records have healthcare_score"
else
    echo "⚠️  $MISSING_HEALTH records missing healthcare_score"
fi

echo ""
echo "Recently Updated Records (top 5):"
echo "--------------------------------------------------------------------------------"
sqlite3 -header -column $DB_PATH "SELECT cve_id, epss_score, epss_date, healthcare_score FROM enrichments WHERE epss_date IS NOT NULL OR healthcare_score IS NOT NULL ORDER BY cve_id DESC LIMIT 5;"

echo ""
echo "================================================================================"
