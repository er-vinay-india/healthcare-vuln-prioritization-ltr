#!/usr/bin/env python
"""
Monitor enrichment progress in real-time
Shows how many records have been updated with the 3 fields
"""

import sqlite3
import sys
from pathlib import Path
import time
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except Exception:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

def monitor_enrichment(watch_mode=False, interval=10):
    """
    Monitor enrichment progress
    
    Args:
        watch_mode: If True, continuously monitor (like watch command)
        interval: Seconds between updates in watch mode
    """
    db = CVEDatabase()
    try:
        while True:
            # Clear screen in watch mode
            if watch_mode:
                print("\033[2J\033[H")  # Clear screen and move to top

            print("=" * 80)
            print(f"ENRICHMENT PROGRESS MONITOR - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print("=" * 80)

            # Query overall statistics
            stats = db.conn.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN epss_date IS NOT NULL THEN 1 ELSE 0 END) as has_epss_date,
                    SUM(CASE WHEN healthcare_score IS NOT NULL THEN 1 ELSE 0 END) as has_healthcare_score,
                    SUM(CASE WHEN curated_severity IS NOT NULL THEN 1 ELSE 0 END) as has_curated_severity,
                    SUM(CASE WHEN epss_score > 0 THEN 1 ELSE 0 END) as has_epss_score,
                    SUM(CASE WHEN is_healthcare = 1 THEN 1 ELSE 0 END) as is_healthcare_count
                FROM enrichments
            """).fetchone()

            total = stats[0]
            has_epss_date = stats[1]
            has_healthcare_score = stats[2]
            has_curated_severity = stats[3]
            has_epss_score = stats[4]
            is_healthcare_count = stats[5]

            print(f"\nTotal CVEs: {total:,}")
            print("\nField Population Status:")
            print("-" * 80)

            # EPSS Date
            epss_date_pct = (has_epss_date / total * 100) if total > 0 else 0
            epss_date_bar = "█" * int(epss_date_pct / 2)
            status = "✅" if epss_date_pct > 99 else ("🔄" if epss_date_pct > 0 else "❌")
            print(f"{status} epss_date:         {has_epss_date:>7,} / {total:,} ({epss_date_pct:>5.1f}%) {epss_date_bar}")

            # Healthcare Score
            healthcare_score_pct = (has_healthcare_score / total * 100) if total > 0 else 0
            healthcare_score_bar = "█" * int(healthcare_score_pct / 2)
            status = "✅" if healthcare_score_pct > 99 else ("🔄" if healthcare_score_pct > 0 else "❌")
            print(f"{status} healthcare_score: {has_healthcare_score:>7,} / {total:,} ({healthcare_score_pct:>5.1f}%) {healthcare_score_bar}")

            # Curated Severity (expected to be low - only for curated CVEs)
            curated_severity_pct = (has_curated_severity / total * 100) if total > 0 else 0
            print(f"ℹ️  curated_severity: {has_curated_severity:>7,} / {total:,} ({curated_severity_pct:>5.1f}%) (Expected: ~0.02%)")

            print("\nAdditional Stats:")
            print("-" * 80)
            print(f"Records with EPSS score > 0:     {has_epss_score:,}")
            print(f"Records marked as healthcare:    {is_healthcare_count:,}")

            # Show consistency check
            print("\nConsistency Checks:")
            print("-" * 80)

            # Check: Records with epss_score should have epss_date
            missing_epss_date = db.conn.execute("""
                SELECT COUNT(*) FROM enrichments 
                WHERE epss_score > 0 AND epss_date IS NULL
            """).fetchone()[0]

            if missing_epss_date == 0:
                print("✅ All records with EPSS score have epss_date")
            else:
                print(f"⚠️  {missing_epss_date:,} records have EPSS score but missing epss_date")

            # Check: All records should have healthcare_score
            missing_healthcare_score = db.conn.execute("""
                SELECT COUNT(*) FROM enrichments 
                WHERE healthcare_score IS NULL
            """).fetchone()[0]

            if missing_healthcare_score == 0:
                print("✅ All records have healthcare_score")
            else:
                print(f"⚠️  {missing_healthcare_score:,} records missing healthcare_score")

            # Show sample of recently updated records
            print("\nRecently Updated Records (sample):")
            print("-" * 80)
            recent = db.conn.execute("""
                SELECT cve_id, epss_score, epss_date, healthcare_score, 
                       CASE WHEN curated_severity IS NOT NULL THEN curated_severity ELSE 'N/A' END as severity
                FROM enrichments 
                WHERE epss_date IS NOT NULL OR healthcare_score IS NOT NULL
                ORDER BY cve_id DESC 
                LIMIT 5
            """).fetchall()

            if recent:
                print(f"{'CVE ID':<18} {'EPSS':<8} {'EPSS Date':<12} {'Health':<8} {'Curated'}")
                for row in recent:
                    print(f"{row[0]:<18} {row[1]:<8.5f} {row[2] or 'NULL':<12} {row[3] or 0.0:<8.3f} {row[4]}")
            else:
                print("No updated records found yet")

            print("\n" + "=" * 80)

            if not watch_mode:
                break

            print(f"\nRefreshing in {interval} seconds... (Press Ctrl+C to stop)")
            try:
                time.sleep(interval)
            except KeyboardInterrupt:
                print("\nMonitoring stopped.")
                break
    finally:
        db.close()


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Monitor enrichment progress")
    parser.add_argument('--watch', '-w', action='store_true',
                       help='Continuously monitor (refresh every N seconds)')
    parser.add_argument('--interval', '-i', type=int, default=10,
                       help='Refresh interval in seconds (default: 10)')

    args = parser.parse_args()

    try:
        monitor_enrichment(watch_mode=args.watch, interval=args.interval)
        return 0
    except Exception:
        logger.exception("Enrichment monitor failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
