#!/usr/bin/env python
"""
Backfill historical CVE data from NVD (2018-2025)
Fetches data in monthly chunks with rate limiting
"""

import sys
from pathlib import Path
from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase
from src.core import cti_recommender
from config.settings import settings

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

# Configuration
START_YEAR = 2018
END_YEAR = 2025
DB_PATH = Path("data/cve_database.db")


def backfill_by_month(start_year: int, end_year: int, api_key: str = None) -> int:
    """
    Backfill CVE data month by month
    
    Args:
        start_year: Starting year (e.g., 2018)
        end_year: Ending year (e.g., 2024)
        api_key: NVD API key (optional, uses centralized settings if not provided)
    """
    
    # Get API key from centralized settings if not provided
    if api_key is None:
        api_key = settings.NVD_API_KEY
    
    if not api_key:
        print("[WARN]  WARNING: No NVD API key found!")
        print("   Rate limit: 5 requests/30 seconds (very slow)")
        print("   Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")
        print("   Set NVD_API_KEY in your centralized project settings/.env")
        response = input("\n   Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Aborted.")
            return
    else:
        print(f"[OK] Using NVD API key (50 requests/30 seconds)")
    
    # Initialize database
    print(f"\nInitializing database: {DB_PATH}")
    db = CVEDatabase(DB_PATH)
    db.print_summary()
    
    # Calculate total months
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)
    current_date = start_date
    
    total_months = (end_year - start_year + 1) * 12
    processed_months = 0
    total_cves = 0
    failed_months = 0
    
    logger.info(f"\n{'='*70}")
    logger.info(f"BACKFILLING CVE DATA: {start_year} - {end_year}")
    logger.info(f"{'='*70}\n")
    logger.info(f"Total months to process: {total_months}")
    logger.info(f"Estimated time: {total_months * 1:.0f} minutes (with API key)\n")
    
    start_time = time.time()
    
    try:
        while current_date <= end_date:
            month_start = current_date.strftime("%Y-%m-01")
            
            # Calculate end of month
            next_month = current_date + relativedelta(months=1)
            month_end = (next_month - timedelta(days=1)).strftime("%Y-%m-%d")
            
            processed_months += 1
            print(f"[{processed_months}/{total_months}] Fetching {month_start} to {month_end}...", end=" ", flush=True)
            
            try:
                # Fetch CVEs for this month
                df = cti_recommender.fetch_nvd_date_range(
                    start_date=month_start,
                    end_date=month_end,
                    api_key=api_key
                )
                
                if not df.empty:
                    # Insert into database
                    count = db.upsert_cves(df)
                    total_cves += count
                    
                    # Log fetch
                    db.log_fetch(
                        start_date=month_start,
                        end_date=month_end,
                        cve_count=count,
                        fetch_type='backfill',
                        status='success'
                    )
                    
                    print(f"[OK] {count} CVEs")
                else:
                    print("[OK] 0 CVEs")
                
            except Exception as e:
                print(f"[X] ERROR: {e}")
                logger.exception(f"Month backfill failed for {month_start} to {month_end}: {e}")
                failed_months += 1
                db.log_fetch(
                    start_date=month_start,
                    end_date=month_end,
                    cve_count=0,
                    fetch_type='backfill',
                    status='error',
                    error_message=str(e)
                )
            
            # Move to next month
            current_date = next_month
            
            # Progress update every 12 months
            if processed_months % 12 == 0:
                elapsed = time.time() - start_time
                avg_per_month = elapsed / processed_months
                remaining = (total_months - processed_months) * avg_per_month
                print(f"\n  Progress: {processed_months}/{total_months} months ({processed_months/total_months*100:.1f}%)")
                print(f"  Total CVEs so far: {total_cves:,}")
                print(f"  Estimated time remaining: {remaining/60:.1f} minutes\n")
    
    except KeyboardInterrupt:
        logger.warning("Backfill interrupted by user")
        failed_months += 1
    
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print("BACKFILL COMPLETE")
        print(f"{'='*70}")
        print(f"Processed months: {processed_months}/{total_months}")
        print(f"Total CVEs fetched: {total_cves:,}")
        print(f"Failed months: {failed_months:,}")
        print(f"Time elapsed: {elapsed/60:.1f} minutes")
        print(f"Database: {DB_PATH}")
        print(f"{'='*70}\n")
        
        # Print final database summary
        db.print_summary()
        db.close()

    return 1 if failed_months > 0 else 0


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                   CVE DATABASE BACKFILL                          ║
║          Fetching Historical CVE Data from NVD                   ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Check for API key
    api_key = settings.NVD_API_KEY
    if api_key:
        print(f"[OK] NVD API Key: {'*' * 20}{api_key[-4:]}")
    else:
        print("[X] NVD API Key: Not found")
    
    # Start backfill
    exit_code = backfill_by_month(START_YEAR, END_YEAR, api_key)
    sys.exit(exit_code)
