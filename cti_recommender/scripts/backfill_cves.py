#!/usr/bin/env python
"""
Backfill historical CVE data from NVD (2018-2025)
Fetches data in monthly chunks with rate limiting
"""

import os
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

# Configuration
START_YEAR = 2018
END_YEAR = 2025
DB_PATH = Path("data/cve_database.db")


def backfill_by_month(start_year: int, end_year: int, api_key: str = None):
    """
    Backfill CVE data month by month
    
    Args:
        start_year: Starting year (e.g., 2018)
        end_year: Ending year (e.g., 2024)
        api_key: NVD API key (optional, reads from NVD_API_KEY env var)
    """
    
    # Get API key from environment if not provided
    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY")
    
    if not api_key:
        print("⚠️  WARNING: No NVD API key found!")
        print("   Rate limit: 5 requests/30 seconds (very slow)")
        print("   Get a free key at: https://nvd.nist.gov/developers/request-an-api-key")
        print("   Set via: export NVD_API_KEY='your-key-here'")
        response = input("\n   Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("Aborted.")
            return
    else:
        print(f"✓ Using NVD API key (50 requests/30 seconds)")
    
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
    
    print(f"\n{'='*70}")
    print(f"BACKFILLING CVE DATA: {start_year} - {end_year}")
    print(f"{'='*70}\n")
    print(f"Total months to process: {total_months}")
    print(f"Estimated time: {total_months * 1:.0f} minutes (with API key)\n")
    
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
                    
                    print(f"✓ {count} CVEs")
                else:
                    print("✓ 0 CVEs")
                
            except Exception as e:
                print(f"✗ ERROR: {e}")
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
        print("\n\n⚠️  Backfill interrupted by user")
    
    finally:
        elapsed = time.time() - start_time
        print(f"\n{'='*70}")
        print("BACKFILL COMPLETE")
        print(f"{'='*70}")
        print(f"Processed months: {processed_months}/{total_months}")
        print(f"Total CVEs fetched: {total_cves:,}")
        print(f"Time elapsed: {elapsed/60:.1f} minutes")
        print(f"Database: {DB_PATH}")
        print(f"{'='*70}\n")
        
        # Print final database summary
        db.print_summary()
        db.close()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                   CVE DATABASE BACKFILL                          ║
║          Fetching Historical CVE Data from NVD                   ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Check for API key
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        print(f"✓ NVD API Key: {'*' * 20}{api_key[-4:]}")
    else:
        print("✗ NVD API Key: Not found")
    
    # Start backfill
    backfill_by_month(START_YEAR, END_YEAR, api_key)
