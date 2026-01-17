#!/usr/bin/env python
"""
Weekly CVE Database Refresh
Fetches new CVEs since last successful fetch
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase
from src.core import cti_recommender

DB_PATH = Path("data/cve_database.db")


def refresh_cves(api_key: str = None, days_back: int = None):
    """
    Refresh CVE database with new entries
    
    Args:
        api_key: NVD API key (optional, reads from NVD_API_KEY env var)
        days_back: Override automatic date detection (for testing)
    """
    
    # Get API key from environment if not provided
    if api_key is None:
        api_key = os.environ.get("NVD_API_KEY")
    
    print(f"\n{'='*70}")
    print("CVE DATABASE REFRESH")
    print(f"{'='*70}\n")
    
    # Initialize database
    print(f"Database: {DB_PATH}")
    db = CVEDatabase(DB_PATH)
    
    # Determine fetch date range
    if days_back:
        start_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        print(f"Manual mode: Fetching last {days_back} days")
    else:
        last_fetch = db.get_last_fetch_date(fetch_type='weekly')
        
        if last_fetch:
            start_date = last_fetch
            print(f"Last fetch: {start_date.isoformat()}")
        else:
            # First time - fetch last 7 days
            start_date = datetime.now(timezone.utc) - timedelta(days=7)
            print(f"First run: Fetching last 7 days")
    
    end_date = datetime.now(timezone.utc)
    
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    print(f"Fetching CVEs: {start_str} to {end_str}\n")
    
    try:
        # Fetch new CVEs
        df = cti_recommender.fetch_nvd_date_range(
            start_date=start_str,
            end_date=end_str,
            api_key=api_key
        )
        
        if df.empty:
            print("✓ No new CVEs found")
            db.log_fetch(
                start_date=start_str,
                end_date=end_str,
                cve_count=0,
                fetch_type='weekly',
                status='success'
            )
        else:
            print(f"\nInserting {len(df)} CVEs into database...")
            count = db.upsert_cves(df)
            
            db.log_fetch(
                start_date=start_str,
                end_date=end_str,
                cve_count=count,
                fetch_type='weekly',
                status='success'
            )
            
            print(f"✓ Successfully added/updated {count} CVEs")
        
        print(f"\n{'='*70}")
        print("REFRESH COMPLETE")
        print(f"{'='*70}\n")
        
        # Show updated stats
        db.print_summary()
        
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        db.log_fetch(
            start_date=start_str,
            end_date=end_str,
            cve_count=0,
            fetch_type='weekly',
            status='error',
            error_message=str(e)
        )
    
    finally:
        db.close()


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                   WEEKLY CVE REFRESH                             ║
║              Update database with new CVEs                       ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Check for API key
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        print(f"✓ NVD API Key: {'*' * 20}{api_key[-4:]}")
    else:
        print("⚠️  NVD API Key: Not found (rate limited to 5 req/30s)")
    
    # Parse command line args
    days_back = None
    if len(sys.argv) > 1:
        try:
            days_back = int(sys.argv[1])
            print(f"   Override: Fetching last {days_back} days")
        except ValueError:
            print(f"   Invalid argument: {sys.argv[1]}")
            sys.exit(1)
    
    refresh_cves(api_key, days_back)
