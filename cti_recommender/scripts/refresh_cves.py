#!/usr/bin/env python
"""
Weekly CVE Database Refresh
Fetches new CVEs since last successful fetch
"""

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
from config.settings import settings

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

DB_PATH = Path("data/cve_database.db")


def refresh_cves(api_key: str = None, days_back: int = None) -> int:
    """
    Refresh CVE database with new entries
    
    Args:
        api_key: NVD API key (optional, uses centralized settings if not provided)
        days_back: Override automatic date detection (for testing)
    """
    
    # Get API key from centralized settings if not provided
    if api_key is None:
        api_key = settings.NVD_API_KEY
    
    logger.info("="*70)
    logger.info("CVE DATABASE REFRESH")
    logger.info("="*70)
    
    # Initialize database
    logger.info(f"Database: {DB_PATH}")
    db = CVEDatabase(DB_PATH)
    
    # Determine fetch date range
    if days_back:
        start_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        logger.info(f"Manual mode: Fetching last {days_back} days", extra={'days_back': days_back})
    else:
        last_fetch = db.get_last_fetch_date(fetch_type='weekly')
        
        if last_fetch:
            start_date = last_fetch
            logger.info(f"Last fetch: {start_date.isoformat()}")
        else:
            # First time - fetch last 7 days
            start_date = datetime.now(timezone.utc) - timedelta(days=7)
            logger.info("First run: Fetching last 7 days")
    
    end_date = datetime.now(timezone.utc)
    
    start_str = start_date.strftime("%Y-%m-%d")
    end_str = end_date.strftime("%Y-%m-%d")
    
    logger.info(f"Fetching CVEs: {start_str} to {end_str}", extra={'start_date': start_str, 'end_date': end_str})
    
    try:
        # Fetch new CVEs
        df = cti_recommender.fetch_nvd_date_range(
            start_date=start_str,
            end_date=end_str,
            api_key=api_key
        )
        
        if df.empty:
            logger.info("[OK] No new CVEs found")
            db.log_fetch(
                start_date=start_str,
                end_date=end_str,
                cve_count=0,
                fetch_type='weekly',
                status='success'
            )
        else:
            logger.info(f"Inserting {len(df)} CVEs into database...", extra={'cve_count': len(df)})
            count = db.upsert_cves(df)
            
            db.log_fetch(
                start_date=start_str,
                end_date=end_str,
                cve_count=count,
                fetch_type='weekly',
                status='success'
            )
            
            logger.info(f"[OK] Successfully added/updated {count} CVEs", extra={'upserted_count': count})
        
        logger.info("="*70)
        logger.info("REFRESH COMPLETE")
        logger.info("="*70)
        
        # Show updated stats
        db.print_summary()
        return 0
        
    except Exception as e:
        logger.exception(f"[X] ERROR: {e}")
        db.log_fetch(
            start_date=start_str,
            end_date=end_str,
            cve_count=0,
            fetch_type='weekly',
            status='error',
            error_message=str(e)
        )
        raise
    
    finally:
        db.close()


if __name__ == "__main__":
    logger.info("""
╔══════════════════════════════════════════════════════════════════╗
║                   WEEKLY CVE REFRESH                             ║
║              Update database with new CVEs                       ║
╚══════════════════════════════════════════════════════════════════╝
""")
    
    # Check for API key
    api_key = settings.NVD_API_KEY
    if api_key:
        logger.info(f"[OK] NVD API Key: {'*' * 20}{api_key[-4:]}")
    else:
        logger.warning("[WARN]  NVD API Key: Not found (rate limited to 5 req/30s)")
    
    # Parse command line args
    days_back = None
    if len(sys.argv) > 1:
        try:
            days_back = int(sys.argv[1])
            logger.info(f"   Override: Fetching last {days_back} days", extra={'days_back': days_back})
        except ValueError:
            logger.error(f"   Invalid argument: {sys.argv[1]}")
            sys.exit(1)
    
    try:
        code = refresh_cves(api_key, days_back)
        sys.exit(code)
    except Exception:
        sys.exit(1)
