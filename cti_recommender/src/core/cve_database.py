"""
SQLite Database Manager for CVE Storage
Handles incremental updates, deduplication, and efficient querying
"""

import sqlite3
import json
import pandas as pd
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Tuple, Any

# Import centralized configuration and logging
try:
    from config.settings import settings
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    # Fallback for standalone usage
    import logging
    logger = logging.getLogger(__name__)
    settings = None


class CVEDatabase:
    """SQLite database manager for CVE data with incremental updates"""
    
    def __init__(self, db_path: Optional[Path] = None):
        # Use centralized settings if available
        if db_path is None and settings:
            self.db_path = settings.get_database_path()
        elif db_path is None:
            self.db_path = Path("data/cve_database.db")
        else:
            self.db_path = Path(db_path)
        
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn: Optional[sqlite3.Connection] = None
        self._connect()
        self._create_tables()
    
    def _connect(self) -> None:
        """Connect to SQLite database"""
        self.conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False  # Allow multi-threaded access (FastAPI)
        )
        self.conn.row_factory = sqlite3.Row  # Enable column access by name
        logger.info("Connected to database", extra={"db_path": str(self.db_path)})
    
    def _create_tables(self) -> None:
        """Create database schema if not exists"""
        cursor = self.conn.cursor()
        
        # Main CVE table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                published TIMESTAMP,
                modified TIMESTAMP,
                description TEXT,
                cvss REAL,
                cvss_vector TEXT,
                cwe TEXT,
                raw_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Enrichment cache (EPSS, KEV, healthcare flags, etc.)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS enrichments (
                cve_id TEXT PRIMARY KEY,
                kev_flag INTEGER DEFAULT 0,
                epss_score REAL,
                epss_percentile REAL,
                epss_date TEXT,
                is_healthcare INTEGER DEFAULT 0,
                is_curated INTEGER DEFAULT 0,
                curated_severity TEXT,
                healthcare_score REAL,
                attack_flag INTEGER DEFAULT 0,
                attack_technique_count INTEGER DEFAULT 0,
                chpl_flag INTEGER DEFAULT 0,
                label INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
            )
        """)
        
        # Fetch tracking log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS fetch_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fetch_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                start_date TIMESTAMP,
                end_date TIMESTAMP,
                cve_count INTEGER,
                fetch_type TEXT,
                status TEXT,
                error_message TEXT
            )
        """)
        
        # Create indexes for common queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_cves_cvss ON cves(cvss)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_enrichments_kev ON enrichments(kev_flag)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_enrichments_healthcare ON enrichments(is_healthcare)
        """)
        
        self.conn.commit()
        logger.info("Database schema created/verified")
    
    def upsert_cves(self, df: pd.DataFrame) -> int:
        """
        Insert or update CVEs from DataFrame
        
        Args:
            df: DataFrame with columns: cve_id, published, description, cvss, etc.
        
        Returns:
            Number of CVEs inserted/updated
        """
        if df.empty:
            return 0
        
        required_cols = ['cve_id', 'published', 'description']
        for col in required_cols:
            if col not in df.columns:
                raise ValueError(f"Missing required column: {col}")
        
        cursor = self.conn.cursor()
        count = 0
        
        for _, row in df.iterrows():
            cve_id = row['cve_id']
            published = row.get('published')
            modified = row.get('modified', published)
            description = row.get('description', '')
            cvss = row.get('cvss')
            cvss_vector = row.get('cvss_vector')
            cwe = row.get('cwe')
            
            # Store full row as JSON for future reference
            raw_json = row.to_json()
            
            try:
                cursor.execute("""
                    INSERT INTO cves (cve_id, published, modified, description, cvss, cvss_vector, cwe, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id) DO UPDATE SET
                        modified = excluded.modified,
                        description = excluded.description,
                        cvss = excluded.cvss,
                        cvss_vector = excluded.cvss_vector,
                        cwe = excluded.cwe,
                        raw_json = excluded.raw_json
                """, (cve_id, published, modified, description, cvss, cvss_vector, cwe, raw_json))
                count += 1
            except sqlite3.IntegrityError as e:
                logger.error("Integrity error for CVE", extra={"cve_id": cve_id, "error": str(e)})
                continue
        
        try:
            self.conn.commit()
            logger.info("Upserted CVEs to database", extra={"count": count})
        except Exception as e:
            logger.error("Commit failed", extra={"error": str(e)}, exc_info=True)
            self.conn.rollback()
            raise
        
        return count
    
    def upsert_enrichments(self, df: pd.DataFrame) -> int:
        """
        Insert or update enrichment data (KEV, EPSS, healthcare flags)
        
        Args:
            df: DataFrame with cve_id and enrichment columns
        
        Returns:
            Number of enrichments inserted/updated
        """
        if df.empty or 'cve_id' not in df.columns:
            return 0
        
        cursor = self.conn.cursor()
        count = 0
        
        for _, row in df.iterrows():
            cve_id = row['cve_id']
            
            # Build dynamic update
            fields = {
                'kev_flag': row.get('kev_flag', 0),
                'epss_score': row.get('epss_score'),
                'epss_percentile': row.get('epss_percentile'),
                'epss_date': row.get('epss_date'),
                'is_healthcare': row.get('is_healthcare', 0),
                'is_curated': row.get('is_curated', 0),
                'curated_severity': row.get('curated_severity'),
                'healthcare_score': row.get('healthcare_score'),
                'attack_flag': row.get('attack_flag', 0),
                'chpl_flag': row.get('chpl_flag', 0),
                'label': row.get('label', 0),
            }
            
            # Filter out None values
            fields = {k: v for k, v in fields.items() if v is not None}
            
            if not fields:
                continue
            
            # Build INSERT/UPDATE query
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['?'] * len(fields))
            updates = ', '.join([f"{k} = excluded.{k}" for k in fields.keys()])
            
            query = f"""
                INSERT INTO enrichments (cve_id, {columns}, updated_at)
                VALUES (?, {placeholders}, CURRENT_TIMESTAMP)
                ON CONFLICT(cve_id) DO UPDATE SET
                    {updates},
                    updated_at = CURRENT_TIMESTAMP
            """
            
            cursor.execute(query, (cve_id, *fields.values()))
            count += 1
        
        try:
            self.conn.commit()
            logger.info("Upserted enrichment records", extra={"count": count})
        except Exception as e:
            logger.error("Enrichment commit failed", extra={"error": str(e)}, exc_info=True)
            self.conn.rollback()
            raise
        return count
    
    def log_fetch(self, start_date: str, end_date: str, cve_count: int,
                  fetch_type: str = 'manual', status: str = 'success',
                  error_message: str = None):
        """Log a fetch operation"""
        cursor = self.conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO fetch_log (start_date, end_date, cve_count, fetch_type, status, error_message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (start_date, end_date, cve_count, fetch_type, status, error_message))
            self.conn.commit()
        except Exception as e:
            logger.error("Failed to log fetch entry", extra={"error": str(e)}, exc_info=True)
            self.conn.rollback()
    
    def get_last_fetch_date(self, fetch_type: str = None) -> Optional[datetime]:
        """Get the end date of the last successful fetch"""
        cursor = self.conn.cursor()
        
        if fetch_type:
            cursor.execute("""
                SELECT end_date FROM fetch_log 
                WHERE fetch_type = ? AND status = 'success'
                ORDER BY fetch_date DESC LIMIT 1
            """, (fetch_type,))
        else:
            cursor.execute("""
                SELECT end_date FROM fetch_log 
                WHERE status = 'success'
                ORDER BY fetch_date DESC LIMIT 1
            """)
        
        row = cursor.fetchone()
        if row and row['end_date']:
            return datetime.fromisoformat(row['end_date'])
        return None
    
    def query_cves(self, 
                   cve_ids: Optional[List[str]] = None,
                   start_date: Optional[str] = None,
                   end_date: Optional[str] = None,
                   days_back: Optional[int] = None,
                   min_cvss: Optional[float] = None,
                   limit: Optional[int] = None) -> pd.DataFrame:
        """
        Query CVEs with optional filters
        
        Args:
            cve_ids: Specific CVE IDs to fetch
            start_date: Filter by published >= start_date (ISO format)
            end_date: Filter by published <= end_date (ISO format)
            days_back: Filter by last N days
            min_cvss: Filter by CVSS >= min_cvss
            limit: Maximum number of results
        
        Returns:
            DataFrame with CVE data
        """
        query = """
            SELECT c.*, 
                   e.kev_flag, e.epss_score, e.epss_percentile,
                   e.is_healthcare, e.is_curated, e.healthcare_score,
                   e.attack_flag, e.chpl_flag
            FROM cves c
            LEFT JOIN enrichments e ON c.cve_id = e.cve_id
            WHERE 1=1
        """
        params = []
        
        if cve_ids:
            placeholders = ','.join(['?'] * len(cve_ids))
            query += f" AND c.cve_id IN ({placeholders})"
            params.extend(cve_ids)
        
        if start_date:
            query += " AND c.published >= ?"
            params.append(start_date)
        
        if end_date:
            query += " AND c.published <= ?"
            params.append(end_date)
        
        if days_back:
            now = datetime.now(timezone.utc)
            cutoff = now - pd.Timedelta(days=days_back)
            query += " AND c.published >= ?"
            params.append(cutoff.isoformat())
        
        if min_cvss:
            query += " AND c.cvss >= ?"
            params.append(min_cvss)
        
        query += " ORDER BY c.published DESC"
        
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        
        try:
            df = pd.read_sql_query(query, self.conn, params=params)
        except Exception as e:
            logger.error("CVE query failed", extra={"error": str(e)}, exc_info=True)
            raise
        logger.info("Queried CVEs from database", extra={"count": len(df)})
        return df
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        cursor = self.conn.cursor()
        
        stats = {}
        
        # Total CVEs
        cursor.execute("SELECT COUNT(*) as count FROM cves")
        stats['total_cves'] = cursor.fetchone()['count']
        
        # Date range
        cursor.execute("SELECT MIN(published) as min, MAX(published) as max FROM cves")
        row = cursor.fetchone()
        stats['date_range'] = (row['min'], row['max'])
        
        # CVEs with CVSS
        cursor.execute("SELECT COUNT(*) as count FROM cves WHERE cvss IS NOT NULL")
        stats['cves_with_cvss'] = cursor.fetchone()['count']
        
        # Enrichment stats
        cursor.execute("SELECT COUNT(*) as count FROM enrichments WHERE kev_flag = 1")
        stats['kev_count'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM enrichments WHERE is_healthcare = 1")
        stats['healthcare_count'] = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM enrichments WHERE is_curated = 1")
        stats['curated_count'] = cursor.fetchone()['count']
        
        # Fetch history
        cursor.execute("SELECT COUNT(*) as count FROM fetch_log WHERE status = 'success'")
        stats['successful_fetches'] = cursor.fetchone()['count']
        
        return stats
    
    def print_summary(self) -> None:
        """Print database summary"""
        stats = self.get_statistics()
        
        logger.info("\n" + "="*70)
        logger.info("CVE DATABASE SUMMARY")
        logger.info("="*70)
        logger.info(f"\nTotal CVEs: {stats['total_cves']:,}")
        logger.info(f"Date Range: {stats['date_range'][0]} to {stats['date_range'][1]}")
        logger.info(f"CVEs with CVSS: {stats['cves_with_cvss']:,} ({stats['cves_with_cvss']/max(stats['total_cves'],1)*100:.1f}%)")
        logger.info(f"\nEnrichments:")
        logger.info(f"  • KEV-flagged: {stats['kev_count']:,}")
        logger.info(f"  • Healthcare-relevant: {stats['healthcare_count']:,}")
        logger.info(f"  • Curated breaches: {stats['curated_count']:,}")
        logger.info(f"\nFetch History: {stats['successful_fetches']} successful fetches")
        logger.info("="*70 + "\n")
    
    def close(self) -> None:
        """Close database connection"""
        if self.conn:
            self.conn.close()
            logger.info("Database connection closed")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


if __name__ == "__main__":
    # Test database
    logger.info("Testing CVE Database...")
    
    with CVEDatabase() as db:
        db.print_summary()
        
        # Test query
        logger.info("\nTesting query (last 7 days):")
        df = db.query_cves(days_back=7, limit=5)
        if not df.empty:
            logger.info(f"Results:\n{df[['cve_id', 'published', 'cvss']].head()}")
        else:
            logger.warning("No CVEs found (database empty)")
