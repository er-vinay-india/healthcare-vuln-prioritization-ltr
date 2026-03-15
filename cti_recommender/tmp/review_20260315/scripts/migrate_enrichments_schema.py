"""
Database Migration: Add Computed Features to Enrichments Table

This migration adds 37 computed feature columns to the enrichments table,
moving from CSV-based storage to unified database storage.

Feature Categories:
- CVSS Decomposition (10): cvss_av, cvss_ac, cvss_pr, cvss_ui, cvss_s, cvss_c, cvss_i, cvss_a, cvss_score_derived, cvss_severity_category
- CWE Intelligence (8): cwe_is_top25, cwe_is_injection, cwe_is_crypto, cwe_is_access_control, cwe_is_input_validation, cwe_is_memory_corruption, cwe_category, cwe_severity_score
- Description NLP (10): desc_has_rce, desc_has_auth_bypass, desc_has_priv_esc, desc_has_sqli, desc_has_xss, desc_has_dos, desc_has_buffer_overflow, desc_has_path_traversal, desc_has_csrf, desc_has_xxe
- Vendor Features (3): vendor_is_high_risk, vendor_is_healthcare, vendor_risk_score
- Interaction Features (6): ultimate_risk, critical_exploitable, network_accessible, auth_not_required, high_impact_network, healthcare_critical

Usage:
    python scripts/migrate_enrichments_schema.py
"""

import sqlite3
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from config.settings import settings


def get_column_info(conn, table_name):
    """Get existing columns in table."""
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = {row[1]: row[2] for row in cursor.fetchall()}
    return columns


def add_column_if_not_exists(conn, table_name, column_name, column_type, description=""):
    """Safely add column to table if it doesn't already exist."""
    existing_columns = get_column_info(conn, table_name)
    
    if column_name in existing_columns:
        print(f"  [SKIP] Column '{column_name}' already exists")
        return False
    
    try:
        cursor = conn.cursor()
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        conn.commit()
        print(f"  [OK] Added column '{column_name}' ({column_type}) - {description}")
        return True
    except sqlite3.Error as e:
        print(f"  [ERROR] Failed to add column '{column_name}': {e}")
        return False


def migrate_enrichments_table(db_path):
    """Add all computed feature columns to enrichments table."""
    
    print("="*70)
    print("DATABASE MIGRATION: Add Computed Features to Enrichments Table")
    print("="*70)
    print(f"\n[INFO] Database: {db_path}")
    
    if not db_path.exists():
        print(f"\n[ERROR] Database not found: {db_path}")
        print("[INFO] Please run STEP_1 and STEP_2 notebooks first to create the database")
        return False
    
    conn = sqlite3.connect(db_path)
    
    try:
        # Get current enrichments table info
        print(f"\n[INFO] Current enrichments table schema:")
        existing_columns = get_column_info(conn, 'enrichments')
        print(f"  Existing columns: {len(existing_columns)}")
        
        added_count = 0
        
        # CVSS Decomposition Features (10 columns)
        print(f"\n[PHASE 1/5] Adding CVSS Decomposition Features...")
        cvss_features = [
            ('cvss_av', 'REAL', 'Attack Vector (1=Physical, 2=Local, 3=Adjacent, 4=Network)'),
            ('cvss_ac', 'REAL', 'Attack Complexity (0=High, 1=Low)'),
            ('cvss_pr', 'REAL', 'Privileges Required (0=High, 0.5=Low, 1=None)'),
            ('cvss_ui', 'REAL', 'User Interaction (0=Required, 1=None)'),
            ('cvss_s', 'REAL', 'Scope Changed (0=Unchanged, 1=Changed)'),
            ('cvss_c', 'REAL', 'Confidentiality Impact (0=None/Low, 1=High)'),
            ('cvss_i', 'REAL', 'Integrity Impact (0=None/Low, 1=High)'),
            ('cvss_a', 'REAL', 'Availability Impact (0=None/Low, 1=High)'),
            ('cvss_score_derived', 'REAL', 'Derived CVSS score from vector'),
            ('cvss_severity_category', 'TEXT', 'Severity category (Low/Medium/High/Critical)')
        ]
        
        for col_name, col_type, col_desc in cvss_features:
            if add_column_if_not_exists(conn, 'enrichments', col_name, col_type, col_desc):
                added_count += 1
        
        # CWE Intelligence Features (8 columns)
        print(f"\n[PHASE 2/5] Adding CWE Intelligence Features...")
        cwe_features = [
            ('cwe_is_top25', 'INTEGER', 'Is in CWE Top 25 (1=Yes, 0=No)'),
            ('cwe_is_injection', 'INTEGER', 'Injection weakness (1=Yes, 0=No)'),
            ('cwe_is_crypto', 'INTEGER', 'Cryptographic weakness (1=Yes, 0=No)'),
            ('cwe_is_access_control', 'INTEGER', 'Access control weakness (1=Yes, 0=No)'),
            ('cwe_is_input_validation', 'INTEGER', 'Input validation weakness (1=Yes, 0=No)'),
            ('cwe_is_memory_corruption', 'INTEGER', 'Memory corruption weakness (1=Yes, 0=No)'),
            ('cwe_category', 'TEXT', 'Primary CWE category'),
            ('cwe_severity_score', 'REAL', 'CWE-based severity score (0-10)')
        ]
        
        for col_name, col_type, col_desc in cwe_features:
            if add_column_if_not_exists(conn, 'enrichments', col_name, col_type, col_desc):
                added_count += 1
        
        # Description NLP Features (10 columns)
        print(f"\n[PHASE 3/5] Adding Description NLP Features...")
        nlp_features = [
            ('desc_has_rce', 'INTEGER', 'Mentions Remote Code Execution (1=Yes, 0=No)'),
            ('desc_has_auth_bypass', 'INTEGER', 'Mentions Authentication Bypass (1=Yes, 0=No)'),
            ('desc_has_priv_esc', 'INTEGER', 'Mentions Privilege Escalation (1=Yes, 0=No)'),
            ('desc_has_sqli', 'INTEGER', 'Mentions SQL Injection (1=Yes, 0=No)'),
            ('desc_has_xss', 'INTEGER', 'Mentions Cross-Site Scripting (1=Yes, 0=No)'),
            ('desc_has_dos', 'INTEGER', 'Mentions Denial of Service (1=Yes, 0=No)'),
            ('desc_has_buffer_overflow', 'INTEGER', 'Mentions Buffer Overflow (1=Yes, 0=No)'),
            ('desc_has_path_traversal', 'INTEGER', 'Mentions Path Traversal (1=Yes, 0=No)'),
            ('desc_has_csrf', 'INTEGER', 'Mentions CSRF (1=Yes, 0=No)'),
            ('desc_has_xxe', 'INTEGER', 'Mentions XXE (1=Yes, 0=No)')
        ]
        
        for col_name, col_type, col_desc in nlp_features:
            if add_column_if_not_exists(conn, 'enrichments', col_name, col_type, col_desc):
                added_count += 1
        
        # Vendor Features (3 columns)
        print(f"\n[PHASE 4/5] Adding Vendor Features...")
        vendor_features = [
            ('vendor_is_high_risk', 'INTEGER', 'High-risk vendor (1=Yes, 0=No)'),
            ('vendor_is_healthcare', 'INTEGER', 'Healthcare vendor (1=Yes, 0=No)'),
            ('vendor_risk_score', 'REAL', 'Vendor risk score (0-3)')
        ]
        
        for col_name, col_type, col_desc in vendor_features:
            if add_column_if_not_exists(conn, 'enrichments', col_name, col_type, col_desc):
                added_count += 1
        
        # Interaction Features (6 columns)
        print(f"\n[PHASE 5/5] Adding Interaction Features...")
        interaction_features = [
            ('ultimate_risk', 'INTEGER', 'KEV + Network + No Auth (1=Yes, 0=No)'),
            ('critical_exploitable', 'INTEGER', 'CVSS≥9 + Network accessible (1=Yes, 0=No)'),
            ('network_accessible', 'INTEGER', 'Attack Vector = Network (1=Yes, 0=No)'),
            ('auth_not_required', 'INTEGER', 'No authentication required (1=Yes, 0=No)'),
            ('high_impact_network', 'INTEGER', 'High CIA impact + Network (1=Yes, 0=No)'),
            ('healthcare_critical', 'INTEGER', 'Healthcare + Critical severity (1=Yes, 0=No)')
        ]
        
        for col_name, col_type, col_desc in interaction_features:
            if add_column_if_not_exists(conn, 'enrichments', col_name, col_type, col_desc):
                added_count += 1
        
        # Summary
        print("\n" + "="*70)
        print("MIGRATION SUMMARY")
        print("="*70)
        print(f"  Columns added: {added_count}")
        print(f"  Total enrichment columns: {len(get_column_info(conn, 'enrichments'))}")
        
        if added_count > 0:
            print(f"\n[OK] Migration completed successfully")
            print(f"\n[NEXT STEP] Run STEP_3_Feature_Enrichment.ipynb to populate these columns")
        else:
            print(f"\n[INFO] No new columns added (migration already complete)")
        
        print("="*70)
        
        return True
        
    except Exception as e:
        print(f"\n[ERROR] Migration failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        conn.close()


if __name__ == "__main__":
    db_path = settings.get_database_path()
    success = migrate_enrichments_table(db_path)
    sys.exit(0 if success else 1)
