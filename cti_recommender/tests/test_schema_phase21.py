#!/usr/bin/env python3
"""
Test database schema after Phase 2.1 refactoring
Verifies all columns present on fresh database creation
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.cve_database import CVEDatabase

def test_schema():
    """Test fresh database creation with complete schema"""
    # Create fresh test database
    test_db = Path('data/test_schema_validation.db')
    test_db.unlink(missing_ok=True)
    
    print_separator()
    print("DATABASE SCHEMA VALIDATION - Phase 2.1")
    print_separator()
    
    # Create database
    print("\n1. Creating fresh database...")
    db = CVEDatabase(test_db)
    print(f"   [OK] Database created: {test_db}")
    
    # Verify CVE table schema
    print("\n2. Verifying cves table...")
    cursor = db.conn.cursor()
    cursor.execute("PRAGMA table_info(cves)")
    cve_columns = {col[1]: col[2] for col in cursor.fetchall()}
    expected_cve_cols = ['cve_id', 'published', 'modified', 'description', 
                         'cvss', 'cvss_vector', 'cwe', 'raw_json', 'created_at']
    
    missing_cve = set(expected_cve_cols) - set(cve_columns.keys())
    if missing_cve:
        print(f"   [X] Missing CVE columns: {missing_cve}")
        assert False, f"Missing CVE columns: {missing_cve}"
    print(f"   [OK] All {len(expected_cve_cols)} CVE columns present")
    
    # Verify enrichments table schema
    print("\n3. Verifying enrichments table...")
    cursor.execute("PRAGMA table_info(enrichments)")
    enrich_columns = {col[1]: col[2] for col in cursor.fetchall()}
    
    expected_enrich_cols = [
        'cve_id', 'kev_flag', 'epss_score', 'epss_percentile', 'epss_date',
        'is_healthcare', 'is_curated', 'curated_severity', 'healthcare_score',
        'attack_flag', 'attack_technique_count', 'chpl_flag', 'label', 'updated_at'
    ]
    
    missing_enrich = set(expected_enrich_cols) - set(enrich_columns.keys())
    if missing_enrich:
        print(f"   [X] Missing enrichment columns: {missing_enrich}")
        assert False, f"Missing enrichment columns: {missing_enrich}"
    print(f"   [OK] All {len(expected_enrich_cols)} enrichment columns present")
    
    # Verify critical column: attack_technique_count
    print("\n4. Verifying attack_technique_count column...")
    if 'attack_technique_count' not in enrich_columns:
        print("   [X] ERROR: attack_technique_count missing!")
        assert False, "attack_technique_count missing"
    print("   [OK] attack_technique_count present (no migration needed)")
    
    # Verify fetch_log table
    print("\n5. Verifying fetch_log table...")
    cursor.execute("PRAGMA table_info(fetch_log)")
    log_columns = {col[1]: col[2] for col in cursor.fetchall()}
    if 'fetch_date' in log_columns and 'cve_count' in log_columns:
        print(f"   [OK] fetch_log table present with {len(log_columns)} columns")
    else:
        print("   [X] fetch_log table incomplete")
        assert False, "fetch_log table incomplete"
    
    # Verify indexes
    print("\n6. Verifying indexes...")
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'")
    indexes = [row[0] for row in cursor.fetchall()]
    expected_indexes = ['idx_cves_published', 'idx_cves_cvss', 
                        'idx_enrichments_kev', 'idx_enrichments_healthcare']
    
    if all(idx in indexes for idx in expected_indexes):
        print(f"   [OK] All {len(expected_indexes)} indexes created")
    else:
        missing_idx = set(expected_indexes) - set(indexes)
        print(f"   [WARN] Missing indexes: {missing_idx}")
    
    # Test basic operations
    print("\n7. Testing basic operations...")
    try:
        # Insert test CVE
        cursor.execute("""
            INSERT INTO cves (cve_id, published, modified, description, cvss)
            VALUES ('CVE-TEST-001', datetime('now'), datetime('now'), 'Test CVE', 7.5)
        """)
        
        # Insert enrichment
        cursor.execute("""
            INSERT INTO enrichments (cve_id, kev_flag, attack_technique_count, label)
            VALUES ('CVE-TEST-001', 0, 3, 2)
        """)
        
        db.conn.commit()
        
        # Query back
        cursor.execute("""
            SELECT c.cve_id, e.attack_technique_count, e.label
            FROM cves c
            JOIN enrichments e ON c.cve_id = e.cve_id
            WHERE c.cve_id = 'CVE-TEST-001'
        """)
        result = cursor.fetchone()
        
        if result and result[1] == 3 and result[2] == 2:
            print("   [OK] Insert/query operations working")
        else:
            print(f"   [X] Data mismatch: {result}")
            assert False, f"Data mismatch: {result}"
            
    except Exception as e:
        print(f"   [X] Error during operations: {e}")
        assert False, f"Error during operations: {e}"
    
    # Cleanup
    db.close()
    test_db.unlink()
    
    print("\n" + "="*70)
    print("[OK] ALL SCHEMA VALIDATION TESTS PASSED")
    print_separator()
    print("\nChanges:")
    print("  • Removed ALTER TABLE migration code")
    print("  • All columns now in initial CREATE TABLE")
    print("  • No runtime migrations needed")
    print("  • Test fixtures updated to match production schema")

if __name__ == "__main__":
    try:
        test_schema()
        sys.exit(0)
    except AssertionError:
        sys.exit(1)
