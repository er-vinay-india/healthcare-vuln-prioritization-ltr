"""Schema contract and EPSS coverage tests for DB status tooling."""
from __future__ import annotations

import sqlite3

import scripts.check_db_status as mod


def _create_valid_schema(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT,
            description TEXT,
            cvss REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE enrichments (
            cve_id TEXT PRIMARY KEY,
            kev_flag INTEGER DEFAULT 0,
            epss_score REAL,
            epss_date TEXT,
            is_healthcare INTEGER DEFAULT 0,
            attack_flag INTEGER DEFAULT 0,
            chpl_flag INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()


def test_validate_schema_contract_passes_for_expected_schema() -> None:
    conn = sqlite3.connect(":memory:")
    _create_valid_schema(conn)

    valid, issues = mod.validate_schema_contract(conn)

    assert valid is True
    assert issues == []


def test_validate_schema_contract_reports_missing_table() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT,
            description TEXT,
            cvss REAL
        )
        """
    )
    conn.commit()

    valid, issues = mod.validate_schema_contract(conn)

    assert valid is False
    assert any("missing table: enrichments" in issue for issue in issues)


def test_validate_schema_contract_reports_missing_column() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute(
        """
        CREATE TABLE cves (
            cve_id TEXT PRIMARY KEY,
            published TEXT,
            description TEXT,
            cvss REAL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE enrichments (
            cve_id TEXT PRIMARY KEY,
            kev_flag INTEGER DEFAULT 0,
            epss_date TEXT,
            is_healthcare INTEGER DEFAULT 0,
            attack_flag INTEGER DEFAULT 0,
            chpl_flag INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()

    valid, issues = mod.validate_schema_contract(conn)

    assert valid is False
    assert any("missing column: enrichments.epss_score" in issue for issue in issues)


def test_get_epss_coverage_returns_expected_metrics() -> None:
    conn = sqlite3.connect(":memory:")
    _create_valid_schema(conn)

    conn.executemany(
        "INSERT INTO cves(cve_id, published, description, cvss) VALUES (?, ?, ?, ?)",
        [
            ("CVE-1", "2024-01-01", "a", 7.5),
            ("CVE-2", "2024-01-02", "b", 9.0),
            ("CVE-3", "2024-01-03", "c", 5.0),
        ],
    )
    conn.executemany(
        "INSERT INTO enrichments(cve_id, kev_flag, epss_score, epss_date, is_healthcare, attack_flag, chpl_flag) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("CVE-1", 1, 0.98, "2024-01-10", 1, 1, 0),
            ("CVE-2", 0, 0.0, "2024-01-10", 0, 1, 1),
            ("CVE-3", 0, None, None, 0, 0, 0),
        ],
    )
    conn.commit()

    result = mod.get_epss_coverage(conn)

    assert result["cves_total"] == 3
    assert result["enrichments_total"] == 3
    assert result["epss_date_present"] == 2
    assert result["epss_score_gt0"] == 1
    assert result["epss_coverage_pct"] == 66.67
