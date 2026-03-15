#!/usr/bin/env python3
"""Check database status after CHPL mapping."""
import argparse
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.core.cve_database import CVEDatabase
from src.utils.cli_runner import get_logger_with_fallback, run_cli

logger = get_logger_with_fallback(__name__)


REQUIRED_SCHEMA: dict[str, set[str]] = {
	"cves": {"cve_id", "published", "description", "cvss"},
	"enrichments": {
		"cve_id",
		"kev_flag",
		"epss_score",
		"epss_date",
		"is_healthcare",
		"attack_flag",
		"chpl_flag",
	},
}


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
	cursor = conn.execute(f"PRAGMA table_info({table})")
	return {str(row[1]) for row in cursor.fetchall()}


def validate_schema_contract(conn: sqlite3.Connection) -> tuple[bool, list[str]]:
	"""Validate required database tables/columns used by status and EPSS checks."""
	issues: list[str] = []
	table_rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
	existing_tables = {str(row[0]) for row in table_rows}

	for table_name, required_columns in REQUIRED_SCHEMA.items():
		if table_name not in existing_tables:
			issues.append(f"missing table: {table_name}")
			continue

		existing_columns = _table_columns(conn, table_name)
		missing_columns = sorted(required_columns - existing_columns)
		for column in missing_columns:
			issues.append(f"missing column: {table_name}.{column}")

	return (len(issues) == 0, issues)


def get_epss_coverage(conn: sqlite3.Connection) -> dict[str, float | int]:
	"""Return canonical EPSS coverage metrics from the stable schema."""
	valid, issues = validate_schema_contract(conn)
	if not valid:
		raise ValueError("Schema contract failed: " + "; ".join(issues))

	cves_total = int(conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0])
	enrichments_total = int(conn.execute("SELECT COUNT(*) FROM enrichments").fetchone()[0])
	epss_date_present = int(
		conn.execute("SELECT COUNT(*) FROM enrichments WHERE epss_date IS NOT NULL").fetchone()[0]
	)
	epss_score_gt0 = int(
		conn.execute(
			"SELECT COUNT(*) FROM enrichments WHERE epss_score IS NOT NULL AND epss_score > 0"
		).fetchone()[0]
	)
	coverage_pct = (epss_date_present / enrichments_total * 100.0) if enrichments_total else 0.0

	return {
		"cves_total": cves_total,
		"enrichments_total": enrichments_total,
		"epss_date_present": epss_date_present,
		"epss_score_gt0": epss_score_gt0,
		"epss_coverage_pct": round(coverage_pct, 2),
	}


def check_db_status() -> None:
	db = CVEDatabase()
	try:
		valid_schema, issues = validate_schema_contract(db.conn)
		if not valid_schema:
			raise RuntimeError("Schema contract failed: " + "; ".join(issues))

		cursor = db.conn.cursor()

		print('='*70)
		print('DATABASE STATUS AFTER CHPL MAPPING')
		print('='*70)

		# Check enrichment signals
		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1')
		kev = cursor.fetchone()[0]

		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE is_healthcare = 1')
		healthcare = cursor.fetchone()[0]

		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE attack_flag = 1')
		attack = cursor.fetchone()[0]

		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1')
		chpl = cursor.fetchone()[0]

		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE is_curated = 1')
		curated = cursor.fetchone()[0]

		print(f'\nMulti-Source Coverage:')
		print(f'   KEV (exploited):              {kev:,}')
		print(f'   Healthcare-related:           {healthcare:,}')
		print(f'   ATT&CK mapped:                {attack:,}')
		print(f'   CHPL certified products:      {chpl:,}')
		print(f'   Curated breaches:             {curated:,}')

		print(f'\nMulti-signal CVEs:')
		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE kev_flag = 1 AND is_healthcare = 1')
		kev_healthcare = cursor.fetchone()[0]

		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE chpl_flag = 1 AND is_healthcare = 1')
		chpl_healthcare = cursor.fetchone()[0]

		cursor.execute('SELECT COUNT(*) FROM enrichments WHERE attack_flag = 1 AND is_healthcare = 1')
		attack_healthcare = cursor.fetchone()[0]

		print(f'   KEV + Healthcare:             {kev_healthcare:,}')
		print(f'   CHPL + Healthcare:            {chpl_healthcare:,}')
		print(f'   ATT&CK + Healthcare:          {attack_healthcare:,}')

		epss = get_epss_coverage(db.conn)
		print(f'\nEPSS Coverage (canonical):')
		print(f"   CVEs total:                   {epss['cves_total']:,}")
		print(f"   Enrichments total:            {epss['enrichments_total']:,}")
		print(f"   EPSS date present:            {epss['epss_date_present']:,}")
		print(f"   EPSS score > 0:               {epss['epss_score_gt0']:,}")
		print(f"   EPSS coverage:                {epss['epss_coverage_pct']:.2f}%")

		print('\n' + '='*70)
		print('[OK] Phase 3 Complete - Ready for next steps')
		print('='*70)
	finally:
		db.close()


def _print_schema_contract_status() -> int:
	db = CVEDatabase()
	try:
		valid, issues = validate_schema_contract(db.conn)
		if valid:
			print("[OK] Schema contract valid")
			return 0

		print("[FAIL] Schema contract violations:")
		for issue in issues:
			print(f" - {issue}")
		return 1
	finally:
		db.close()


def _print_epss_coverage() -> int:
	db = CVEDatabase()
	try:
		coverage = get_epss_coverage(db.conn)
		print(
			"CVES_TOTAL={cves_total} ENRICHMENTS_TOTAL={enrichments_total} "
			"EPSS_DATE_PRESENT={epss_date_present} EPSS_SCORE_GT0={epss_score_gt0} "
			"EPSS_COVERAGE={epss_coverage_pct:.2f}%".format(**coverage)
		)
		return 0
	finally:
		db.close()


def main(argv: list[str] | None = None) -> int:
	parser = argparse.ArgumentParser(description="Check database status and schema/EPSS coverage")
	parser.add_argument(
		"--schema-contract-only",
		action="store_true",
		help="Validate required DB schema tables/columns only",
	)
	parser.add_argument(
		"--epss-coverage-only",
		action="store_true",
		help="Print canonical EPSS coverage summary only",
	)
	args = parser.parse_args(argv or [])

	def _run() -> int:
		if args.schema_contract_only:
			return _print_schema_contract_status()
		if args.epss_coverage_only:
			return _print_epss_coverage()

		check_db_status()
		return 0

	return run_cli(_run, logger, "Database status check failed")


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
