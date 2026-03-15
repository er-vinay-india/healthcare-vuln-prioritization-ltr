"""Data Quality and Validation Module for CTI Recommender

Provides comprehensive data quality checks, validation, and audit capabilities
for the vulnerability recommender system.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
import re

import pandas as pd
import numpy as np

logger = logging.getLogger("data_quality")
logging.basicConfig(level=logging.INFO)


class DataQualityReport:
    """Container for data quality assessment results"""
    
    def __init__(self):
        self.issues: List[Dict] = []
        self.stats: Dict = {}
        self.warnings: List[str] = []
        self.errors: List[str] = []
        
    def add_issue(self, severity: str, category: str, message: str, count: int = 0, details: Optional[Dict] = None):
        """Add a data quality issue"""
        self.issues.append({
            'severity': severity,
            'category': category,
            'message': message,
            'count': count,
            'details': details or {}
        })
        if severity == 'error':
            self.errors.append(message)
        elif severity == 'warning':
            self.warnings.append(message)
    
    def add_stat(self, key: str, value):
        """Add a statistic to the report"""
        self.stats[key] = value
    
    def to_dict(self) -> Dict:
        """Export report as dictionary"""
        return {
            'issues': self.issues,
            'stats': self.stats,
            'summary': {
                'total_issues': len(self.issues),
                'errors': len(self.errors),
                'warnings': len(self.warnings)
            }
        }
    
    def print_summary(self):
        """Print human-readable summary"""
        print("\n" + "="*70)
        print("DATA QUALITY REPORT")
        print("="*70)
        
        print("\n[STATS] STATISTICS:")
        for key, value in self.stats.items():
            print(f"  • {key}: {value}")
        
        if self.errors:
            print(f"\n[FAIL] ERRORS ({len(self.errors)}):")
            for err in self.errors:
                print(f"  • {err}")
        
        if self.warnings:
            print(f"\n[WARN]  WARNINGS ({len(self.warnings)}):")
            for warn in self.warnings:
                print(f"  • {warn}")
        
        print("\n" + "="*70 + "\n")


def validate_cve_format(cve_id: str) -> bool:
    """Validate CVE ID format (CVE-YYYY-NNNNN+)"""
    if not isinstance(cve_id, str):
        return False
    pattern = r'^CVE-\d{4}-\d{4,}$'
    return bool(re.match(pattern, cve_id))


def validate_cvss_score(score: float) -> bool:
    """Validate CVSS score is in valid range [0.0, 10.0]"""
    if pd.isna(score):
        return False
    return 0.0 <= float(score) <= 10.0


def check_nvd_quality(df: pd.DataFrame) -> DataQualityReport:
    """Comprehensive data quality check for NVD dataset"""
    report = DataQualityReport()
    
    # Basic stats
    report.add_stat("Total CVEs", len(df))
    report.add_stat("Columns", list(df.columns))
    
    # Check for duplicate CVE IDs
    if 'cve_id' in df.columns:
        duplicates = df['cve_id'].duplicated().sum()
        if duplicates > 0:
            report.add_issue('error', 'duplicates', f"Found {duplicates} duplicate CVE IDs", duplicates)
            # Show examples
            dup_ids = df[df['cve_id'].duplicated(keep=False)]['cve_id'].unique()[:5]
            report.add_issue('info', 'duplicates', f"Example duplicates: {', '.join(dup_ids)}")
    
    # Validate CVE ID format
    if 'cve_id' in df.columns:
        invalid_cves = df[~df['cve_id'].apply(validate_cve_format)]
        if len(invalid_cves) > 0:
            report.add_issue('error', 'format', f"Found {len(invalid_cves)} invalid CVE ID formats", len(invalid_cves))
            report.add_issue('info', 'format', f"Examples: {invalid_cves['cve_id'].head(3).tolist()}")
    
    # Check CVSS scores
    if 'cvss' in df.columns:
        missing_cvss = df['cvss'].isna().sum()
        report.add_stat("Missing CVSS scores", missing_cvss)
        if missing_cvss > 0:
            pct = (missing_cvss / len(df)) * 100
            report.add_issue('warning', 'cvss', f"Missing CVSS scores: {missing_cvss} ({pct:.1f}%)", missing_cvss)
        
        # Check for invalid CVSS values
        valid_cvss = df['cvss'].dropna()
        if len(valid_cvss) > 0:
            invalid_cvss = valid_cvss[~valid_cvss.apply(validate_cvss_score)]
            if len(invalid_cvss) > 0:
                report.add_issue('error', 'cvss', f"Found {len(invalid_cvss)} invalid CVSS scores (not in 0-10 range)", len(invalid_cvss))
            
            report.add_stat("CVSS mean", f"{valid_cvss.mean():.2f}")
            report.add_stat("CVSS median", f"{valid_cvss.median():.2f}")
            report.add_stat("CVSS min", f"{valid_cvss.min():.2f}")
            report.add_stat("CVSS max", f"{valid_cvss.max():.2f}")
    
    # Check published dates
    if 'published' in df.columns:
        missing_dates = df['published'].isna().sum()
        if missing_dates > 0:
            report.add_issue('error', 'dates', f"Missing published dates: {missing_dates}", missing_dates)
        
        # Check for future dates
        now = pd.Timestamp.now(tz='UTC')
        try:
            dates = pd.to_datetime(df['published'], errors='coerce', utc=True)
            future_dates = dates[dates > now]
            if len(future_dates) > 0:
                report.add_issue('warning', 'dates', f"Found {len(future_dates)} CVEs with future dates", len(future_dates))
            
            # Date range
            valid_dates = dates.dropna()
            if len(valid_dates) > 0:
                report.add_stat("Date range", f"{valid_dates.min()} to {valid_dates.max()}")
                
                # Check for very old CVEs (might indicate stale data)
                two_years_ago = now - pd.Timedelta(days=730)
                very_old = valid_dates[valid_dates < two_years_ago]
                report.add_stat("CVEs older than 2 years", len(very_old))
        except Exception as e:
            report.add_issue('error', 'dates', f"Failed to parse dates: {str(e)}")
    
    # Check descriptions
    desc_col = 'description_en' if 'description_en' in df.columns else 'description'
    if desc_col in df.columns:
        missing_desc = df[desc_col].isna().sum()
        empty_desc = (df[desc_col].astype(str).str.strip() == '').sum()
        total_missing = missing_desc + empty_desc
        if total_missing > 0:
            pct = (total_missing / len(df)) * 100
            report.add_issue('warning', 'descriptions', f"Missing/empty descriptions: {total_missing} ({pct:.1f}%)", total_missing)
        
        # Check for very short descriptions (might be incomplete)
        valid_desc = df[desc_col].dropna().astype(str)
        short_desc = valid_desc[valid_desc.str.len() < 50]
        if len(short_desc) > 0:
            report.add_issue('warning', 'descriptions', f"Found {len(short_desc)} suspiciously short descriptions (<50 chars)", len(short_desc))
        
        report.add_stat("Avg description length", f"{valid_desc.str.len().mean():.0f} chars")
    
    # Check for required columns
    required_cols = ['cve_id', 'published', 'cvss']
    missing_cols = [col for col in required_cols if col not in df.columns]
    if missing_cols:
        report.add_issue('error', 'schema', f"Missing required columns: {', '.join(missing_cols)}")
    
    return report


def check_kev_quality(df: pd.DataFrame) -> DataQualityReport:
    """Data quality check for CISA KEV dataset"""
    report = DataQualityReport()
    
    report.add_stat("Total KEV entries", len(df))
    
    if 'cve_id' in df.columns:
        # Check for duplicates
        duplicates = df['cve_id'].duplicated().sum()
        if duplicates > 0:
            report.add_issue('warning', 'duplicates', f"Found {duplicates} duplicate CVE IDs in KEV", duplicates)
        
        # Validate CVE format
        invalid = df[~df['cve_id'].apply(validate_cve_format)]
        if len(invalid) > 0:
            report.add_issue('error', 'format', f"Invalid CVE formats in KEV: {len(invalid)}", len(invalid))
    
    # Check date fields
    for date_col in ['dateAdded', 'dueDate']:
        if date_col in df.columns:
            missing = df[date_col].isna().sum()
            if missing > 0:
                report.add_issue('warning', 'dates', f"Missing {date_col}: {missing}", missing)
    
    return report


def check_chpl_quality(df: pd.DataFrame) -> DataQualityReport:
    """Data quality check for CHPL dataset"""
    report = DataQualityReport()
    
    report.add_stat("Total CHPL products", len(df))
    
    if 'product' in df.columns:
        missing_product = df['product'].isna().sum()
        if missing_product > 0:
            report.add_issue('warning', 'products', f"Missing product names: {missing_product}", missing_product)
        
        report.add_stat("Unique products", df['product'].nunique())
    
    if 'developer' in df.columns:
        missing_dev = df['developer'].isna().sum()
        if missing_dev > 0:
            report.add_issue('warning', 'developers', f"Missing developer names: {missing_dev}", missing_dev)
        
        report.add_stat("Unique developers", df['developer'].nunique())
    
    return report


def check_attack_quality(df: pd.DataFrame) -> DataQualityReport:
    """Data quality check for MITRE ATT&CK dataset"""
    report = DataQualityReport()
    
    report.add_stat("Total ATT&CK techniques", len(df))
    
    if 'name' in df.columns:
        missing_names = df['name'].isna().sum()
        if missing_names > 0:
            report.add_issue('warning', 'names', f"Missing technique names: {missing_names}", missing_names)
    
    if 'external_references' in df.columns:
        # Count techniques with CAPEC mappings
        has_capec = df['external_references'].apply(
            lambda refs: any(ref.get('source_name') == 'capec' for ref in (refs or []))
        ).sum()
        report.add_stat("Techniques with CAPEC mappings", has_capec)
    
    return report


def audit_top_recommendations(top_df: pd.DataFrame, kev_df: Optional[pd.DataFrame] = None) -> Dict:
    """Audit top recommendations for healthcare relevance
    
    Returns manual review checklist and statistics
    """
    audit = {
        'total': len(top_df),
        'kev_count': 0,
        'high_cvss_count': 0,
        'healthcare_keywords_count': 0,
        'recommendations': []
    }
    
    # Healthcare-related keywords for manual review
    healthcare_keywords = [
        'health', 'medical', 'patient', 'hospital', 'clinical', 'ehr', 'emr',
        'hipaa', 'pacs', 'dicom', 'hl7', 'fhir', 'pharmacy', 'diagnostic'
    ]
    
    for idx, row in top_df.iterrows():
        cve_id = row.get('cve_id', 'N/A')
        cvss = row.get('cvss', 0)
        kev_flag = row.get('kev_flag', 0)
        desc = str(row.get('description_en', row.get('description', ''))).lower()
        
        # Check for healthcare keywords
        has_health_keyword = any(kw in desc for kw in healthcare_keywords)
        
        audit['kev_count'] += int(kev_flag)
        if cvss >= 9.0:
            audit['high_cvss_count'] += 1
        if has_health_keyword:
            audit['healthcare_keywords_count'] += 1
        
        # Build recommendation
        rec = {
            'rank': idx + 1,
            'cve_id': cve_id,
            'cvss': float(cvss),
            'kev': bool(kev_flag),
            'has_healthcare_keyword': has_health_keyword,
            'review_priority': 'HIGH' if (kev_flag or has_health_keyword) else 'MEDIUM' if cvss >= 9.0 else 'LOW'
        }
        audit['recommendations'].append(rec)
    
    # Calculate precision estimates
    if len(audit['recommendations']) > 0:
        audit['kev_precision'] = audit['kev_count'] / len(audit['recommendations'])
        audit['healthcare_keyword_precision'] = audit['healthcare_keywords_count'] / len(audit['recommendations'])
    
    return audit


def generate_quality_report(
    nvd_df: pd.DataFrame,
    kev_df: Optional[pd.DataFrame] = None,
    chpl_df: Optional[pd.DataFrame] = None,
    attack_df: Optional[pd.DataFrame] = None,
    top_recommendations: Optional[pd.DataFrame] = None,
    output_path: Optional[Path] = None
) -> Dict:
    """Generate comprehensive data quality report for all datasets"""
    
    print("\n Running comprehensive data quality checks...\n")
    
    reports = {}
    
    # Check NVD
    print("Checking NVD dataset...")
    nvd_report = check_nvd_quality(nvd_df)
    reports['nvd'] = nvd_report
    nvd_report.print_summary()
    
    # Check KEV
    if kev_df is not None:
        print("Checking CISA KEV dataset...")
        kev_report = check_kev_quality(kev_df)
        reports['kev'] = kev_report
        kev_report.print_summary()
    
    # Check CHPL
    if chpl_df is not None:
        print("Checking CHPL dataset...")
        chpl_report = check_chpl_quality(chpl_df)
        reports['chpl'] = chpl_report
        chpl_report.print_summary()
    
    # Check ATT&CK
    if attack_df is not None:
        print("Checking MITRE ATT&CK dataset...")
        attack_report = check_attack_quality(attack_df)
        reports['attack'] = attack_report
        attack_report.print_summary()
    
    # Audit top recommendations
    if top_recommendations is not None:
        print("Auditing top recommendations...")
        audit = audit_top_recommendations(top_recommendations, kev_df)
        reports['audit'] = audit
        
        print("\n" + "="*70)
        print("TOP RECOMMENDATIONS AUDIT")
        print("="*70)
        print(f"\nTotal recommendations: {audit['total']}")
        print(f"KEV-flagged: {audit['kev_count']} ({audit.get('kev_precision', 0):.1%})")
        print(f"High CVSS (≥9.0): {audit['high_cvss_count']}")
        print(f"Healthcare keywords detected: {audit['healthcare_keywords_count']} ({audit.get('healthcare_keyword_precision', 0):.1%})")
        
        print("\n Manual Review Checklist (Top 10):")
        for rec in audit['recommendations'][:10]:
            priority_emoji = "" if rec['review_priority'] == 'HIGH' else "" if rec['review_priority'] == 'MEDIUM' else ""
            kev_badge = " [KEV]" if rec['kev'] else ""
            health_badge = " [HC]" if rec['has_healthcare_keyword'] else ""
            print(f"  {priority_emoji} #{rec['rank']:2d} {rec['cve_id']} (CVSS: {rec['cvss']:.1f}){kev_badge}{health_badge}")
        print("\n" + "="*70 + "\n")
    
    # Save to file if requested
    if output_path:
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(output_path, 'w') as f:
                f.write("="*70 + "\n")
                f.write("DATA QUALITY REPORT\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("="*70 + "\n\n")

                for dataset_name, report in reports.items():
                    if isinstance(report, DataQualityReport):
                        f.write(f"\n{dataset_name.upper()} DATASET\n")
                        f.write("-"*70 + "\n")

                        f.write("\nStatistics:\n")
                        for key, value in report.stats.items():
                            f.write(f"  {key}: {value}\n")

                        if report.errors:
                            f.write(f"\nErrors ({len(report.errors)}):\n")
                            for err in report.errors:
                                f.write(f"  - {err}\n")

                        if report.warnings:
                            f.write(f"\nWarnings ({len(report.warnings)}):\n")
                            for warn in report.warnings:
                                f.write(f"  - {warn}\n")

                        f.write("\n")
                    elif dataset_name == 'audit':
                        f.write("\nTOP RECOMMENDATIONS AUDIT\n")
                        f.write("-"*70 + "\n")
                        f.write(f"Total: {report['total']}\n")
                        f.write(f"KEV-flagged: {report['kev_count']}\n")
                        f.write(f"High CVSS: {report['high_cvss_count']}\n")
                        f.write(f"Healthcare keywords: {report['healthcare_keywords_count']}\n")
        except Exception:
            logger.exception("Failed to write quality report to %s", output_path)
            raise
        
        print(f"[OK] Report saved to: {output_path}")
    
    return reports


def main() -> int:
    try:
        print("Data Quality Module - use via import in your scripts")
        print("Example:")
        print("  from data_quality import generate_quality_report")
        print("  reports = generate_quality_report(nvd_df, kev_df, chpl_df, attack_df, top20_df, 'outputs/quality_report.txt')")
        return 0
    except Exception:
        logger.exception("Data quality module execution failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
