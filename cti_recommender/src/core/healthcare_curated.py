"""
Healthcare Curated Dataset Manager
Loads and manages confirmed healthcare breach CVEs for high-confidence labeling
"""

import json
import pandas as pd
from pathlib import Path
from typing import Dict, List, Optional, Set
import logging

logger = logging.getLogger("healthcare_curated")

# Default path to curated dataset
DEFAULT_CURATED_PATH = Path("data/healthcare_breaches.json")


class HealthcareCuratedDataset:
    """Manages curated healthcare breach dataset"""
    
    def __init__(self, data_path: Path = DEFAULT_CURATED_PATH):
        self.data_path = Path(data_path)
        self.breaches = []
        self.metadata = {}
        self.cve_index = {}
        self._load()
    
    def _load(self):
        """Load curated dataset from JSON file"""
        if not self.data_path.exists():
            logger.warning(f"Curated dataset not found at {self.data_path}")
            return
        
        try:
            with open(self.data_path, 'r') as f:
                data = json.load(f)
            
            self.metadata = data.get('metadata', {})
            self.breaches = data.get('breaches', [])
            
            # Build index for fast lookup
            self.cve_index = {
                breach['cve_id']: breach 
                for breach in self.breaches
            }
            
            logger.info(
                f"Loaded {len(self.breaches)} curated healthcare CVEs "
                f"(v{self.metadata.get('version', 'unknown')})"
            )
            
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to load curated dataset: {e}")
            self.breaches = []
            self.cve_index = {}
    
    def get_cve_ids(self) -> Set[str]:
        """Get set of all curated CVE IDs"""
        return set(self.cve_index.keys())
    
    def is_curated(self, cve_id: str) -> bool:
        """Check if CVE is in curated dataset"""
        return cve_id in self.cve_index
    
    def get_breach_info(self, cve_id: str) -> Optional[Dict]:
        """Get full breach information for a CVE"""
        return self.cve_index.get(cve_id)
    
    def get_by_severity(self, severity: str) -> List[Dict]:
        """Get all breaches with specific severity"""
        return [
            breach for breach in self.breaches
            if breach.get('severity', '').lower() == severity.lower()
        ]
    
    def get_by_vendor(self, vendor: str) -> List[Dict]:
        """Get all breaches affecting a specific vendor"""
        vendor_lower = vendor.lower()
        return [
            breach for breach in self.breaches
            if any(vendor_lower in v.lower() for v in breach.get('affected_vendors', []))
        ]
    
    def get_exploited_in_wild(self) -> List[Dict]:
        """Get all CVEs confirmed exploited in the wild"""
        return [
            breach for breach in self.breaches
            if breach.get('exploited_in_wild', False)
        ]
    
    def get_high_confidence(self) -> List[Dict]:
        """Get high-confidence healthcare breaches"""
        return [
            breach for breach in self.breaches
            if breach.get('confidence', '').lower() == 'high'
        ]
    
    def enrich_dataframe(self, df: pd.DataFrame, cve_column: str = 'cve_id') -> pd.DataFrame:
        """
        Add curated dataset flags to DataFrame
        
        Args:
            df: DataFrame with CVE IDs
            cve_column: Name of column containing CVE IDs
        
        Returns:
            DataFrame with added columns: is_curated, curated_severity, curated_confidence
        """
        if cve_column not in df.columns:
            logger.warning(f"Column '{cve_column}' not found")
            df['is_curated'] = 0
            df['curated_severity'] = ''
            df['curated_confidence'] = ''
            return df
        
        # Map CVEs to curated info
        df['is_curated'] = df[cve_column].map(
            lambda cve: 1 if self.is_curated(cve) else 0
        )
        
        df['curated_severity'] = df[cve_column].map(
            lambda cve: self.cve_index.get(cve, {}).get('severity', '')
        )
        
        df['curated_confidence'] = df[cve_column].map(
            lambda cve: self.cve_index.get(cve, {}).get('confidence', '')
        )
        
        df['curated_exploited'] = df[cve_column].map(
            lambda cve: 1 if self.cve_index.get(cve, {}).get('exploited_in_wild', False) else 0
        )
        
        # Report coverage
        curated_count = df['is_curated'].sum()
        coverage = curated_count / len(df) * 100 if len(df) > 0 else 0
        logger.info(
            f"Curated dataset coverage: {curated_count}/{len(df)} ({coverage:.1f}%)"
        )
        
        return df
    
    def get_label_score(self, cve_id: str) -> int:
        """
        Get label score (0-5) for a CVE based on curated data
        
        Scoring:
        - 5: Critical + high confidence + exploited in wild
        - 4: Critical + high confidence
        - 3: High severity + exploited in wild
        - 2: In curated dataset but lower severity
        - 0: Not in curated dataset
        
        Args:
            cve_id: CVE ID to score
        
        Returns:
            Integer score 0-5
        """
        if not self.is_curated(cve_id):
            return 0
        
        breach = self.get_breach_info(cve_id)
        severity = breach.get('severity', '').lower()
        confidence = breach.get('confidence', '').lower()
        exploited = breach.get('exploited_in_wild', False)
        
        # Critical + high confidence + exploited = 5
        if severity == 'critical' and confidence == 'high' and exploited:
            return 5
        
        # Critical + high confidence = 4
        if severity == 'critical' and confidence == 'high':
            return 4
        
        # High severity + exploited = 3
        if severity == 'high' and exploited:
            return 3
        
        # Critical but medium confidence = 3
        if severity == 'critical':
            return 3
        
        # In dataset but lower priority = 2
        return 2
    
    def get_statistics(self) -> Dict:
        """Get statistics about the curated dataset"""
        total = len(self.breaches)
        
        if total == 0:
            return {
                'total': 0,
                'by_severity': {},
                'by_confidence': {},
                'exploited_count': 0,
                'unique_vendors': 0
            }
        
        stats = {
            'total': total,
            'by_severity': {},
            'by_confidence': {},
            'by_breach_type': {},
            'exploited_count': sum(1 for b in self.breaches if b.get('exploited_in_wild', False)),
            'exploited_percentage': sum(1 for b in self.breaches if b.get('exploited_in_wild', False)) / total * 100,
        }
        
        # Count by severity
        for breach in self.breaches:
            sev = breach.get('severity', 'unknown')
            stats['by_severity'][sev] = stats['by_severity'].get(sev, 0) + 1
            
            conf = breach.get('confidence', 'unknown')
            stats['by_confidence'][conf] = stats['by_confidence'].get(conf, 0) + 1
            
            breach_type = breach.get('breach_type', 'unknown')
            stats['by_breach_type'][breach_type] = stats['by_breach_type'].get(breach_type, 0) + 1
        
        # Count unique vendors
        all_vendors = set()
        for breach in self.breaches:
            vendors = breach.get('affected_vendors', [])
            all_vendors.update(vendors)
        stats['unique_vendors'] = len(all_vendors)
        
        return stats
    
    def print_summary(self):
        """Print summary of curated dataset"""
        stats = self.get_statistics()
        
        print("\n" + "="*70)
        print("HEALTHCARE CURATED DATASET SUMMARY")
        print("="*70)
        print(f"\nTotal CVEs: {stats['total']}")
        print(f"Exploited in wild: {stats['exploited_count']} ({stats.get('exploited_percentage', 0):.1f}%)")
        print(f"Unique vendors: {stats['unique_vendors']}")
        
        print("\nBy Severity:")
        for sev, count in sorted(stats['by_severity'].items(), key=lambda x: x[1], reverse=True):
            print(f"  • {sev}: {count}")
        
        print("\nBy Confidence:")
        for conf, count in sorted(stats['by_confidence'].items(), key=lambda x: x[1], reverse=True):
            print(f"  • {conf}: {count}")
        
        print("\nTop Breach Types:")
        top_types = sorted(stats['by_breach_type'].items(), key=lambda x: x[1], reverse=True)[:5]
        for btype, count in top_types:
            print(f"  • {btype.replace('_', ' ').title()}: {count}")
        
        print("="*70 + "\n")


def load_curated_dataset(data_path: Path = DEFAULT_CURATED_PATH) -> HealthcareCuratedDataset:
    """
    Convenience function to load curated dataset
    
    Args:
        data_path: Path to healthcare_breaches.json
    
    Returns:
        HealthcareCuratedDataset instance
    """
    return HealthcareCuratedDataset(data_path)


if __name__ == "__main__":
    # Test the curated dataset
    print("Loading healthcare curated dataset...")
    dataset = load_curated_dataset()
    
    # Print summary
    dataset.print_summary()
    
    # Test specific queries
    print("\nHigh confidence breaches:")
    high_conf = dataset.get_high_confidence()
    for breach in high_conf[:5]:
        print(f"  • {breach['cve_id']}: {breach.get('healthcare_impact', 'N/A')}")
    
    print(f"\n... and {len(high_conf) - 5} more")
    
    # Test label scoring
    print("\nLabel score examples:")
    test_cves = ['CVE-2021-44228', 'CVE-2023-0669', 'CVE-2020-1472', 'CVE-2999-99999']
    for cve in test_cves:
        score = dataset.get_label_score(cve)
        curated = "✓" if dataset.is_curated(cve) else "✗"
        print(f"  {cve}: score={score} curated={curated}")
