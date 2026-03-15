#!/usr/bin/env python3
"""
ATT&CK technique mapper for CVEs.
Uses cached ATT&CK Enterprise matrix - no external API calls.
Maps CVE descriptions to MITRE ATT&CK techniques via keyword matching.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import gzip
import pickle
import re
import sys
import pandas as pd
from typing import List, Dict, Set

try:
    from src.utils.logging_config import get_logger
    logger = get_logger(__name__)
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

class AttackMapper:
    """Maps CVEs to MITRE ATT&CK techniques using cached data."""
    
    def __init__(self, cache_path=None):
        """Load ATT&CK techniques from cache."""
        if cache_path is None:
            cache_path = Path(__file__).parent.parent.parent / 'cache' / 'attack' / 'attack_techniques.pkl.gz'

        try:
            with gzip.open(cache_path, 'rb') as f:
                self.techniques_df = pickle.load(f)
        except Exception:
            logger.exception("Failed to load ATT&CK cache from %s", cache_path)
            raise

        logger.info(f"Loaded {len(self.techniques_df)} ATT&CK techniques from cache")

        # Build lookup dictionaries for fast matching
        self._build_lookups()
    
    def _build_lookups(self):
        """Build efficient lookup structures."""
        self.technique_names = {}  # name -> technique_id
        self.technique_patterns = []  # (regex_pattern, technique_id, name)
        
        for _, tech in self.techniques_df.iterrows():
            # Extract technique ID from external_references
            external_refs = tech.get('external_references', [])
            tech_id = None
            
            if isinstance(external_refs, list):
                for ref in external_refs:
                    if ref.get('source_name') == 'mitre-attack' and 'external_id' in ref:
                        tech_id = ref['external_id']
                        break
            
            name = tech.get('name', '').lower()
            
            if not tech_id or not name:
                continue
            
            # Store name mapping
            self.technique_names[name] = tech_id
            
            # Create regex pattern for matching
            # Escape special chars and make it word-boundary aware
            pattern = r'\b' + re.escape(name) + r'\b'
            self.technique_patterns.append((
                re.compile(pattern, re.IGNORECASE),
                tech_id,
                name
            ))
        
        logger.info(f"Built {len(self.technique_patterns)} technique patterns for matching")
    
    def map_cve_to_techniques(self, description: str) -> Dict:
        """
        Map CVE description to ATT&CK techniques.
        
        Returns dict with:
        - techniques: List of matched technique IDs
        - technique_count: Number of techniques
        - attack_flag: 1 if any techniques matched, 0 otherwise
        """
        if not description:
            return {
                'techniques': [],
                'technique_count': 0,
                'attack_flag': 0
            }
        
        matched_techniques = set()
        
        # Try to match each technique pattern
        for pattern, tech_id, name in self.technique_patterns:
            if pattern.search(description):
                matched_techniques.add(tech_id)
        
        return {
            'techniques': sorted(list(matched_techniques)),
            'technique_count': len(matched_techniques),
            'attack_flag': 1 if matched_techniques else 0
        }
    
    def get_technique_info(self, technique_id: str) -> Dict:
        """Get detailed info for a technique."""
        # Find by matching external_id in external_references
        for _, tech in self.techniques_df.iterrows():
            external_refs = tech.get('external_references', [])
            if isinstance(external_refs, list):
                for ref in external_refs:
                    if ref.get('external_id') == technique_id:
                        return {
                            'id': technique_id,
                            'name': tech.get('name', ''),
                            'description': tech.get('description', '')[:200]
                        }
        return {}

def main() -> int:
    try:
        # Test the mapper
        mapper = AttackMapper()

        # Test cases
        test_cases = [
            "SQL injection vulnerability in web application",
            "Remote code execution via buffer overflow",
            "Privilege escalation through DLL hijacking",
            "Cross-site scripting (XSS) in user input field",
            "Denial of service via resource exhaustion"
        ]

        print("\n" + "="*70)
        print("ATT&CK MAPPER TEST")
        print("="*70)

        for desc in test_cases:
            result = mapper.map_cve_to_techniques(desc)
            print(f"\nDescription: {desc}")
            print(f"  Matched: {result['technique_count']} techniques")
            for tech_id in result['techniques'][:3]:  # Show first 3
                info = mapper.get_technique_info(tech_id)
                print(f"    {tech_id}: {info.get('name', 'Unknown')}")
        return 0
    except Exception:
        logger.exception("ATT&CK mapper demo execution failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
