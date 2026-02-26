"""Healthcare-specific CPE and Vendor Mapping System

Provides structured mapping of CPE patterns, vendors, and products
to healthcare sector relevance for improved vulnerability prioritization.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Set, Optional
import re

import pandas as pd

logger = logging.getLogger("healthcare_mapping")
logging.basicConfig(level=logging.INFO)


# Healthcare-specific vendor patterns
HEALTHCARE_VENDORS = {
    # Medical Device Manufacturers
    'ge_healthcare': ['ge healthcare', 'ge medical', 'gehc'],
    'philips': ['philips healthcare', 'philips medical'],
    'siemens': ['siemens healthineers', 'siemens medical'],
    'medtronic': ['medtronic'],
    'boston_scientific': ['boston scientific'],
    'abbott': ['abbott laboratories', 'abbott'],
    'stryker': ['stryker'],
    'bd': ['becton dickinson', 'bd', 'carefusion'],
    'baxter': ['baxter'],
    'zimmer_biomet': ['zimmer biomet'],
    
    # EHR/EMR Vendors
    'epic': ['epic systems', 'epic'],
    'cerner': ['cerner', 'oracle health', 'oracle cerner'],
    'meditech': ['meditech', 'medical information technology'],
    'allscripts': ['allscripts'],
    'athenahealth': ['athenahealth'],
    'nextgen': ['nextgen healthcare'],
    'eclinicalworks': ['eclinicalworks'],
    'practice_fusion': ['practice fusion'],
    
    # PACS/Imaging
    'agfa': ['agfa healthcare'],
    'fujifilm': ['fujifilm medical'],
    'carestream': ['carestream health'],
    'sectra': ['sectra'],
    
    # Healthcare IT
    'mckesson': ['mckesson'],
    'change_healthcare': ['change healthcare'],
    'optum': ['optum', 'unitedhealth'],
    'nuance': ['nuance healthcare', 'nuance communications'],
    'infor': ['infor healthcare'],
    
    # Laboratory/Diagnostics
    'roche': ['roche diagnostics'],
    'quest': ['quest diagnostics'],
    'labcorp': ['laboratory corporation'],
    'beckman_coulter': ['beckman coulter'],
    
    # Pharmacy Systems
    'omnicell': ['omnicell'],
    'bd_rowa': ['bd rowa'],
    'arxium': ['arxium'],
    'scriptpro': ['scriptpro'],
    
    # Telehealth
    'teladoc': ['teladoc'],
    'amwell': ['american well', 'amwell'],
    'zoom': ['zoom healthcare'],  # When used in healthcare context
    
    # Hospital Management
    'workday': ['workday healthcare'],
    'kronos': ['kronos healthcare'],
}


# Healthcare product categories and keywords
HEALTHCARE_PRODUCTS = {
    'ehr_emr': [
        'electronic health record', 'electronic medical record',
        'ehr', 'emr', 'patient record system', 'clinical information system'
    ],
    'pacs': [
        'pacs', 'picture archiving', 'dicom', 'medical imaging',
        'radiology information system', 'ris'
    ],
    'medical_devices': [
        'infusion pump', 'ventilator', 'patient monitor', 'defibrillator',
        'mri', 'ct scanner', 'ultrasound', 'x-ray', 'anesthesia',
        'pacemaker', 'insulin pump', 'glucose monitor'
    ],
    'pharmacy': [
        'pharmacy management', 'medication dispensing', 'pharmacy system',
        'drug information', 'prescription'
    ],
    'laboratory': [
        'laboratory information system', 'lis', 'lab analyzer',
        'diagnostic system', 'specimen'
    ],
    'telehealth': [
        'telemedicine', 'telehealth', 'remote patient monitoring',
        'virtual care', 'patient portal'
    ],
    'hospital_operations': [
        'nurse call system', 'bed management', 'admission discharge transfer',
        'adt system', 'hospital information system', 'his'
    ]
}


# Healthcare-specific CVE description keywords
HEALTHCARE_KEYWORDS = [
    # Medical terminology
    'patient', 'medical', 'clinical', 'healthcare', 'hospital',
    'health care', 'physician', 'nurse', 'doctor', 'diagnosis',
    
    # Health data
    'phi', 'protected health information', 'patient data',
    'medical record', 'health information', 'clinical data',
    
    # Standards
    'hipaa', 'hitech', 'hl7', 'fhir', 'dicom', 'ihe',
    
    # Departments
    'radiology', 'cardiology', 'oncology', 'emergency department',
    'intensive care', 'icu', 'operating room', 'laboratory',
    
    # Equipment
    'medical device', 'diagnostic equipment', 'imaging system',
    'infusion', 'ventilator', 'monitor',
    
    # Systems
    'ehr', 'emr', 'pacs', 'ris', 'lis', 'his', 'cpoe'
]


class HealthcareMapper:
    """Enhanced healthcare relevance mapper with structured patterns"""
    
    def __init__(self):
        self.vendor_patterns = self._compile_vendor_patterns()
        self.product_keywords = self._flatten_product_keywords()
        self.healthcare_keywords = [kw.lower() for kw in HEALTHCARE_KEYWORDS]
        
    def _compile_vendor_patterns(self) -> Dict[str, List[str]]:
        """Normalize vendor patterns to lowercase"""
        patterns = {}
        for key, vendors in HEALTHCARE_VENDORS.items():
            patterns[key] = [v.lower() for v in vendors]
        return patterns
    
    def _flatten_product_keywords(self) -> List[str]:
        """Flatten product keywords into single list"""
        keywords = []
        for category, terms in HEALTHCARE_PRODUCTS.items():
            keywords.extend([t.lower() for t in terms])
        return keywords
    
    def check_vendor_match(self, text: str) -> Optional[str]:
        """Check if text matches healthcare vendor
        
        Returns vendor key if match found, None otherwise
        """
        if not isinstance(text, str):
            return None
        
        text_lower = text.lower()
        
        for vendor_key, patterns in self.vendor_patterns.items():
            for pattern in patterns:
                # Use word boundaries to avoid false positives like "epic fail" matching "epic"
                regex_pattern = r'\b' + re.escape(pattern) + r'\b'
                if re.search(regex_pattern, text_lower):
                    return vendor_key
        
        return None
    
    def check_product_match(self, text: str) -> bool:
        """Check if text mentions healthcare products
        
        Uses word boundaries for short acronyms to avoid false positives
        """
        if not isinstance(text, str):
            return False
        
        text_lower = text.lower()
        
        for keyword in self.product_keywords:
            # Short acronyms (<=4 chars) need word boundaries to avoid substring matches
            # e.g., 'his' should match "HIS system" not "this is"
            if len(keyword) <= 4 and keyword.isalpha():
                regex_pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(regex_pattern, text_lower):
                    return True
            else:
                # Longer keywords can use substring matching
                if keyword in text_lower:
                    return True
        
        return False
    
    def check_healthcare_keyword(self, text: str) -> bool:
        """Check if text contains healthcare keywords
        
        Uses word boundaries for short acronyms to avoid false positives
        """
        if not isinstance(text, str):
            return False
        
        text_lower = text.lower()
        
        for keyword in self.healthcare_keywords:
            # Short acronyms (<=4 chars) need word boundaries to avoid substring matches
            # e.g., 'his' should match "HIS system" not "this is", 'phi' should match "PHI data" not "graphics"
            if len(keyword) <= 4 and keyword.isalpha():
                regex_pattern = r'\b' + re.escape(keyword) + r'\b'
                if re.search(regex_pattern, text_lower):
                    return True
            else:
                # Longer keywords and multi-word phrases can use substring matching
                if keyword in text_lower:
                    return True
        
        return False
    
    def get_healthcare_score(self, text: str, vendor_weight: float = 0.5, 
                            product_weight: float = 0.3, keyword_weight: float = 0.2) -> float:
        """Calculate healthcare relevance score (0-1)
        
        Combines vendor, product, and keyword matching with configurable weights
        """
        if not isinstance(text, str):
            return 0.0
        
        score = 0.0
        
        # Vendor match (strongest signal)
        if self.check_vendor_match(text):
            score += vendor_weight
        
        # Product match (medium signal)
        if self.check_product_match(text):
            score += product_weight
        
        # Keyword match (weakest signal)
        if self.check_healthcare_keyword(text):
            score += keyword_weight
        
        return min(score, 1.0)  # Cap at 1.0
    
    def enrich_dataframe(self, df: pd.DataFrame, description_col: str = 'description_en') -> pd.DataFrame:
        """Add healthcare mapping features to dataframe
        
        Adds columns:
        - healthcare_vendor: matched vendor key or None
        - healthcare_product: boolean indicating product match
        - healthcare_keyword: boolean indicating keyword match
        - healthcare_score: composite relevance score (0-1)
        - is_healthcare: binary flag (1 if score > 0.3)
        """
        df = df.copy()
        
        # Use fallback description column if needed
        if description_col not in df.columns:
            description_col = 'description' if 'description' in df.columns else None
        
        if description_col is None:
            logger.warning("No description column found, cannot enrich dataframe")
            return df
        
        # Apply mappings
        df['healthcare_vendor'] = df[description_col].apply(self.check_vendor_match)
        df['healthcare_product'] = df[description_col].apply(self.check_product_match).astype(int)
        df['healthcare_keyword'] = df[description_col].apply(self.check_healthcare_keyword).astype(int)
        df['healthcare_score'] = df[description_col].apply(self.get_healthcare_score)
        
        # Binary flag with threshold
        df['is_healthcare'] = (df['healthcare_score'] > 0.3).astype(int)
        
        return df
    
    def export_mapping_csv(self, output_path: Path):
        """Export healthcare mapping patterns to CSV for review/editing"""
        records = []
        
        # Export vendors
        for vendor_key, patterns in self.vendor_patterns.items():
            for pattern in patterns:
                records.append({
                    'type': 'vendor',
                    'key': vendor_key,
                    'pattern': pattern,
                    'active': True
                })
        
        # Export product keywords
        for category, terms in HEALTHCARE_PRODUCTS.items():
            for term in terms:
                records.append({
                    'type': 'product',
                    'key': category,
                    'pattern': term.lower(),
                    'active': True
                })
        
        # Export general keywords
        for keyword in HEALTHCARE_KEYWORDS:
            records.append({
                'type': 'keyword',
                'key': 'general',
                'pattern': keyword.lower(),
                'active': True
            })
        
        df = pd.DataFrame(records)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(output_path, index=False)
        
        logger.info(f"Exported {len(records)} mapping patterns to {output_path}")
        return df


def load_custom_mappings(csv_path: Path) -> HealthcareMapper:
    """Load healthcare mapper from custom CSV file
    
    CSV should have columns: type, key, pattern, active
    """
    df = pd.read_csv(csv_path)
    
    # Filter active patterns
    df = df[df['active'] == True]
    
    # Reconstruct mappings
    custom_vendors = {}
    custom_products = {}
    custom_keywords = []
    
    for _, row in df.iterrows():
        pattern_type = row['type']
        key = row['key']
        pattern = row['pattern']
        
        if pattern_type == 'vendor':
            if key not in custom_vendors:
                custom_vendors[key] = []
            custom_vendors[key].append(pattern)
        elif pattern_type == 'product':
            if key not in custom_products:
                custom_products[key] = []
            custom_products[key].append(pattern)
        elif pattern_type == 'keyword':
            custom_keywords.append(pattern)
    
    # Update globals and create mapper
    HEALTHCARE_VENDORS.update(custom_vendors)
    HEALTHCARE_PRODUCTS.update(custom_products)
    HEALTHCARE_KEYWORDS.extend(custom_keywords)
    
    return HealthcareMapper()


def analyze_healthcare_coverage(df: pd.DataFrame, mapper: HealthcareMapper, 
                                description_col: str = 'description_en') -> Dict:
    """Analyze healthcare coverage in dataset"""
    
    enriched = mapper.enrich_dataframe(df, description_col)
    
    analysis = {
        'total_cves': len(enriched),
        'healthcare_flagged': enriched['is_healthcare'].sum(),
        'vendor_matches': enriched['healthcare_vendor'].notna().sum(),
        'product_matches': enriched['healthcare_product'].sum(),
        'keyword_matches': enriched['healthcare_keyword'].sum(),
        'avg_healthcare_score': enriched['healthcare_score'].mean(),
        'top_vendors': enriched['healthcare_vendor'].value_counts().head(10).to_dict()
    }
    
    return analysis


if __name__ == "__main__":
    # Example usage and testing
    mapper = HealthcareMapper()
    
    # Export default mappings
    output_path = Path("data/config/healthcare_mapping.csv")
    mapper.export_mapping_csv(output_path)
    print(f"[OK] Exported healthcare mappings to {output_path}")
    
    # Test examples
    test_cases = [
        "Epic Systems electronic health record vulnerability",
        "Philips MRI system buffer overflow",
        "Generic WordPress plugin XSS",
        "Cerner HIPAA patient data exposure",
        "Microsoft Windows kernel vulnerability"
    ]
    
    print("\n[TEST] Testing healthcare detection:")
    for test in test_cases:
        score = mapper.get_healthcare_score(test)
        vendor = mapper.check_vendor_match(test)
        product = mapper.check_product_match(test)
        print(f"  Score: {score:.2f} | Vendor: {vendor or 'None':<15} | Product: {product} | {test[:60]}")
