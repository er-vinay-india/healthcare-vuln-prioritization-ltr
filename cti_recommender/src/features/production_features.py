"""
Production-Ready Feature Engineering (Leakage-Free)
====================================================

Extracts predictive features available at CVE publication time WITHOUT using:
- KEV flags (what we're predicting)
- EPSS scores (what we're predicting)

Uses ONLY publication-time signals:
- CVSS severity
- CWE weakness patterns
- Vendor/product intelligence
- ATT&CK mappings
- Description keywords
- Historical patterns
- Healthcare relevance

Author: AI-Enhanced Feature Engineering
Date: 2026-03-03
"""

import re
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from collections import defaultdict


# CWE Top 25 Most Dangerous Software Weaknesses (2023-2024)
CWE_TOP_25 = {
    'CWE-787',   # Out-of-bounds Write
    'CWE-79',    # Cross-site Scripting (XSS)
    'CWE-89',    # SQL Injection
    'CWE-416',   # Use After Free
    'CWE-78',    # OS Command Injection
    'CWE-20',    # Improper Input Validation
    'CWE-125',   # Out-of-bounds Read
    'CWE-22',    # Path Traversal
    'CWE-352',   # CSRF
    'CWE-434',   # Unrestricted Upload
    'CWE-862',   # Missing Authorization
    'CWE-476',   # NULL Pointer Dereference
    'CWE-287',   # Improper Authentication
    'CWE-190',   # Integer Overflow
    'CWE-502',   # Deserialization of Untrusted Data
    'CWE-77',    # Command Injection
    'CWE-119',   # Improper Restriction of Operations
    'CWE-798',   # Hard-coded Credentials
    'CWE-918',   # SSRF
    'CWE-306',   # Missing Authentication
    'CWE-362',   # Race Condition
    'CWE-269',   # Improper Privilege Management
    'CWE-94',    # Code Injection
    'CWE-863',   # Incorrect Authorization
    'CWE-276',   # Incorrect Default Permissions
}

# Major vendors with high exploit rates
HIGH_RISK_VENDORS = {
    'microsoft', 'cisco', 'adobe', 'oracle', 'google', 'apple',
    'linux', 'apache', 'mozilla', 'atlassian', 'gitlab', 'jenkins'
}

# Healthcare-specific vendors
HEALTHCARE_VENDORS = {
    'philips', 'ge healthcare', 'siemens', 'medtronic', 'cerner',
    'epic', 'allscripts', 'mckesson', 'baxter', 'bd', 'becton',
    'stryker', 'abbott', 'boston scientific', 'drager', 'fresenius',
    'hospira', 'smiths medical', 'masimo', 'nihon kohden'
}

# Exploitation keywords in CVE descriptions
EXPLOIT_KEYWORDS = {
    'high': [
        'remote code execution', 'rce', 'arbitrary code execution',
        'bypass authentication', 'privilege escalation', 'authentication bypass',
        'buffer overflow', 'proof of concept', 'poc', 'exploit available',
        'actively exploited', 'in the wild', 'zero-day', '0day'
    ],
    'medium': [
        'denial of service', 'dos', 'information disclosure',
        'cross-site scripting', 'xss', 'sql injection',
        'code injection', 'command injection', 'path traversal'
    ],
    'low': [
        'improper access control', 'insufficient verification',
        'weak encryption', 'missing validation'
    ]
}


class ProductionFeatureEngineer:
    """
    Extracts production-ready features using only publication-time data.
    
    NO LEAKAGE: Does not use KEV flags or EPSS scores
    """
    
    def __init__(self, historical_data: Optional[pd.DataFrame] = None):
        """
        Initialize feature engineer.
        
        Args:
            historical_data: Historical CVE data for computing vendor/CWE risk scores
                           Must have columns: cve_id, kev_flag (for training)
        """
        self.historical_data = historical_data
        self.vendor_risk_scores = {}
        self.cwe_risk_scores = {}
        
        if historical_data is not None:
            self._compute_historical_patterns()
    
    def _compute_historical_patterns(self):
        """Compute vendor and CWE exploitation rates from historical data."""
        if self.historical_data is None or 'kev_flag' not in self.historical_data.columns:
            return
        
        # Vendor exploitation rates
        if 'description' in self.historical_data.columns:
            self.historical_data['vendor'] = self.historical_data['description'].apply(self._extract_vendor)
            vendor_stats = self.historical_data.groupby('vendor')['kev_flag'].agg(['sum', 'count'])
            vendor_stats = vendor_stats[vendor_stats['count'] >= 5]  # Min 5 CVEs
            self.vendor_risk_scores = (vendor_stats['sum'] / vendor_stats['count']).to_dict()
        
        # CWE exploitation rates
        if 'cwe' in self.historical_data.columns:
            cwe_data = self.historical_data[self.historical_data['cwe'].notna()].copy()
            cwe_data['cwe_id'] = cwe_data['cwe'].apply(self._extract_primary_cwe)
            cwe_stats = cwe_data.groupby('cwe_id')['kev_flag'].agg(['sum', 'count'])
            cwe_stats = cwe_stats[cwe_stats['count'] >= 10]  # Min 10 CVEs
            self.cwe_risk_scores = (cwe_stats['sum'] / cwe_stats['count']).to_dict()
    
    @staticmethod
    def _extract_vendor(description: str) -> str:
        """Extract vendor from description text."""
        if not description or pd.isna(description):
            return "unknown"
        
        desc_lower = str(description).lower()
        
        # Check for high-risk vendors
        for vendor in HIGH_RISK_VENDORS:
            if vendor in desc_lower:
                return vendor
        
        # Check for healthcare vendors
        for vendor in HEALTHCARE_VENDORS:
            if vendor in desc_lower:
                return vendor
        
        return "unknown"
    
    @staticmethod
    def _extract_primary_cwe(cwe_str: str) -> str:
        """Extract primary CWE ID from CWE string."""
        if not cwe_str or pd.isna(cwe_str):
            return "UNKNOWN"
        match = re.search(r'CWE-(\d+)', str(cwe_str))
        return f"CWE-{match.group(1)}" if match else "UNKNOWN"
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Extract all production-ready features from CVE data.
        
        Args:
            df: DataFrame with CVE data (must have: cve_id, cvss, description, cwe, published, etc.)
        
        Returns:
            DataFrame with added feature columns
        """
        result = df.copy()
        
        # Ensure datetime
        if 'published' in result.columns:
            result['published'] = pd.to_datetime(result['published'], errors='coerce')
        
        # === 1. CVSS FEATURES (available at publish) ===
        result = self._extract_cvss_features(result)
        
        # === 2. CWE FEATURES (available at publish) ===
        result = self._extract_cwe_features(result)
        
        # === 3. VENDOR FEATURES (extracted from description) ===
        result = self._extract_vendor_features(result)
        
        # === 4. DESCRIPTION NLP FEATURES (available at publish) ===
        result = self._extract_description_features(result)
        
        # === 5. TEMPORAL FEATURES (publication time) ===
        result = self._extract_temporal_features(result)
        
        # === 6. HEALTHCARE FEATURES (available at publish) ===
        result = self._extract_healthcare_features(result)
        
        # === 7. ATT&CK FEATURES (available shortly after publish) ===
        result = self._extract_attack_features(result)
        
        # === 8. HISTORICAL RISK SCORES (computed from past data) ===
        result = self._extract_historical_risk(result)
        
        return result
    
    def _extract_cvss_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract CVSS-based features."""
        result = df.copy()
        
        result['cvss'] = result.get('cvss', pd.Series(5.0, index=result.index)).fillna(5.0)
        result['cvss_norm'] = result['cvss'] / 10.0
        result['cvss_critical'] = (result['cvss'] >= 9.0).astype(int)
        result['cvss_high'] = (result['cvss'] >= 7.0).astype(int)
        result['cvss_medium'] = ((result['cvss'] >= 4.0) & (result['cvss'] < 7.0)).astype(int)
        result['cvss_low'] = (result['cvss'] < 4.0).astype(int)
        
        return result
    
    def _extract_cwe_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract CWE weakness pattern features."""
        result = df.copy()
        
        # Extract primary CWE
        if 'cwe' in result.columns:
            result['cwe_id'] = result['cwe'].apply(self._extract_primary_cwe)
        else:
            result['cwe_id'] = "UNKNOWN"
        
        # CWE Top 25 flag
        result['cwe_top25'] = result['cwe_id'].apply(lambda x: 1 if x in CWE_TOP_25 else 0)
        
        # CWE category (first digit indicates category)
        result['cwe_category'] = result['cwe_id'].apply(self._categorize_cwe)
        
        # Count of CWEs (some CVEs have multiple)
        if 'cwe' in result.columns:
            result['cwe_count'] = result['cwe'].apply(lambda x: len(re.findall(r'CWE-\d+', str(x))) if pd.notna(x) else 0)
        else:
            result['cwe_count'] = 0
        
        return result
    
    @staticmethod
    def _categorize_cwe(cwe_id: str) -> str:
        """Categorize CWE by type."""
        if cwe_id == "UNKNOWN":
            return "unknown"
        
        cwe_categories = {
            'memory': ['787', '416', '125', '476', '119'],  # Memory issues
            'injection': ['79', '89', '78', '77', '94'],    # Injection flaws
            'auth': ['287', '306', '862', '863'],           # Authentication
            'crypto': ['327', '328', '798'],                # Cryptographic
            'path': ['22', '434', '352'],                   # Path/File issues
        }
        
        cwe_num = cwe_id.replace('CWE-', '')
        for category, nums in cwe_categories.items():
            if cwe_num in nums:
                return category
        
        return "other"
    
    def _extract_vendor_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract vendor-based features from description (optimized for large datasets)."""
        result = df.copy()
        
        if 'description' not in result.columns:
            result['is_high_risk_vendor'] = 0
            result['is_healthcare_vendor'] = 0
            return result
        
        result['description_lower'] = result['description'].fillna('').str.lower()
        
        # Vectorized vendor detection (much faster for large datasets)
        # Build regex pattern for batch matching
        high_risk_pattern = '|'.join(HIGH_RISK_VENDORS)
        healthcare_pattern = '|'.join(HEALTHCARE_VENDORS)
        
        result['is_high_risk_vendor'] = result['description_lower'].str.contains(
            high_risk_pattern, case=False, regex=True, na=False
        ).astype(int)
        
        result['is_healthcare_vendor'] = result['description_lower'].str.contains(
            healthcare_pattern, case=False, regex=True, na=False
        ).astype(int)
        
        result.drop('description_lower', axis=1, inplace=True)
        
        return result
    
    def _extract_description_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract NLP features from CVE descriptions (optimized for large datasets)."""
        result = df.copy()
        
        if 'description' not in result.columns:
            result['desc_length'] = 0
            result['has_exploit_keywords_high'] = 0
            result['has_exploit_keywords_med'] = 0
            result['exploit_keyword_count'] = 0
            return result
        
        result['description_lower'] = result['description'].fillna('').str.lower()
        
        # Description length (longer = more complex/serious)
        result['desc_length'] = result['description'].fillna('').str.len()
        result['desc_length_norm'] = np.clip(result['desc_length'] / 500.0, 0, 1)
        
        # Vectorized keyword detection using regex
        high_pattern = '|'.join([kw.replace(' ', r'\s+') for kw in EXPLOIT_KEYWORDS['high']])
        med_pattern = '|'.join([kw.replace(' ', r'\s+') for kw in EXPLOIT_KEYWORDS['medium']])
        low_pattern = '|'.join([kw.replace(' ', r'\s+') for kw in EXPLOIT_KEYWORDS['low']])
        
        result['has_exploit_keywords_high'] = result['description_lower'].str.contains(
            high_pattern, case=False, regex=True, na=False
        ).astype(int)
        
        result['has_exploit_keywords_med'] = result['description_lower'].str.contains(
            med_pattern, case=False, regex=True, na=False
        ).astype(int)
        
        result['has_exploit_keywords_low'] = result['description_lower'].str.contains(
            low_pattern, case=False, regex=True, na=False
        ).astype(int)
        
        # Keyword count (approximate - count total keyword indicators)
        result['exploit_keyword_count'] = (
            result['has_exploit_keywords_high'] * 2 +  # High keywords more weight
            result['has_exploit_keywords_med'] +
            result['has_exploit_keywords_low']
        )
        
        result.drop('description_lower', axis=1, inplace=True)
        
        return result
    
    def _extract_temporal_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract temporal/recency features."""
        result = df.copy()
        
        if 'published' not in result.columns:
            result['days_since_published'] = 0
            result['recency_score'] = 0.5
            result['is_recent'] = 0
            return result
        
        prediction_date = datetime.now()
        result['days_since_published'] = (prediction_date - result['published']).dt.days.fillna(0).astype(int)
        result['recency_score'] = 1.0 / (1.0 + result['days_since_published'] / 365.0)
        result['is_recent'] = (result['days_since_published'] <= 90).astype(int)
        
        return result
    
    def _extract_healthcare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract healthcare-specific features."""
        result = df.copy()
        
        # Use existing healthcare flags if available
        if 'is_healthcare' not in result.columns:
            result['is_healthcare'] = 0
        
        if 'chpl_flag' not in result.columns:
            result['chpl_flag'] = 0
        
        # Interaction: healthcare × critical
        result['healthcare_critical'] = (result['is_healthcare'] & result['cvss_critical']).astype(int)
        result['chpl_critical'] = (result['chpl_flag'] & result['cvss_critical']).astype(int)
        
        return result
    
    def _extract_attack_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract ATT&CK mapping features."""
        result = df.copy()
        
        if 'attack_technique_count' not in result.columns:
            result['attack_technique_count'] = 0
        
        result['has_attack'] = (result['attack_technique_count'] > 0).astype(int)
        result['attack_multi'] = (result['attack_technique_count'] > 1).astype(int)
        result['attack_healthcare'] = (result['has_attack'] & result['is_healthcare']).astype(int)
        
        return result
    
    def _extract_historical_risk(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add historical risk scores for vendor and CWE."""
        result = df.copy()
        
        # Vendor risk score (from historical exploitation rates)
        if self.vendor_risk_scores and 'description' in result.columns:
            result['vendor_risk_score'] = 0.0
            for idx, row in result.iterrows():
                desc_lower = str(row.get('description', '')).lower()
                for vendor, risk in self.vendor_risk_scores.items():
                    if vendor in desc_lower:
                        result.at[idx, 'vendor_risk_score'] = max(result.at[idx, 'vendor_risk_score'], risk)
        else:
            result['vendor_risk_score'] = 0.0
        
        # CWE risk score (from historical exploitation rates)
        if self.cwe_risk_scores and 'cwe_id' in result.columns:
            result['cwe_risk_score'] = result['cwe_id'].map(self.cwe_risk_scores).fillna(0.0)
        else:
            result['cwe_risk_score'] = 0.0
        
        return result
    
    def get_feature_columns(self) -> List[str]:
        """Return list of all production-ready feature columns."""
        return [
            # CVSS features (5)
            'cvss_norm', 'cvss_critical', 'cvss_high', 'cvss_medium', 'cvss_low',
            
            # CWE features (3)
            'cwe_top25', 'cwe_count',
            # Note: cwe_category is categorical, handled separately
            
            # Vendor features (2)
            'is_high_risk_vendor', 'is_healthcare_vendor',
            
            # Description NLP features (5)
            'desc_length_norm', 'has_exploit_keywords_high',
            'has_exploit_keywords_med', 'has_exploit_keywords_low',
            'exploit_keyword_count',
            
            # Temporal features (3)
            'days_since_published', 'recency_score', 'is_recent',
            
            # Healthcare features (4)
            'is_healthcare', 'chpl_flag', 'healthcare_critical', 'chpl_critical',
            
            # ATT&CK features (4)
            'attack_technique_count', 'has_attack', 'attack_multi', 'attack_healthcare',
            
            # Historical risk scores (2)
            'vendor_risk_score', 'cwe_risk_score',
        ]
    
    def get_feature_importance_groups(self) -> Dict[str, List[str]]:
        """Return features grouped by type for ablation studies."""
        return {
            'cvss': ['cvss_norm', 'cvss_critical', 'cvss_high', 'cvss_medium', 'cvss_low'],
            'cwe': ['cwe_top25', 'cwe_count', 'cwe_risk_score'],
            'vendor': ['is_high_risk_vendor', 'is_healthcare_vendor', 'vendor_risk_score'],
            'description': ['desc_length_norm', 'has_exploit_keywords_high', 'has_exploit_keywords_med', 
                           'has_exploit_keywords_low', 'exploit_keyword_count'],
            'temporal': ['days_since_published', 'recency_score', 'is_recent'],
            'healthcare': ['is_healthcare', 'chpl_flag', 'healthcare_critical', 'chpl_critical'],
            'attack': ['attack_technique_count', 'has_attack', 'attack_multi', 'attack_healthcare'],
        }


# Convenience function
def extract_production_features(
    df: pd.DataFrame,
    historical_data: Optional[pd.DataFrame] = None
) -> pd.DataFrame:
    """
    Extract all production features from CVE data.
    
    Args:
        df: CVE data with published, cvss, description, cwe, etc.
        historical_data: Historical data for computing risk scores
    
    Returns:
        DataFrame with production-ready features
    """
    engineer = ProductionFeatureEngineer(historical_data=historical_data)
    return engineer.extract_features(df)
