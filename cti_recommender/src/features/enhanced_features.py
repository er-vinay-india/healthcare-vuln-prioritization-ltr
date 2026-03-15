"""
Enhanced Feature Engineering Module
====================================

This module provides additional feature extraction capabilities to improve
CVE prioritization for healthcare environments.

New feature categories:
1. CVSS Vector Decomposition (8 features)
2. CWE Intelligence (5+ features)
3. ATT&CK Tactical Intelligence (7+ features)
4. CHPL/Healthcare Deep Features (5+ features)
5. Vendor Intelligence (5+ features)
6. Description NLP Features (10+ features)

Author: Enhanced Feature Engineering
Date: 2026-03-08
"""

import re
import pandas as pd
import numpy as np
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict


# ============================================================================
# CONSTANTS AND LOOKUP TABLES
# ============================================================================

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

# CWE Category Mappings
CWE_CATEGORIES = {
    # Injection family
    'injection': {'CWE-79', 'CWE-89', 'CWE-78', 'CWE-77', 'CWE-94', 'CWE-502'},
    # Memory corruption
    'memory': {'CWE-787', 'CWE-416', 'CWE-125', 'CWE-119', 'CWE-190', 'CWE-476'},
    # Authentication/Authorization (mapped to access_control)
    'auth': {'CWE-287', 'CWE-306', 'CWE-862', 'CWE-863', 'CWE-269', 'CWE-798'},
    'access_control': {'CWE-287', 'CWE-306', 'CWE-862', 'CWE-863', 'CWE-269', 'CWE-798'},
    # Path/File handling
    'path': {'CWE-22', 'CWE-434', 'CWE-276'},
    # Web vulnerabilities
    'web': {'CWE-79', 'CWE-352', 'CWE-918'},
    # Input validation
    'input': {'CWE-20', 'CWE-190'},
    'input_validation': {'CWE-20', 'CWE-190'},
    # Cryptographic issues
    'crypto': {'CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-326', 'CWE-310', 'CWE-311', 'CWE-312', 'CWE-313'},
    # Concurrency
    'concurrency': {'CWE-362'}
}

# High-risk vendors (frequent exploitation history)
HIGH_RISK_VENDORS = {
    'microsoft', 'cisco', 'adobe', 'oracle', 'google', 'apple',
    'linux', 'apache', 'mozilla', 'atlassian', 'gitlab', 'jenkins',
    'vmware', 'fortinet', 'palo alto', 'juniper'
}

# Healthcare-specific vendors
HEALTHCARE_VENDORS = {
    'philips', 'ge healthcare', 'ge medical', 'siemens', 'medtronic', 
    'cerner', 'epic', 'allscripts', 'mckesson', 'baxter', 'bd', 
    'becton', 'stryker', 'abbott', 'boston scientific', 'drager', 
    'draeger', 'fresenius', 'hospira', 'smiths medical', 'masimo', 
    'nihon kohden', 'mindray', 'carestream', 'agfa'
}

# Description exploitation keywords (for NLP features)
EXPLOIT_KEYWORDS = {
    'rce': ['remote code execution', 'rce', 'arbitrary code execution', 'execute arbitrary code'],
    'auth_bypass': ['bypass authentication', 'authentication bypass', 'without authentication'],
    'priv_esc': ['privilege escalation', 'escalate privileges', 'elevated privileges'],
    'dos': ['denial of service', 'dos', 'crash', 'resource exhaustion'],
    'info_disclosure': ['information disclosure', 'disclose', 'expose sensitive'],
    'exploit_mentioned': ['exploit', 'proof of concept', 'poc', 'in the wild', 'actively exploited'],
    'weaponization': ['metasploit', 'exploit-db', 'nuclei', 'weaponized']
}

# ATT&CK tactics (MITRE ATT&CK framework)
ATTACK_TACTICS = [
    'reconnaissance', 'resource-development', 'initial-access',
    'execution', 'persistence', 'privilege-escalation',
    'defense-evasion', 'credential-access', 'discovery',
    'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact'
]


# ============================================================================
# 1. CVSS VECTOR DECOMPOSITION FEATURES
# ============================================================================

def parse_cvss_vector(cvss_vector: str) -> Dict[str, float]:
    """
    Parse CVSS v3.x vector string into individual metric features.
    
    Args:
        cvss_vector: CVSS vector string (e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    
    Returns:
        Dict with 8 CVSS dimension features (all numeric, higher = more severe)
    """
    features = {
        'cvss_av': 0.0,  # Attack Vector
        'cvss_ac': 0.0,  # Attack Complexity
        'cvss_pr': 0.0,  # Privileges Required
        'cvss_ui': 0.0,  # User Interaction
        'cvss_s': 0.0,   # Scope
        'cvss_c': 0.0,   # Confidentiality Impact
        'cvss_i': 0.0,   # Integrity Impact
        'cvss_a': 0.0    # Availability Impact
    }
    
    if pd.isna(cvss_vector) or not isinstance(cvss_vector, str):
        return features
    
    # Attack Vector: N=Network(4) > A=Adjacent(3) > L=Local(2) > P=Physical(1)
    if 'AV:N' in cvss_vector:
        features['cvss_av'] = 4.0
    elif 'AV:A' in cvss_vector:
        features['cvss_av'] = 3.0
    elif 'AV:L' in cvss_vector:
        features['cvss_av'] = 2.0
    elif 'AV:P' in cvss_vector:
        features['cvss_av'] = 1.0
    
    # Attack Complexity: L=Low(2) > H=High(1)
    if 'AC:L' in cvss_vector:
        features['cvss_ac'] = 2.0
    elif 'AC:H' in cvss_vector:
        features['cvss_ac'] = 1.0
    
    # Privileges Required: N=None(3) > L=Low(2) > H=High(1)
    if 'PR:N' in cvss_vector:
        features['cvss_pr'] = 3.0
    elif 'PR:L' in cvss_vector:
        features['cvss_pr'] = 2.0
    elif 'PR:H' in cvss_vector:
        features['cvss_pr'] = 1.0
    
    # User Interaction: N=None(2) > R=Required(1)
    if 'UI:N' in cvss_vector:
        features['cvss_ui'] = 2.0
    elif 'UI:R' in cvss_vector:
        features['cvss_ui'] = 1.0
    
    # Scope: C=Changed(2) > U=Unchanged(1)
    if 'S:C' in cvss_vector:
        features['cvss_s'] = 2.0
    elif 'S:U' in cvss_vector:
        features['cvss_s'] = 1.0
    
    # Impact metrics: H=High(3) > L=Low(2) > N=None(1)
    for metric, prefix in [('c', 'C:'), ('i', 'I:'), ('a', 'A:')]:
        if f'{prefix}H' in cvss_vector:
            features[f'cvss_{metric}'] = 3.0
        elif f'{prefix}L' in cvss_vector:
            features[f'cvss_{metric}'] = 2.0
        elif f'{prefix}N' in cvss_vector:
            features[f'cvss_{metric}'] = 1.0
    
    return features


def extract_cvss_decomposition_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract all 10 CVSS vector decomposition features.
    
    Args:
        df: DataFrame with 'cvss_vector' column
    
    Returns:
        DataFrame with 10 new CVSS dimension columns added
    """
    print("Extracting CVSS vector decomposition features...")
    
    # Parse CVSS vectors
    cvss_features = df['cvss_vector'].apply(parse_cvss_vector)
    cvss_df = pd.DataFrame(cvss_features.tolist(), index=df.index)
    
    # Add to original dataframe
    for col in cvss_df.columns:
        df[col] = cvss_df[col]
    
    # Create derived features matching database schema
    # cvss_score_derived: Simplified CVSS score calculation
    df['cvss_score_derived'] = (
        df['cvss_av'] * 0.2 +  # Attack vector weight
        df['cvss_ac'] * 0.1 +  # Complexity weight
        df['cvss_pr'] * 0.15 + # Privileges weight
        df['cvss_ui'] * 0.05 + # User interaction weight
        df['cvss_c'] * 0.2 +   # Confidentiality impact
        df['cvss_i'] * 0.15 +  # Integrity impact
        df['cvss_a'] * 0.15    # Availability impact
    )
    
    # cvss_severity_category: Categorical severity (0=None, 1=Low, 2=Medium, 3=High, 4=Critical)
    def get_severity_category(row):
        total_impact = row['cvss_c'] + row['cvss_i'] + row['cvss_a']
        if total_impact >= 8:
            return 4.0  # Critical
        elif total_impact >= 6:
            return 3.0  # High
        elif total_impact >= 4:
            return 2.0  # Medium
        elif total_impact > 0:
            return 1.0  # Low
        return 0.0  # None
    
    df['cvss_severity_category'] = df.apply(get_severity_category, axis=1)
    
    print(f"  ✓ Added 8 CVSS decomposition features + 2 derived features")
    return df


# ============================================================================
# 2. CWE INTELLIGENCE FEATURES
# ============================================================================

def extract_cwe_id(cwe_string: str) -> Set[str]:
    """Extract CWE IDs from CWE string."""
    if pd.isna(cwe_string) or not isinstance(cwe_string, str):
        return set()
    
    # Extract CWE-XXX patterns
    matches = re.findall(r'CWE-\d+', cwe_string.upper())
    return set(matches)


def extract_cwe_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract CWE intelligence features.
    
    Args:
        df: DataFrame with 'cwe' column
    
    Returns:
        DataFrame with CWE feature columns added
    """
    print("Extracting CWE intelligence features...")
    
    # Extract CWE IDs
    df['cwe_set'] = df['cwe'].apply(extract_cwe_id)
    
    # Feature 1: Is in Top 25
    df['cwe_is_top25'] = df['cwe_set'].apply(
        lambda cwes: 1.0 if any(cwe in CWE_TOP_25 for cwe in cwes) else 0.0
    )
    
    # Feature 2: Is injection vulnerability
    df['cwe_is_injection'] = df['cwe_set'].apply(
        lambda cwes: 1.0 if any(cwe in CWE_CATEGORIES.get('injection', set()) for cwe in cwes) else 0.0
    )
    
    # Feature 3: Is crypto vulnerability
    df['cwe_is_crypto'] = df['cwe_set'].apply(
        lambda cwes: 1.0 if any(cwe in CWE_CATEGORIES.get('crypto', set()) for cwe in cwes) else 0.0
    )
    
    # Feature 4: Is access control vulnerability
    df['cwe_is_access_control'] = df['cwe_set'].apply(
        lambda cwes: 1.0 if any(cwe in CWE_CATEGORIES.get('access_control', set()) for cwe in cwes) else 0.0
    )
    
    # Feature 5: Is input validation vulnerability
    df['cwe_is_input_validation'] = df['cwe_set'].apply(
        lambda cwes: 1.0 if any(cwe in CWE_CATEGORIES.get('input_validation', set()) for cwe in cwes) else 0.0
    )
    
    # Feature 6: Is memory corruption vulnerability
    df['cwe_is_memory_corruption'] = df['cwe_set'].apply(
        lambda cwes: 1.0 if any(cwe in CWE_CATEGORIES.get('memory', set()) for cwe in cwes) else 0.0
    )
    
    # Feature 7: CWE category (categorical)
    def get_cwe_category(cwes):
        if not cwes:
            return 0.0
        for category_name, category_cwes in CWE_CATEGORIES.items():
            if any(cwe in category_cwes for cwe in cwes):
                return hash(category_name) % 100  # Simple categorical encoding
        return 0.0
    
    df['cwe_category'] = df['cwe_set'].apply(get_cwe_category)
    
    # Feature 8: CWE severity score (based on category)
    def calc_cwe_severity(cwes):
        if not cwes:
            return 0.0
        scores = []
        for cwe in cwes:
            if cwe in CWE_TOP_25:
                scores.append(3.0)
            elif any(cwe in cats for cats in CWE_CATEGORIES.values()):
                scores.append(2.0)
            else:
                scores.append(1.0)
        return max(scores) if scores else 0.0
    
    df['cwe_severity_score'] = df['cwe_set'].apply(calc_cwe_severity)
    
    # Clean up temporary column
    df.drop(columns=['cwe_set'], inplace=True)
    
    print(f"  ✓ Added 8 CWE intelligence features")
    return df


# ============================================================================
# Feature extraction wrapper
# ============================================================================

def extract_all_enhanced_features(df: pd.DataFrame, include_nlp: bool = True) -> pd.DataFrame:
    """
    Extract all enhanced features.
    
    Args:
        df: DataFrame with raw CVE data
        include_nlp: Whether to extract NLP features (requires 'description' column)
    
    Returns:
        DataFrame with all enhanced features added
    """
    print("\n" + "="*80)
    print("ENHANCED FEATURE EXTRACTION")
    print("="*80)
    
    # Track initial state
    initial_cols = len(df.columns)
    
    # Phase 1: CVSS decomposition (10 features)
    df = extract_cvss_decomposition_features(df)
    
    # Phase 2: CWE intelligence (8 features)
    df = extract_cwe_features(df)
    
    # Phase 3: Description NLP (10 features)
    if include_nlp:
        df = extract_description_nlp_features(df)
    
    # Phase 4: Vendor intelligence (3 features)
    df = extract_vendor_features(df)
    
    # Phase 5: Interaction features (6 features)
    df = extract_interaction_features(df)
    
    # Summary
    new_cols = len(df.columns) - initial_cols
    print(f"\n  Total new features added: {new_cols}")
    print("="*80)
    
    return df
    print(f"\n  Total new features added: {new_cols}")
    print("="*80)
    
    return df


# ============================================================================
# 3. DESCRIPTION NLP FEATURES
# ============================================================================

def extract_description_nlp_features(df: pd.DataFrame, description_col: str = 'description') -> pd.DataFrame:
    """
    Extract NLP features from CVE descriptions.
    
    Args:
        df: DataFrame with description column
        description_col: Name of description column
    
    Returns:
        DataFrame with NLP feature columns added
    """
    print("Extracting description NLP features...")
    
    # Helper function to check keywords
    def has_keywords(text: str, keywords: List[str]) -> float:
        if pd.isna(text) or not isinstance(text, str):
            return 0.0
        text_lower = text.lower()
        return 1.0 if any(kw in text_lower for kw in keywords) else 0.0
    
    # Check if description column exists
    if description_col not in df.columns:
        print(f"  ⚠ Warning: '{description_col}' column not found, skipping NLP features")
        # Add zero columns
        for category in ['rce', 'auth_bypass', 'priv_esc', 'dos', 'info_disclosure', 'exploit_mentioned']:
            df[f'desc_has_{category}'] = 0.0
        df['desc_keyword_density'] = 0.0
        df['desc_exploitation_score'] = 0.0
        df['desc_length'] = 0.0
        df['desc_complexity'] = 0.0
        return df
    
    # Match database schema: 10 specific NLP features
    # desc_has_rce, desc_has_auth_bypass, desc_has_priv_esc (already from EXPLOIT_KEYWORDS)
    df['desc_has_rce'] = df[description_col].apply(lambda x: has_keywords(x, EXPLOIT_KEYWORDS.get('rce', [])))
    df['desc_has_auth_bypass'] = df[description_col].apply(lambda x: has_keywords(x, EXPLOIT_KEYWORDS.get('auth_bypass', [])))
    df['desc_has_priv_esc'] = df[description_col].apply(lambda x: has_keywords(x, EXPLOIT_KEYWORDS.get('priv_esc', [])))
    
    # Additional NLP features matching database schema
    sqli_keywords = ['sql injection', 'sqli', 'sql query', 'union select']
    df['desc_has_sqli'] = df[description_col].apply(lambda x: has_keywords(x, sqli_keywords))
    
    xss_keywords = ['cross-site scripting', 'xss', 'script injection']
    df['desc_has_xss'] = df[description_col].apply(lambda x: has_keywords(x, xss_keywords))
    
    df['desc_has_dos'] = df[description_col].apply(lambda x: has_keywords(x, EXPLOIT_KEYWORDS.get('dos', [])))
    
    buffer_keywords = ['buffer overflow', 'buffer overrun', 'heap overflow', 'stack overflow']
    df['desc_has_buffer_overflow'] = df[description_col].apply(lambda x: has_keywords(x, buffer_keywords))
    
    path_keywords = ['path traversal', 'directory traversal', '../', 'dot dot']
    df['desc_has_path_traversal'] = df[description_col].apply(lambda x: has_keywords(x, path_keywords))
    
    csrf_keywords = ['csrf', 'cross-site request forgery', 'xsrf']
    df['desc_has_csrf'] = df[description_col].apply(lambda x: has_keywords(x, csrf_keywords))
    
    xxe_keywords = ['xxe', 'xml external entity', 'xml injection']
    df['desc_has_xxe'] = df[description_col].apply(lambda x: has_keywords(x, xxe_keywords))
    
    print(f"  ✓ Added 10 description NLP features")
    return df


# ============================================================================
# 4. VENDOR INTELLIGENCE FEATURES
# ============================================================================

def extract_vendor_from_cve(cve_id: str, description: str = None) -> str:
    """
    Extract vendor name from CVE ID or description.
    Very basic extraction - can be enhanced.
    """
    # For now, just return empty string - vendor extraction is complex
    # and would require CPE parsing which we don't have in the features CSV
    return ''


def extract_vendor_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract vendor intelligence features.
    
    Args:
        df: DataFrame with CVE data
    
    Returns:
        DataFrame with vendor feature columns added
    """
    print("Extracting vendor intelligence features...")
    
    # Since we don't have vendor data in the features CSV,
    # we'll create placeholder features based on description patterns
    
    def check_vendor_mention(text: str, vendors: Set[str]) -> float:
        if pd.isna(text) or not isinstance(text, str):
            return 0.0
        text_lower = text.lower()
        return 1.0 if any(v in text_lower for v in vendors) else 0.0
    
    # Check for high-risk vendor mentions in description (if available)
    if 'description' in df.columns:
        df['vendor_is_high_risk'] = df['description'].apply(
            lambda x: check_vendor_mention(x, HIGH_RISK_VENDORS)
        )
        df['vendor_is_healthcare'] = df['description'].apply(
            lambda x: check_vendor_mention(x, HEALTHCARE_VENDORS)
        )
    else:
        df['vendor_is_high_risk'] = 0.0
        df['vendor_is_healthcare'] = 0.0
    
    # Create vendor risk score (can be enhanced with historical data)
    df['vendor_risk_score'] = (
        df['vendor_is_high_risk'] * 2.0 +
        df['vendor_is_healthcare'] * 1.5
    ) / 3.5
    
    print(f"  ✓ Added 3 vendor intelligence features")
    return df


# ============================================================================
# 5. ENHANCED INTERACTION FEATURES
# ============================================================================

def extract_interaction_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Create enhanced interaction features between different dimensions.
    
    Args:
        df: DataFrame with base features
    
    Returns:
        DataFrame with interaction feature columns added
    """
    print("Extracting enhanced interaction features...")
    
    # Match database schema: 6 interaction features
    # ultimate_risk: Network + No Auth + High Impact
    if all(c in df.columns for c in ['cvss_av', 'cvss_pr', 'cvss_c', 'cvss_i', 'cvss_a']):
        df['ultimate_risk'] = (
            (df['cvss_av'] == 4.0).astype(float) *  # Network accessible
            (df['cvss_pr'] == 3.0).astype(float) *  # No privileges required
            ((df['cvss_c'] + df['cvss_i'] + df['cvss_a']) / 3.0)  # High impact
        )
    else:
        df['ultimate_risk'] = 0.0
    
    # critical_exploitable: High CVSS + Exploit mentioned
    if all(c in df.columns for c in ['cvss_c', 'cvss_i', 'cvss_a', 'desc_has_rce']):
        high_impact = ((df['cvss_c'] + df['cvss_i'] + df['cvss_a']) >= 7.0).astype(float)
        df['critical_exploitable'] = high_impact * df['desc_has_rce']
    else:
        df['critical_exploitable'] = 0.0
    
    # network_accessible: Network attack vector
    if 'cvss_av' in df.columns:
        df['network_accessible'] = (df['cvss_av'] == 4.0).astype(float)
    else:
        df['network_accessible'] = 0.0
    
    # auth_not_required: No privileges required
    if 'cvss_pr' in df.columns:
        df['auth_not_required'] = (df['cvss_pr'] == 3.0).astype(float)
    else:
        df['auth_not_required'] = 0.0
    
#    # high_impact_network: Network + High impact
    if all(c in df.columns for c in ['cvss_av', 'cvss_c', 'cvss_i', 'cvss_a']):
        high_impact = ((df['cvss_c'] + df['cvss_i'] + df['cvss_a']) >= 7.0).astype(float)
        df['high_impact_network'] = (df['cvss_av'] == 4.0).astype(float) * high_impact
    else:
        df['high_impact_network'] = 0.0
    
    # healthcare_critical: Healthcare device + Critical vulnerability
    if all(c in df.columns for c in ['is_healthcare', 'cvss_c', 'cvss_i', 'cvss_a']):
        high_impact = ((df['cvss_c'] + df['cvss_i'] + df['cvss_a']) >= 7.0).astype(float)
        df['healthcare_critical'] = df.get('is_healthcare', 0.0) * high_impact
    else:
        df['healthcare_critical'] = 0.0
    
    print(f"  ✓ Added 6 interaction features")
    return df


# ============================================================================
# Feature extraction wrapper (UPDATED)
# ============================================================================

def extract_all_enhanced_features(df: pd.DataFrame, include_nlp: bool = True) -> pd.DataFrame:
    """
    Extract all enhanced features.
    
    Args:
        df: DataFrame with raw CVE data
        include_nlp: Whether to extract NLP features (requires 'description' column)
    
    Returns:
        DataFrame with all enhanced features added
    """
    print("\n" + "="*80)
    print("ENHANCED FEATURE EXTRACTION")
    print("="*80)
    
    # Track initial state
    initial_cols = len(df.columns)
    
    # Phase 1: CVSS decomposition
    df = extract_cvss_decomposition_features(df)
    
    # Phase 2: CWE intelligence
    df = extract_cwe_features(df)
    
    # Phase 3: Description NLP (if available)
    if include_nlp:
        df = extract_description_nlp_features(df)
    
    # Phase 4: Vendor intelligence
    df = extract_vendor_features(df)
    
    # Phase 5: Interaction features
    df = extract_interaction_features(df)
    
    # Summary
    new_cols = len(df.columns) - initial_cols
    print(f"\n  Total new features added: {new_cols}")
    print("="*80)
    
    return df


def get_enhanced_feature_columns() -> List[str]:
    """Return list of all enhanced feature column names (matching database schema)."""
    return [
        # CVSS decomposition (10)
        'cvss_av', 'cvss_ac', 'cvss_pr', 'cvss_ui', 'cvss_s',
        'cvss_c', 'cvss_i', 'cvss_a',
        'cvss_score_derived', 'cvss_severity_category',
        
        # CWE intelligence (8)
        'cwe_is_top25', 'cwe_is_injection', 'cwe_is_crypto',
        'cwe_is_access_control', 'cwe_is_input_validation',
        'cwe_is_memory_corruption', 'cwe_category', 'cwe_severity_score',
        
        # Description NLP (10)
        'desc_has_rce', 'desc_has_auth_bypass', 'desc_has_priv_esc',
        'desc_has_sqli', 'desc_has_xss', 'desc_has_dos',
        'desc_has_buffer_overflow', 'desc_has_path_traversal',
        'desc_has_csrf', 'desc_has_xxe',
        
        # Vendor intelligence (3)
        'vendor_is_high_risk', 'vendor_is_healthcare', 'vendor_risk_score',
        
        # Interaction features (6)
        'ultimate_risk', 'critical_exploitable', 'network_accessible',
        'auth_not_required', 'high_impact_network', 'healthcare_critical',
    ]


# ============================================================================
# Enhanced Feature Extractor Class (Notebook Interface)
# ============================================================================

class EnhancedFeatureExtractor:
    """
    Object-oriented wrapper for enhanced feature extraction functions.
    
    This class provides the interface expected by STEP_3_Compute_Features.ipynb
    and wraps all the functional implementations above.
    
    Usage:
        extractor = EnhancedFeatureExtractor()
        enhanced_df = extractor.extract_all_features(df)
    """
    
    def __init__(self):
        """Initialize the feature extractor."""
        print("[OK] EnhancedFeatureExtractor initialized")
        print("  - CVSS decomposition: ready")
        print("  - CWE intelligence: ready")
        print("  - Description NLP: ready")
        print("  - Vendor intelligence: ready")
        print("  - Interaction features: ready")
    
    def extract_all_features(self, df: pd.DataFrame, include_nlp: bool = True) -> pd.DataFrame:
        """
        Extract all enhanced features from a DataFrame of CVE data.
        
        This is the main entry point that notebooks should use.
        
        Args:
            df: DataFrame with CVE data (must have cvss_vector, cwe, description columns)
            include_nlp: Whether to extract NLP features (default True)
        
        Returns:
            DataFrame with all enhanced features added
        """
        return extract_all_enhanced_features(df, include_nlp=include_nlp)
    
    def get_feature_columns(self) -> List[str]:
        """Get list of all feature column names that will be created."""
        return get_enhanced_feature_columns()
