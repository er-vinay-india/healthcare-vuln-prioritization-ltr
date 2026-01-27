"""
Configuration Management Module

This module handles configuration loading and management for experiments.
"""

from typing import Any, Dict, List, Optional
import json
import yaml
from pathlib import Path


def load_config(config_path: str) -> Dict:
    """
    Load configuration from YAML or JSON file.
    
    Args:
        config_path: Path to config file
    
    Returns:
        Dict with configuration
    """
    # TODO: Implement config loading
    # - Detect file type (.yaml, .json)
    # - Load and parse
    # - Return config dict
    raise NotImplementedError("To be implemented")


def save_config(config: Dict, output_path: str) -> None:
    """
    Save configuration to file.
    
    Args:
        config: Configuration dict
        output_path: Output file path
    """
    # TODO: Implement config saving
    raise NotImplementedError("To be implemented")


def get_feature_cols(config: Optional[Dict] = None) -> List[str]:
    """
    Get list of feature columns from config or use defaults.
    
    Args:
        config: Optional config dict
    
    Returns:
        List of feature column names
    """
    # TODO: Implement feature column retrieval
    # - Load from config if available
    # - Otherwise use default list
    if config and 'feature_cols' in config:
        return config['feature_cols']
    
    # Default feature columns
    return [
        'cvss_base_score',
        'cvss_exploitability_subscore',
        'cvss_impact_subscore',
        'epss_score',
        'epss_percentile',
        'kev_flag',
        'attack_technique_count',
        'chpl_healthcare_flag',
        'healthcare_breach_flag',
        'cve_age_days',
        'cvss_epss_interaction',
        'kev_healthcare_interaction',
    ]


def merge_configs(base_config: Dict, override_config: Dict) -> Dict:
    """
    Merge two configuration dicts (override takes precedence).
    
    Args:
        base_config: Base configuration
        override_config: Override configuration
    
    Returns:
        Merged configuration dict
    """
    # TODO: Implement deep merge
    raise NotImplementedError("To be implemented")
