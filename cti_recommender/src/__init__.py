"""CTI Healthcare Vulnerability Recommender System

A multi-source vulnerability scoring and ranking system for healthcare organizations.
Integrates NVD, CISA KEV, MITRE ATT&CK, and CHPL data sources.
"""

__version__ = "1.0.0"
__author__ = "CTI Recommender Team"

# Lazy imports to avoid loading heavy dependencies when not needed
__all__ = [
    'cti_recommender',
    'ltr',
    'data_quality',
    'healthcare_mapping',
]


def __getattr__(name):
    """Lazy load modules on demand"""
    if name == 'cti_recommender':
        from src.core import cti_recommender
        return cti_recommender
    elif name == 'ltr':
        from src.core import ltr
        return ltr
    elif name == 'data_quality':
        from src.analysis import data_quality
        return data_quality
    elif name == 'healthcare_mapping':
        from src.analysis import healthcare_mapping
        return healthcare_mapping
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
