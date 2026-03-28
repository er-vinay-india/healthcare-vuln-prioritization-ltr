"""
Centralized Experiment Configuration
====================================
Production-grade ML configuration with YAML files.
Version-controllable, reproducible, type-validated.

Directory Structure:
    config/
    ├── experiments/
    │   ├── default.yaml      # Base config (inherited by all)
    │   ├── debug.yaml        # Fast iteration (small samples)
    │   └── production.yaml   # Full data (deployment)
    └── experiment_config.py  # This file (loader + validation)

Usage in notebooks:
    from config.experiment_config import cfg
    
    # Default loads based on EXPERIMENT_PROFILE env var (or 'production')
    print(cfg.rgcn.hidden_channels)
    print(cfg.sampling.graph_sample_size)
    
    # Switch profiles
    from config.experiment_config import load_config
    cfg = load_config('debug')  # Fast iteration

Usage in scripts:
    from config.experiment_config import load_config
    cfg = load_config('production')
    cfg.print_summary()
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from pathlib import Path
import os
import yaml
from dotenv import load_dotenv

# Load .env for secrets only (API keys, etc.)
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    load_dotenv(env_path)


# ==========================================================
# CONFIG DATA CLASSES (Type-safe, validated)
# ==========================================================

@dataclass
class ExperimentMeta:
    """Experiment metadata."""
    name: str = "cve_prioritization"
    version: str = "1.0.0"
    description: str = ""


@dataclass
class FeatureEngineeringConfig:
    """Feature engineering configuration."""
    audit: bool = True          # Enable missingness auditing
    plot: bool = True           # Show visualization plots
    plot_top_missing: int = 25  # Top N columns for missingness bar chart
    reference_date: str = "2025-01-01"  # Reference date for temporal features
    cvss_missing_fill: float = 5.0      # Fill value for missing CVSS (0-10)
    epss_missing_fill: float = 0.0      # Fill value for missing EPSS (0-1)


@dataclass
class DataConfig:
    """Data loading and feature configuration."""
    min_cve_date: str = "2024-01-01"
    train_test_split_date: str = "2024-11-01"
    feature_cols: List[str] = field(default_factory=lambda: [
        'cvss_norm', 'epss_score', 'epss_percentile', 'kev_flag',
        'days_since_published', 'recency_score', 'attack_technique_count', 'has_attack',
        'chpl_flag', 'is_healthcare', 'cvss_epss_product', 'kev_healthcare_interaction'
    ])
    similarity_features: List[str] = field(default_factory=lambda: [
        'cvss', 'epss_score', 'kev_flag', 'is_healthcare', 'attack_technique_count'
    ])


@dataclass
class SamplingConfig:
    """Data sampling configuration. None = use all data."""
    graph_sample_size: Optional[int] = None
    rgcn_sample_size: Optional[int] = None
    test_sample_size: Optional[int] = None


@dataclass
class TemporalSplitsConfig:
    """Temporal splitting configuration supporting multiple strategies."""
    strategy: str = 'date'  # 'date' | 'percentage' | 'year_based'
    
    # Date-based split
    date_split: Dict[str, Any] = field(default_factory=lambda: {
        'split_date': '2024-11-01',
        'validation_weeks': 12
    })
    
    # Percentage-based split
    percentage_split: Dict[str, Any] = field(default_factory=lambda: {
        'train': 0.70,
        'val': 0.15,
        'test': 0.15,
        'shuffle': False
    })
    
    # Year-based split
    year_split: Dict[str, Any] = field(default_factory=lambda: {
        'train_years': [2018, 2019, 2020, 2021, 2022, 2023, 2024],
        'test_years': [2025],
        'validation_weeks': 12
    })


@dataclass
class RGCNConfig:
    """RGCN model hyperparameters."""
    hidden_channels: int = 64
    num_layers: int = 2
    dropout: float = 0.3
    learning_rate: float = 0.01
    epochs: int = 100
    early_stopping_patience: int = 5
    max_neighbors: int = 3
    # Mini-batch training (critical for scalability!)
    use_minibatch: bool = True  # Auto-enables for >5K nodes
    batch_size: int = 1024      # Nodes per mini-batch
    num_neighbors: List[int] = field(default_factory=lambda: [15, 10])  # Per layer


@dataclass
class DiffusionConfig:
    """DiffusionRank algorithm parameters."""
    alpha: float = 0.85
    max_iter: int = 100
    tolerance: float = 1e-6


@dataclass
class SimilarityConfig:
    """Similarity graph construction parameters."""
    k_neighbors: int = 10
    threshold: float = 0.7


@dataclass
class EvaluationConfig:
    """Evaluation metrics configuration."""
    k_values: List[int] = field(default_factory=lambda: [10, 20, 50, 100])
    precision_threshold: int = 3


@dataclass
class ModelsConfig:
    """Model file paths."""
    baseline_path: str = "models/ltr_model_conf_weighted.pkl"
    rgcn_path: str = "models/rgcn_model.pt"
    ensemble_path: str = "models/ensemble_model.pkl"


@dataclass
class OutputConfig:
    """Output configuration."""
    dir: str = "outputs"
    save_predictions: bool = True
    save_plots: bool = True


@dataclass
class DeviceConfig:
    """Compute device configuration."""
    training: str = "auto"  # auto | cpu | cuda | mps
    inference: str = "cpu"
    force_cpu: bool = False


@dataclass
class ExperimentConfig:
    """
    Main configuration class.
    Aggregates all sub-configs with full type safety.
    """
    experiment: ExperimentMeta = field(default_factory=ExperimentMeta)
    data: DataConfig = field(default_factory=DataConfig)
    feature_engineering: FeatureEngineeringConfig = field(default_factory=FeatureEngineeringConfig)
    sampling: SamplingConfig = field(default_factory=SamplingConfig)
    temporal_splits: TemporalSplitsConfig = field(default_factory=TemporalSplitsConfig)
    rgcn: RGCNConfig = field(default_factory=RGCNConfig)
    diffusion: DiffusionConfig = field(default_factory=DiffusionConfig)
    similarity: SimilarityConfig = field(default_factory=SimilarityConfig)
    evaluation: EvaluationConfig = field(default_factory=EvaluationConfig)
    models: ModelsConfig = field(default_factory=ModelsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    device: DeviceConfig = field(default_factory=DeviceConfig)
    
    # Internal tracking
    _profile: str = "default"
    _project_root: Path = field(default_factory=lambda: Path(__file__).parent.parent)
    
    # ==========================================================
    # CONVENIENCE PROPERTIES (backward compatibility)
    # ==========================================================
    
    @property
    def debug_mode(self) -> bool:
        """True if running in debug profile."""
        return self._profile == 'debug'
    
    @property
    def project_root(self) -> Path:
        return self._project_root
    
    @property
    def database_path(self) -> Path:
        try:
            from config.settings import settings
            return settings.get_database_path()
        except Exception:
            return self._project_root / "data/cve_database.db"
    
    @property
    def model_path(self) -> Path:
        return self._project_root / self.models.baseline_path
    
    @property
    def output_dir(self) -> Path:
        return self._project_root / self.output.dir
    
    # Flat access for common params (backward compat)
    @property
    def graph_sample_size(self) -> Optional[int]:
        return self.sampling.graph_sample_size
    
    @property
    def rgcn_sample_size(self) -> Optional[int]:
        return self.sampling.rgcn_sample_size
    
    @property
    def test_sample_size(self) -> Optional[int]:
        return self.sampling.test_sample_size
    
    @property
    def rgcn_hidden_channels(self) -> int:
        return self.rgcn.hidden_channels
    
    @property
    def rgcn_epochs(self) -> int:
        return self.rgcn.epochs
    
    @property
    def feature_cols(self) -> List[str]:
        return self.data.feature_cols
    
    @property
    def k_values(self) -> List[int]:
        return self.evaluation.k_values
    
    @property
    def training_device(self) -> str:
        """Get actual training device (resolves 'auto')."""
        if self.device.force_cpu:
            return 'cpu'
        if self.device.training == 'auto':
            import torch
            if torch.backends.mps.is_available():
                return 'mps'
            if torch.cuda.is_available():
                return 'cuda'
            return 'cpu'
        return self.device.training
    
    @property
    def inference_device(self) -> str:
        return self.device.inference
    
    # ==========================================================
    # UTILITY METHODS
    # ==========================================================
    
    def get_sample_size(self, full_size: int, param_name: str = 'default') -> int:
        """
        Get effective sample size.
        
        Args:
            full_size: Full dataset size
            param_name: Which parameter ('graph', 'rgcn', 'test')
        
        Returns:
            Sample size to use (full_size if None configured)
        """
        sample_map = {
            'graph': self.sampling.graph_sample_size,
            'rgcn': self.sampling.rgcn_sample_size,
            'test': self.sampling.test_sample_size,
            'default': self.sampling.rgcn_sample_size
        }
        sample_size = sample_map.get(param_name, self.sampling.rgcn_sample_size)
        return sample_size if sample_size else full_size
    
    def to_dict(self, include_device: bool = False) -> Dict[str, Any]:
        """Convert config to flat dictionary."""
        result = {
            'profile': self._profile,
            'experiment_name': self.experiment.name,
            'debug_mode': self.debug_mode,
            'graph_sample_size': self.sampling.graph_sample_size or 'ALL',
            'rgcn_sample_size': self.sampling.rgcn_sample_size or 'ALL',
            'test_sample_size': self.sampling.test_sample_size or 'ALL',
            'rgcn_hidden_channels': self.rgcn.hidden_channels,
            'rgcn_epochs': self.rgcn.epochs,
            'rgcn_num_layers': self.rgcn.num_layers,
            'rgcn_dropout': self.rgcn.dropout,
            'rgcn_learning_rate': self.rgcn.learning_rate,
            'rgcn_max_neighbors': self.rgcn.max_neighbors,
            'diffusion_alpha': self.diffusion.alpha,
            'similarity_k_neighbors': self.similarity.k_neighbors,
            'similarity_threshold': self.similarity.threshold,
            'k_values': self.evaluation.k_values,
            'database_path': str(self.database_path),
        }
        # Only compute device if requested (avoids torch import)
        if include_device:
            result['training_device'] = self.training_device
            result['inference_device'] = self.inference_device
        else:
            result['training_device'] = self.device.training
            result['inference_device'] = self.device.inference
        return result
    
    def print_summary(self):
        """Print configuration summary."""
        mode = "DEBUG" if self.debug_mode else "PRODUCTION"
        print("=" * 65)
        print(f"EXPERIMENT CONFIG: {self.experiment.name} [{mode}]")
        print("=" * 65)
        for key, value in self.to_dict().items():
            print(f"  {key:30s}: {value}")
        print("=" * 65)


# ==========================================================
# YAML LOADING FUNCTIONS
# ==========================================================

def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f) or {}


def _merge_dicts(base: Dict, override: Dict) -> Dict:
    """Deep merge two dicts, override takes precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge_dicts(result[key], value)
        else:
            result[key] = value
    return result


def _dict_to_config(data: Dict[str, Any], profile: str) -> ExperimentConfig:
    """Convert dictionary to ExperimentConfig with validation."""
    cfg = ExperimentConfig()
    cfg._profile = profile
    
    # Map dict sections to dataclasses
    if 'experiment' in data:
        cfg.experiment = ExperimentMeta(**data['experiment'])
    if 'data' in data:
        cfg.data = DataConfig(**data['data'])
    if 'feature_engineering' in data:
        cfg.feature_engineering = FeatureEngineeringConfig(**data['feature_engineering'])
    if 'sampling' in data:
        cfg.sampling = SamplingConfig(**data['sampling'])
    if 'temporal_splits' in data:
        cfg.temporal_splits = TemporalSplitsConfig(**data['temporal_splits'])
    if 'rgcn' in data:
        cfg.rgcn = RGCNConfig(**data['rgcn'])
    if 'diffusion' in data:
        cfg.diffusion = DiffusionConfig(**data['diffusion'])
    if 'similarity' in data:
        cfg.similarity = SimilarityConfig(**data['similarity'])
    if 'evaluation' in data:
        cfg.evaluation = EvaluationConfig(**data['evaluation'])
    if 'models' in data:
        cfg.models = ModelsConfig(**data['models'])
    if 'output' in data:
        cfg.output = OutputConfig(**data['output'])
    if 'device' in data:
        cfg.device = DeviceConfig(**data['device'])
    
    return cfg


def load_config(profile: str = None) -> ExperimentConfig:
    """
    Load experiment configuration from YAML.
    
    Args:
        profile: Config profile name ('debug', 'production', or custom)
                 If None, uses EXPERIMENT_PROFILE env var or 'production'
    
    Returns:
        ExperimentConfig instance
    
    Example:
        cfg = load_config('debug')  # Fast iteration
        cfg = load_config('production')  # Full data
    """
    if profile is None:
        profile = os.getenv('EXPERIMENT_PROFILE', 'production')
    
    config_dir = Path(__file__).parent / 'experiments'
    
    # Load base config
    default_path = config_dir / 'default.yaml'
    if not default_path.exists():
        raise FileNotFoundError(f"Default config not found: {default_path}")
    
    config_data = _load_yaml(default_path)
    
    # Load and merge profile config
    if profile != 'default':
        profile_path = config_dir / f'{profile}.yaml'
        if profile_path.exists():
            profile_data = _load_yaml(profile_path)
            # Remove _inherit key if present
            profile_data.pop('_inherit', None)
            config_data = _merge_dicts(config_data, profile_data)
        else:
            print(f"Warning: Profile '{profile}' not found, using default")
    
    return _dict_to_config(config_data, profile)


# ==========================================================
# GLOBAL CONFIG INSTANCE
# ==========================================================

# Load default profile on import
_default_profile = os.getenv('EXPERIMENT_PROFILE', 'production')
cfg = load_config(_default_profile)


def get_config() -> ExperimentConfig:
    """Get the global config instance."""
    return cfg


def set_profile(profile: str):
    """
    Switch to a different config profile.
    
    Args:
        profile: 'debug', 'production', or custom profile name
    """
    global cfg
    cfg = load_config(profile)


# ==========================================================
# BACKWARD COMPATIBILITY EXPORTS
# ==========================================================
# These are computed at import time for simple usage
DEBUG_MODE = cfg.debug_mode
GRAPH_SAMPLE_SIZE = cfg.graph_sample_size
RGCN_SAMPLE_SIZE = cfg.rgcn_sample_size
TEST_SAMPLE_SIZE = cfg.test_sample_size
RGCN_HIDDEN_CHANNELS = cfg.rgcn_hidden_channels
RGCN_EPOCHS = cfg.rgcn_epochs


if __name__ == '__main__':
    # Print config when run directly
    print("\n--- Default Profile ---")
    load_config('production').print_summary()
    
    print("\n--- Debug Profile ---")
    load_config('debug').print_summary()
