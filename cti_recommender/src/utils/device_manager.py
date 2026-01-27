"""
Cross-platform GPU Device Manager
Automatically detects and configures the best available compute device:
- Apple Silicon (MPS): M1, M2, M3, M4, M5 chips
- NVIDIA (CUDA): GPU with CUDA support
- AMD (ROCm): GPU with ROCm support
- CPU: Fallback for systems without GPU
"""

import torch
import logging
from typing import Literal, Optional

logger = logging.getLogger(__name__)

DeviceType = Literal["mps", "cuda", "cpu"]


class DeviceManager:
    """Manages compute device selection and configuration across platforms."""
    
    def __init__(self, prefer_device: Optional[DeviceType] = None):
        """
        Initialize device manager.
        
        Args:
            prefer_device: Preferred device type. If None, auto-selects best available.
        """
        self.device = self._get_device(prefer_device)
        self.device_type = self.device.type
        self._log_device_info()
    
    def _get_device(self, prefer_device: Optional[DeviceType] = None) -> torch.device:
        """
        Determine the best available device.
        
        Args:
            prefer_device: Preferred device type (mps, cuda, cpu)
            
        Returns:
            torch.device object
        """
        if prefer_device == "cpu":
            return torch.device("cpu")
        
        # Check for Apple Silicon MPS
        if prefer_device == "mps" or (prefer_device is None and torch.backends.mps.is_available()):
            if torch.backends.mps.is_built():
                return torch.device("mps")
            else:
                logger.warning("MPS requested but not built. Falling back to CPU.")
        
        # Check for NVIDIA CUDA
        if prefer_device == "cuda" or (prefer_device is None and torch.cuda.is_available()):
            return torch.device("cuda")
        
        # Fallback to CPU
        return torch.device("cpu")
    
    def _log_device_info(self):
        """Log device information."""
        if self.device_type == "mps":
            logger.info("✓ Using Apple Silicon GPU (MPS) for acceleration")
            logger.info("  - Metal Performance Shaders enabled")
            logger.info("  - Unified memory architecture")
        elif self.device_type == "cuda":
            gpu_name = torch.cuda.get_device_name(0)
            gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1e9
            logger.info(f"✓ Using NVIDIA GPU (CUDA) for acceleration")
            logger.info(f"  - GPU: {gpu_name}")
            logger.info(f"  - Memory: {gpu_memory:.1f} GB")
        else:
            logger.info("⚠ Using CPU (no GPU acceleration)")
            logger.info("  - Consider using a system with GPU for faster training")
    
    def to_device(self, *tensors_or_models):
        """
        Move tensors or models to the configured device.
        
        Args:
            *tensors_or_models: PyTorch tensors or models
            
        Returns:
            Tuple of moved objects (or single object if only one input)
        """
        moved = [obj.to(self.device) for obj in tensors_or_models]
        return moved[0] if len(moved) == 1 else tuple(moved)
    
    def synchronize(self):
        """Synchronize device operations (wait for all kernels to finish)."""
        if self.device_type == "mps":
            torch.mps.synchronize()
        elif self.device_type == "cuda":
            torch.cuda.synchronize()
    
    def empty_cache(self):
        """Clear GPU memory cache."""
        if self.device_type == "mps":
            torch.mps.empty_cache()
        elif self.device_type == "cuda":
            torch.cuda.empty_cache()
    
    def get_memory_info(self) -> dict:
        """
        Get memory usage information.
        
        Returns:
            Dictionary with memory statistics
        """
        if self.device_type == "cuda":
            return {
                "allocated": torch.cuda.memory_allocated() / 1e9,
                "reserved": torch.cuda.memory_reserved() / 1e9,
                "max_allocated": torch.cuda.max_memory_allocated() / 1e9,
            }
        else:
            # MPS and CPU don't have direct memory tracking
            return {"info": "Memory tracking not available for this device"}
    
    def __repr__(self):
        return f"DeviceManager(device={self.device})"


# Global device manager instance
_global_device_manager: Optional[DeviceManager] = None


def get_device_manager(prefer_device: Optional[DeviceType] = None) -> DeviceManager:
    """
    Get or create the global device manager.
    
    Args:
        prefer_device: Preferred device type (mps, cuda, cpu)
        
    Returns:
        DeviceManager instance
    """
    global _global_device_manager
    if _global_device_manager is None:
        _global_device_manager = DeviceManager(prefer_device)
    return _global_device_manager


def get_device(prefer_device: Optional[DeviceType] = None) -> torch.device:
    """
    Convenience function to get the torch device directly.
    
    Args:
        prefer_device: Preferred device type (mps, cuda, cpu)
        
    Returns:
        torch.device object
    """
    return get_device_manager(prefer_device).device


# Quick test function
def test_device():
    """Test device detection and basic operations."""
    print("=" * 60)
    print("Device Detection Test")
    print("=" * 60)
    
    dm = get_device_manager()
    print(f"\nDetected device: {dm.device}")
    print(f"Device type: {dm.device_type}")
    
    # Test tensor operations
    print("\nTesting tensor operations...")
    x = torch.randn(100, 100)
    y = torch.randn(100, 100)
    
    x, y = dm.to_device(x, y)
    
    import time
    start = time.time()
    for _ in range(100):
        z = x @ y
    dm.synchronize()
    elapsed = time.time() - start
    
    print(f"✓ 100 matrix multiplications completed in {elapsed:.4f}s")
    print(f"  Average: {elapsed/100*1000:.2f}ms per operation")
    
    if dm.device_type in ["mps", "cuda"]:
        print("\n✓ GPU acceleration is working!")
    else:
        print("\n⚠ Running on CPU (no GPU acceleration)")
    
    print("=" * 60)


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Run test
    test_device()
