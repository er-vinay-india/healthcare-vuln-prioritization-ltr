"""
Relational Graph Convolutional Network (RGCN) for CVE Prioritization

This module implements an RGCN model to capture CVE-to-CWE relationships
and prioritize vulnerabilities based on graph structure and node features.

Architecture:
- Input: CVE node features + CVE-CWE bipartite graph
- RGCN layers: Learn node embeddings using typed edges
- Output: Priority scores for each CVE

Optimizations (v2):
- Mini-batch training with NeighborLoader for O(batch) vs O(n) per epoch
- CPU training (more stable than MPS for sparse GNN ops)
- Progress tracking with tqdm

Author: Vinayk Sharma
Date: January 27, 2026
Phase: 7 - Advanced Models
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import RGCNConv
from torch_geometric.data import Data, HeteroData
from torch_geometric.loader import NeighborLoader
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
from tqdm.auto import tqdm
import logging
import time

logger = logging.getLogger(__name__)


class RGCNPrioritizer(nn.Module):
    """
    RGCN model for CVE prioritization.
    
    Uses relational graph convolutions to model CVE-CWE relationships
    and learn embeddings that capture vulnerability patterns.
    """
    
    def __init__(
        self,
        num_features: int,
        hidden_channels: int = 64,
        num_layers: int = 2,
        num_relations: int = 2,
        dropout: float = 0.3,
        num_bases: int = 30
    ):
        """
        Initialize RGCN model.
        
        Args:
            num_features: Number of input features per node
            hidden_channels: Hidden layer dimension
            num_layers: Number of RGCN layers
            num_relations: Number of edge types (e.g., CVE->CWE, CWE->CVE)
            dropout: Dropout rate
            num_bases: Number of bases for basis-decomposition (reduces params)
        """
        super().__init__()
        
        self.num_features = num_features
        self.hidden_channels = hidden_channels
        self.num_layers = num_layers
        self.num_relations = num_relations
        self.dropout = dropout
        
        # RGCN layers
        self.convs = nn.ModuleList()
        
        # First layer: features -> hidden
        self.convs.append(
            RGCNConv(
                num_features,
                hidden_channels,
                num_relations,
                num_bases=num_bases
            )
        )
        
        # Middle layers: hidden -> hidden
        for _ in range(num_layers - 2):
            self.convs.append(
                RGCNConv(
                    hidden_channels,
                    hidden_channels,
                    num_relations,
                    num_bases=num_bases
                )
            )
        
        # Last layer: hidden -> hidden
        if num_layers > 1:
            self.convs.append(
                RGCNConv(
                    hidden_channels,
                    hidden_channels,
                    num_relations,
                    num_bases=num_bases
                )
            )
        
        # Prediction head
        self.fc1 = nn.Linear(hidden_channels, hidden_channels // 2)
        self.fc2 = nn.Linear(hidden_channels // 2, 1)
        
        self.reset_parameters()
    
    def reset_parameters(self):
        """Reset all learnable parameters."""
        for conv in self.convs:
            conv.reset_parameters()
        self.fc1.reset_parameters()
        self.fc2.reset_parameters()
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass.
        
        Args:
            x: Node features [num_nodes, num_features]
            edge_index: Edge connectivity [2, num_edges]
            edge_type: Edge types [num_edges]
            
        Returns:
            Priority scores [num_nodes, 1]
        """
        # Apply RGCN layers
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index, edge_type)
            if i < len(self.convs) - 1:
                x = F.relu(x)
                x = F.dropout(x, p=self.dropout, training=self.training)
        
        # Final ReLU
        x = F.relu(x)
        
        # Prediction head
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.fc1(x)
        x = F.relu(x)
        x = F.dropout(x, p=self.dropout, training=self.training)
        x = self.fc2(x)
        
        return x.squeeze(-1)
    
    def get_embeddings(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor
    ) -> torch.Tensor:
        """
        Get node embeddings (before prediction head).
        
        Args:
            x: Node features [num_nodes, num_features]
            edge_index: Edge connectivity [2, num_edges]
            edge_type: Edge types [num_edges]
            
        Returns:
            Node embeddings [num_nodes, hidden_channels]
        """
        for i, conv in enumerate(self.convs):
            x = conv(x, edge_index, edge_type)
            if i < len(self.convs) - 1:
                x = F.relu(x)
        
        return F.relu(x)


class CVERGCNTrainer:
    """
    Trainer for RGCN CVE prioritization model.
    
    Supports two training modes:
    1. Full-batch (small graphs < 5K nodes): Original O(n) per epoch
    2. Mini-batch (large graphs): Uses NeighborLoader for O(batch) per epoch
    """
    
    def __init__(
        self,
        model: RGCNPrioritizer,
        learning_rate: float = 0.01,
        weight_decay: float = 5e-4,
        device: str = None,
        use_minibatch: bool = True,
        batch_size: int = 1024,
        num_neighbors: List[int] = None
    ):
        """
        Initialize trainer.
        
        Args:
            model: RGCN model to train
            learning_rate: Learning rate
            weight_decay: L2 regularization
            device: Device to use ('cpu', 'cuda', 'mps')
            use_minibatch: Use mini-batch training (recommended for >5K nodes)
            batch_size: Mini-batch size (only if use_minibatch=True)
            num_neighbors: Neighbors to sample per layer [layer1, layer2, ...]
        """
        self.model = model
        self.use_minibatch = use_minibatch
        self.batch_size = batch_size
        self.num_neighbors = num_neighbors or [15, 10]  # Default: 15 L1, 10 L2 neighbors
        
        # FORCE CPU for RGCN - MPS has issues with sparse ops, CPU is often faster
        # Only use CUDA if available (proper GPU)
        if device is None:
            if torch.cuda.is_available():
                device = 'cuda'
            else:
                device = 'cpu'  # CPU is faster than MPS for sparse GNN ops!
        elif device == 'mps':
            logger.warning("MPS is slow for RGCN sparse ops - switching to CPU")
            device = 'cpu'
        
        self.device = torch.device(device)
        self.model.to(self.device)
        
        self.optimizer = torch.optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        
        # Use MSE loss for regression
        self.criterion = nn.MSELoss()
        
        logger.info(f"RGCN Trainer initialized on device: {self.device}")
        logger.info(f"Mini-batch training: {use_minibatch}, batch_size: {batch_size}")
    
    def train_epoch(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        train_mask: torch.Tensor
    ) -> float:
        """
        Train for one epoch.
        
        Args:
            x: Node features
            edge_index: Edge connectivity
            edge_type: Edge types
            y: Target scores
            train_mask: Boolean mask for training nodes
            
        Returns:
            Training loss
        """
        self.model.train()
        self.optimizer.zero_grad()
        
        # Forward pass
        out = self.model(x, edge_index, edge_type)
        
        # Compute loss only on training nodes
        loss = self.criterion(out[train_mask], y[train_mask])
        
        # Backward pass
        loss.backward()
        self.optimizer.step()
        
        return loss.item()
    
    @torch.no_grad()
    def evaluate(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        eval_mask: torch.Tensor
    ) -> Tuple[float, np.ndarray]:
        """
        Evaluate model on validation/test set.
        
        Args:
            x: Node features
            edge_index: Edge connectivity
            edge_type: Edge types
            y: Target scores
            eval_mask: Boolean mask for evaluation nodes
            
        Returns:
            (loss, predictions)
        """
        self.model.eval()
        
        # Forward pass
        out = self.model(x, edge_index, edge_type)
        
        # Compute loss
        loss = self.criterion(out[eval_mask], y[eval_mask])
        
        # Get predictions
        predictions = out[eval_mask].cpu().numpy()
        
        return loss.item(), predictions
    
    def _create_neighbor_loader(
        self,
        data: Data,
        input_nodes: torch.Tensor,
        shuffle: bool = True
    ) -> NeighborLoader:
        """Create NeighborLoader for mini-batch training."""
        return NeighborLoader(
            data,
            num_neighbors=self.num_neighbors,
            batch_size=self.batch_size,
            input_nodes=input_nodes,
            shuffle=shuffle,
            num_workers=0,  # No multiprocessing (simpler, avoids issues)
        )
    
    def fit(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        train_mask: torch.Tensor,
        val_mask: Optional[torch.Tensor] = None,
        epochs: int = 200,
        early_stopping_patience: int = 20,
        verbose: bool = True
    ) -> Dict[str, List[float]]:
        """
        Train model with optional early stopping.
        
        Uses mini-batch training with NeighborLoader for large graphs (>5K nodes).
        
        Args:
            x: Node features
            edge_index: Edge connectivity
            edge_type: Edge types
            y: Target scores
            train_mask: Training nodes mask
            val_mask: Validation nodes mask (optional)
            epochs: Maximum training epochs
            early_stopping_patience: Patience for early stopping
            verbose: Print progress
            
        Returns:
            Training history
        """
        num_nodes = x.shape[0]
        use_minibatch = self.use_minibatch and num_nodes > 5000
        
        if use_minibatch:
            return self._fit_minibatch(
                x, edge_index, edge_type, y, train_mask, val_mask,
                epochs, early_stopping_patience, verbose
            )
        else:
            return self._fit_fullbatch(
                x, edge_index, edge_type, y, train_mask, val_mask,
                epochs, early_stopping_patience, verbose
            )
    
    def _fit_fullbatch(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        train_mask: torch.Tensor,
        val_mask: Optional[torch.Tensor] = None,
        epochs: int = 200,
        early_stopping_patience: int = 20,
        verbose: bool = True
    ) -> Dict[str, List[float]]:
        """Full-batch training (original method for small graphs)."""
        import sys
        
        # Move data to device
        x = x.to(self.device)
        edge_index = edge_index.to(self.device)
        edge_type = edge_type.to(self.device)
        y = y.to(self.device)
        train_mask = train_mask.to(self.device)
        
        if val_mask is not None:
            val_mask = val_mask.to(self.device)
        
        history = {
            'train_loss': [],
            'val_loss': []
        }
        
        best_val_loss = float('inf')
        patience_counter = 0
        best_model_state = None
        
        if verbose:
            print(f"Training: [", end="", flush=True)
        
        for epoch in range(epochs):
            # Train
            train_loss = self.train_epoch(x, edge_index, edge_type, y, train_mask)
            history['train_loss'].append(train_loss)
            
            # Validate
            if val_mask is not None:
                val_loss, _ = self.evaluate(x, edge_index, edge_type, y, val_mask)
                history['val_loss'].append(val_loss)
                
                # Early stopping check
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                    best_model_state = self.model.state_dict().copy()
                    if verbose:
                        print("↑", end="", flush=True)  # Improvement
                else:
                    patience_counter += 1
                    if verbose:
                        print(".", end="", flush=True)  # No improvement
                
                # Early stopping
                if patience_counter >= early_stopping_patience:
                    if verbose:
                        print(f"] Early stop @ {epoch+1}")
                    break
            else:
                if verbose:
                    print(".", end="", flush=True)
            
            # Progress milestone every 10 epochs
            if verbose and (epoch + 1) % 10 == 0:
                print(f"{epoch+1}", end="", flush=True)
        
        if verbose and patience_counter < early_stopping_patience:
            print(f"] Done!")
            print(f"  Final: train_loss={train_loss:.4f}, val_loss={history['val_loss'][-1] if history['val_loss'] else 'N/A':.4f}")
        
        # Restore best model
        if best_model_state is not None:
            self.model.load_state_dict(best_model_state)
            if verbose:
                print(f"  Best val_loss: {best_val_loss:.4f}")
        
        return history
    
    def _fit_minibatch(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        train_mask: torch.Tensor,
        val_mask: Optional[torch.Tensor] = None,
        epochs: int = 200,
        early_stopping_patience: int = 20,
        verbose: bool = True
    ) -> Dict[str, List[float]]:
        """
        Mini-batch training with NeighborLoader.
        
        ~10-100x faster than full-batch for large graphs!
        Falls back to full-batch if pyg-lib/torch-sparse not available.
        """
        import sys
        
        # Check if NeighborLoader dependencies are available
        try:
            # Test if sampling works
            test_data = Data(x=x[:100], edge_index=edge_index[:, :100] if edge_index.shape[1] > 100 else edge_index)
            test_loader = NeighborLoader(test_data, num_neighbors=[2], batch_size=10, 
                                         input_nodes=torch.arange(min(10, x.shape[0])))
            next(iter(test_loader))  # Try to get one batch
        except (ImportError, RuntimeError) as e:
            if verbose:
                print(f"⚠ NeighborLoader not available ({type(e).__name__}), using full-batch", flush=True)
            return self._fit_fullbatch(
                x, edge_index, edge_type, y, train_mask, val_mask,
                epochs, early_stopping_patience, verbose
            )
        
        if verbose:
            print(f"Mini-batch mode: batch_size={self.batch_size}")
        start_time = time.time()
        
        # Create PyG Data object
        if verbose:
            print("  Creating graph data...", end="", flush=True)
        data = Data(
            x=x,
            edge_index=edge_index,
            edge_type=edge_type,
            y=y,
            train_mask=train_mask,
            val_mask=val_mask if val_mask is not None else torch.zeros_like(train_mask)
        )
        if verbose:
            print(" ✓", flush=True)
        
        # Get training node indices
        train_nodes = train_mask.nonzero(as_tuple=True)[0]
        
        # Create loader for training
        if verbose:
            print(f"  Creating NeighborLoader ({len(train_nodes):,} train nodes)...", end="", flush=True)
        train_loader = self._create_neighbor_loader(data, train_nodes, shuffle=True)
        num_batches = len(train_loader)
        if verbose:
            print(f" ✓ ({num_batches} batches)", flush=True)
        
        history = {
            'train_loss': [],
            'val_loss': []
        }
        
        best_val_loss = float('inf')
        patience_counter = 0
        best_model_state = None
        
        if verbose:
            print(f"\nEpoch progress ({epochs} total):", flush=True)
            print("[", end="", flush=True)
        
        for epoch in range(epochs):
            epoch_start = time.time()
            
            # Train one epoch with mini-batches
            self.model.train()
            total_loss = 0
            total_nodes = 0
            
            for batch_idx, batch in enumerate(train_loader):
                batch = batch.to(self.device)
                self.optimizer.zero_grad()
                
                # Forward pass on subgraph
                out = self.model(batch.x, batch.edge_index, batch.edge_type)
                
                # Loss only on target nodes (first batch_size nodes in batch)
                batch_size = batch.batch_size
                loss = self.criterion(out[:batch_size], batch.y[:batch_size])
                
                # Backward
                loss.backward()
                self.optimizer.step()
                
                total_loss += loss.item() * batch_size
                total_nodes += batch_size
            
            train_loss = total_loss / total_nodes
            history['train_loss'].append(train_loss)
            
            # Validate
            if val_mask is not None and val_mask.any():
                val_loss, _ = self._evaluate_fullbatch(x, edge_index, edge_type, y, val_mask)
                history['val_loss'].append(val_loss)
                
                if val_loss < best_val_loss:
                    best_val_loss = val_loss
                    patience_counter = 0
                    best_model_state = self.model.state_dict().copy()
                    if verbose:
                        print("↑", end="", flush=True)  # Improved!
                else:
                    patience_counter += 1
                    if verbose:
                        print(".", end="", flush=True)  # No improvement
                
                # Show epoch number every 10 epochs
                if verbose and (epoch + 1) % 10 == 0:
                    elapsed = time.time() - start_time
                    print(f" {epoch+1}({elapsed:.0f}s)", end="", flush=True)
                
                if patience_counter >= early_stopping_patience:
                    if verbose:
                        print(f"] Early stop @ epoch {epoch+1}")
                    break
            else:
                if verbose:
                    print(".", end="", flush=True)
        
        elapsed = time.time() - start_time
        
        if verbose and patience_counter < early_stopping_patience:
            print(f"] Done!")
        
        if verbose:
            print(f"\n✓ Training completed in {elapsed:.1f}s ({elapsed/60:.1f} min)")
            print(f"  Final train_loss: {train_loss:.4f}")
            if history['val_loss']:
                print(f"  Best val_loss: {best_val_loss:.4f}")
        
        # Restore best model
        if best_model_state is not None:
            self.model.load_state_dict(best_model_state)
        
        return history
    
    @torch.no_grad()
    def _evaluate_fullbatch(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        eval_mask: torch.Tensor
    ) -> Tuple[float, np.ndarray]:
        """Evaluate on full graph (for validation)."""
        self.model.eval()
        
        x = x.to(self.device)
        edge_index = edge_index.to(self.device)
        edge_type = edge_type.to(self.device)
        y = y.to(self.device)
        eval_mask = eval_mask.to(self.device)
        
        out = self.model(x, edge_index, edge_type)
        loss = self.criterion(out[eval_mask], y[eval_mask])
        predictions = out[eval_mask].cpu().numpy()
        
        return loss.item(), predictions
    
    @torch.no_grad()
    def predict(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        mask: Optional[torch.Tensor] = None
    ) -> np.ndarray:
        """
        Generate predictions.
        
        Args:
            x: Node features
            edge_index: Edge connectivity
            edge_type: Edge types
            mask: Optional mask for specific nodes
            
        Returns:
            Predictions as numpy array
        """
        self.model.eval()
        
        # Move to device
        x = x.to(self.device)
        edge_index = edge_index.to(self.device)
        edge_type = edge_type.to(self.device)
        
        # Forward pass
        out = self.model(x, edge_index, edge_type)
        
        # Apply mask if provided
        if mask is not None:
            mask = mask.to(self.device)
            out = out[mask]
        
        return out.cpu().numpy()


def prepare_rgcn_data(
    cve_features: np.ndarray,
    cve_to_cwe: Dict[int, List[int]],
    cve_labels: np.ndarray,
    train_idx: np.ndarray,
    val_idx: Optional[np.ndarray] = None,
    test_idx: Optional[np.ndarray] = None,
    normalize_features: bool = True,
    verbose: bool = True
) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, 
           torch.Tensor, torch.Tensor, torch.Tensor]:
    """
    Prepare data for RGCN training.
    
    Args:
        cve_features: CVE feature matrix [num_cves, num_features]
        cve_to_cwe: Mapping from CVE index to CWE indices
        cve_labels: Priority labels [num_cves]
        train_idx: Training indices
        val_idx: Validation indices
        test_idx: Test indices
        normalize_features: Whether to standardize features
        verbose: Print progress
        
    Returns:
        (x, edge_index, edge_type, y, train_mask, val_mask, test_mask)
    """
    import sys
    
    num_cves = len(cve_features)
    num_features = cve_features.shape[1]
    
    if verbose:
        print(f"Preparing RGCN data ({num_cves:,} nodes)...", flush=True)
    
    # Normalize features
    if normalize_features:
        if verbose:
            print("  [1/4] Normalizing features...", end="", flush=True)
        scaler = StandardScaler()
        cve_features = scaler.fit_transform(cve_features)
        if verbose:
            print(" ✓", flush=True)
    
    # Build edge list with types
    if verbose:
        print(f"  [2/4] Building edges ({len(cve_to_cwe):,} mappings)...", end="", flush=True)
    
    edges = []
    edge_types = []
    
    for cve_idx, cwe_list in cve_to_cwe.items():
        if cve_idx >= num_cves:
            continue
        
        for cwe_idx in cwe_list:
            if cwe_idx >= num_cves:
                continue
            
            # CVE -> CWE
            edges.append([cve_idx, cwe_idx])
            edge_types.append(0)
            
            # CWE -> CVE (reverse edge)
            edges.append([cwe_idx, cve_idx])
            edge_types.append(1)
    
    if verbose:
        print(f" ✓ ({len(edges):,} edges)", flush=True)
    
    # Convert to tensors
    if len(edges) == 0:
        logger.warning("No edges found, creating self-loops")
        edges = [[i, i] for i in range(num_cves)]
        edge_types = [0] * num_cves
    
    if verbose:
        print("  [3/4] Creating tensors...", end="", flush=True)
    
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    edge_type = torch.tensor(edge_types, dtype=torch.long)
    x = torch.tensor(cve_features, dtype=torch.float32)
    y = torch.tensor(cve_labels, dtype=torch.float32)
    
    if verbose:
        print(" ✓", flush=True)
    
    # Create masks
    if verbose:
        print("  [4/4] Creating masks...", end="", flush=True)
    
    train_mask = torch.zeros(num_cves, dtype=torch.bool)
    train_mask[train_idx] = True
    
    val_mask = torch.zeros(num_cves, dtype=torch.bool)
    if val_idx is not None:
        val_mask[val_idx] = True
    
    test_mask = torch.zeros(num_cves, dtype=torch.bool)
    if test_idx is not None:
        test_mask[test_idx] = True
    
    if verbose:
        print(" ✓", flush=True)
        print(f"  → Nodes: {num_cves:,}, Edges: {edge_index.shape[1]:,}, Train/Val: {train_mask.sum()}/{val_mask.sum()}", flush=True)
    
    return x, edge_index, edge_type, y, train_mask, val_mask, test_mask


def train_rgcn_model(
    cve_features: np.ndarray,
    cve_to_cwe: Dict[int, List[int]],
    cve_labels: np.ndarray,
    train_idx: np.ndarray,
    val_idx: Optional[np.ndarray] = None,
    test_idx: Optional[np.ndarray] = None,
    hidden_channels: int = 64,
    num_layers: int = 2,
    dropout: float = 0.3,
    learning_rate: float = 0.01,
    epochs: int = 200,
    early_stopping_patience: int = 20,
    device: str = None,
    verbose: bool = True,
    use_minibatch: bool = True,
    batch_size: int = 1024
) -> Tuple[RGCNPrioritizer, CVERGCNTrainer, Dict]:
    """
    Train RGCN model end-to-end.
    
    Optimized for large datasets:
    - Uses CPU (more stable than MPS for sparse GNN ops)
    - Mini-batch training with NeighborLoader for O(batch) per epoch
    - Early stopping to prevent overfitting
    
    Expected training times (32K samples, 100 epochs):
    - Old (full-batch MPS): 100+ minutes
    - New (mini-batch CPU): ~5-10 minutes
    
    Args:
        cve_features: CVE feature matrix
        cve_to_cwe: CVE-CWE mapping
        cve_labels: Priority labels
        train_idx: Training indices
        val_idx: Validation indices
        test_idx: Test indices
        hidden_channels: Hidden layer size
        num_layers: Number of RGCN layers
        dropout: Dropout rate
        learning_rate: Learning rate
        epochs: Max epochs
        early_stopping_patience: Early stopping patience
        device: Device to use (default: CPU for RGCN, CUDA if available)
        verbose: Print progress
        use_minibatch: Use mini-batch training (recommended for >5K nodes)
        batch_size: Mini-batch size
        
    Returns:
        (model, trainer, history)
    """
    import sys
    
    if verbose:
        print("\n" + "="*50, flush=True)
        print("RGCN TRAINING PIPELINE", flush=True)
        print("="*50, flush=True)
    
    # Prepare data
    if verbose:
        print("\n[STEP 1/4] Preparing data...", flush=True)
    
    x, edge_index, edge_type, y, train_mask, val_mask, test_mask = prepare_rgcn_data(
        cve_features, cve_to_cwe, cve_labels, train_idx, val_idx, test_idx, verbose=verbose
    )
    
    num_nodes = x.shape[0]
    num_features = x.shape[1]
    
    # Device selection
    if verbose:
        print("\n[STEP 2/4] Setting up device...", flush=True)
    
    if device is None or device == 'mps':
        if torch.cuda.is_available():
            device = 'cuda'
        else:
            device = 'cpu'
            if verbose:
                print(f"  → Using CPU (faster than MPS for sparse ops)", flush=True)
    
    # Auto-enable mini-batch for large graphs
    if num_nodes > 5000 and use_minibatch:
        if verbose:
            print(f"  → Mini-batch enabled ({num_nodes:,} nodes > 5K)", flush=True)
            print(f"  → Batch size: {batch_size}", flush=True)
    
    # Create model
    if verbose:
        print("\n[STEP 3/4] Creating model...", flush=True)
    
    model = RGCNPrioritizer(
        num_features=num_features,
        hidden_channels=hidden_channels,
        num_layers=num_layers,
        num_relations=2,
        dropout=dropout
    )
    
    if verbose:
        print(f"  → Model: {num_features} → {hidden_channels} → 1", flush=True)
    
    # Create trainer
    trainer = CVERGCNTrainer(
        model=model,
        learning_rate=learning_rate,
        device=device,
        use_minibatch=use_minibatch,
        batch_size=batch_size
    )
    
    # Train
    if verbose:
        print("\n[STEP 4/4] Training...", flush=True)
    
    history = trainer.fit(
        x=x,
        edge_index=edge_index,
        edge_type=edge_type,
        y=y,
        train_mask=train_mask,
        val_mask=val_mask if val_idx is not None else None,
        epochs=epochs,
        early_stopping_patience=early_stopping_patience,
        verbose=verbose
    )
    
    return model, trainer, history


def fast_rgcn_inference(
    model: RGCNPrioritizer,
    train_features: np.ndarray,
    test_features: np.ndarray,
    train_cve_to_cwe: Dict[int, List[int]],
    test_to_train_neighbors: Dict[int, List[int]],
    batch_size: int = 500,
    device: str = 'cpu'
) -> np.ndarray:
    """
    Fast RGCN inference using mini-batch subgraph extraction.
    
    Instead of computing RGCN on the full graph (slow!), this:
    1. Processes test nodes in batches
    2. For each batch, extracts only relevant subgraph
    3. Computes predictions on small subgraph (fast!)
    
    Speedup: ~100x for large graphs
    
    Args:
        model: Trained RGCN model
        train_features: Training node features [n_train, n_features]
        test_features: Test node features [n_test, n_features]
        train_cve_to_cwe: Mapping for training nodes
        test_to_train_neighbors: For each test node, list of train neighbors
        batch_size: Number of test nodes per batch
        device: Device for computation
        
    Returns:
        Predictions for all test nodes [n_test]
    """
    model.eval()
    model.to(device)
    
    n_train = len(train_features)
    n_test = len(test_features)
    predictions = np.zeros(n_test)
    
    # Normalize features
    scaler = StandardScaler()
    train_norm = scaler.fit_transform(train_features)
    test_norm = scaler.transform(test_features)
    
    # Process in batches
    for batch_start in range(0, n_test, batch_size):
        batch_end = min(batch_start + batch_size, n_test)
        batch_test_idx = list(range(batch_start, batch_end))
        
        # Collect all nodes needed for this batch
        # Test nodes + their train neighbors
        needed_train = set()
        for test_idx in batch_test_idx:
            if test_idx in test_to_train_neighbors:
                needed_train.update(test_to_train_neighbors[test_idx])
        
        needed_train = sorted(list(needed_train))
        
        # Build local index mapping
        # Local indices: [0..n_train_local-1] = train nodes, [n_train_local..] = test batch
        train_local_map = {global_idx: local_idx for local_idx, global_idx in enumerate(needed_train)}
        n_train_local = len(needed_train)
        test_local_map = {global_idx: n_train_local + i for i, global_idx in enumerate(batch_test_idx)}
        
        # Build features for subgraph
        if len(needed_train) > 0:
            local_features = np.vstack([
                train_norm[needed_train],
                test_norm[batch_test_idx]
            ])
        else:
            local_features = test_norm[batch_test_idx]
            n_train_local = 0
        
        # Build edges for subgraph
        src_nodes, dst_nodes, edge_types_list = [], [], []
        
        # Train-train edges (within needed_train)
        for train_global in needed_train:
            if train_global in train_cve_to_cwe:
                for neighbor in train_cve_to_cwe[train_global]:
                    if neighbor in train_local_map:
                        src_nodes.append(train_local_map[train_global])
                        dst_nodes.append(train_local_map[neighbor])
                        edge_types_list.append(0)
        
        # Test-train edges
        for test_global in batch_test_idx:
            if test_global in test_to_train_neighbors:
                for train_global in test_to_train_neighbors[test_global]:
                    if train_global in train_local_map:
                        # Test -> Train
                        src_nodes.append(test_local_map[test_global])
                        dst_nodes.append(train_local_map[train_global])
                        edge_types_list.append(0)
                        # Train -> Test (reverse)
                        src_nodes.append(train_local_map[train_global])
                        dst_nodes.append(test_local_map[test_global])
                        edge_types_list.append(1)
        
        # Create tensors
        x = torch.tensor(local_features, dtype=torch.float32, device=device)
        
        if len(src_nodes) > 0:
            edge_index = torch.tensor([src_nodes, dst_nodes], dtype=torch.long, device=device)
            edge_type = torch.tensor(edge_types_list, dtype=torch.long, device=device)
        else:
            # No edges - create empty tensors
            edge_index = torch.zeros((2, 0), dtype=torch.long, device=device)
            edge_type = torch.zeros(0, dtype=torch.long, device=device)
        
        # Forward pass on small subgraph
        with torch.no_grad():
            out = model(x, edge_index, edge_type)
        
        # Extract predictions for test nodes only
        batch_preds = out[n_train_local:].cpu().numpy()
        predictions[batch_start:batch_end] = batch_preds
    
    return predictions


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Synthetic data for demonstration
    num_cves = 1000
    num_features = 12
    
    # Random features
    cve_features = np.random.randn(num_cves, num_features)
    
    # Random CVE-CWE mapping
    cve_to_cwe = {}
    for i in range(num_cves):
        # Each CVE connected to 1-3 random other nodes (CWEs)
        num_connections = np.random.randint(1, 4)
        cwe_list = np.random.choice(num_cves, num_connections, replace=False).tolist()
        cve_to_cwe[i] = cwe_list
    
    # Random labels
    cve_labels = np.random.randint(1, 6, num_cves).astype(float)
    
    # Train/val/test split
    indices = np.arange(num_cves)
    np.random.shuffle(indices)
    train_idx = indices[:700]
    val_idx = indices[700:850]
    test_idx = indices[850:]
    
    print("Training RGCN model...")
    model, trainer, history = train_rgcn_model(
        cve_features=cve_features,
        cve_to_cwe=cve_to_cwe,
        cve_labels=cve_labels,
        train_idx=train_idx,
        val_idx=val_idx,
        test_idx=test_idx,
        hidden_channels=32,
        num_layers=2,
        epochs=50,
        verbose=True
    )
    
    print("\n✓ Training complete!")
    print(f"Final train loss: {history['train_loss'][-1]:.4f}")
    print(f"Final val loss: {history['val_loss'][-1]:.4f}")
