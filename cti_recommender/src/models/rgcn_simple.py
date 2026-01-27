"""
Simple RGCN implementation that avoids PyTorch Geometric crashes on macOS.

Uses basic PyTorch operations instead of PyG's RGCNConv which has
sparse tensor issues on Apple Silicon.
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class SimpleRGCN(nn.Module):
    """
    Simple RGCN implementation using dense message passing.
    
    Avoids PyG's sparse ops that crash on macOS.
    """
    
    def __init__(
        self,
        num_features: int,
        hidden_channels: int = 64,
        num_layers: int = 2,
        num_relations: int = 2,
        dropout: float = 0.3
    ):
        super().__init__()
        
        self.num_features = num_features
        self.hidden_channels = hidden_channels
        self.num_layers = num_layers
        self.num_relations = num_relations
        self.dropout = dropout
        
        # Input projection
        self.input_proj = nn.Linear(num_features, hidden_channels)
        
        # Per-relation weight matrices for message passing
        self.relation_weights = nn.ModuleList([
            nn.Linear(hidden_channels, hidden_channels, bias=False)
            for _ in range(num_relations)
        ])
        
        # Self-loop weight
        self.self_weight = nn.Linear(hidden_channels, hidden_channels, bias=False)
        
        # Layer norm for stability
        self.layer_norm = nn.LayerNorm(hidden_channels)
        
        # Prediction head
        self.fc1 = nn.Linear(hidden_channels, hidden_channels // 2)
        self.fc2 = nn.Linear(hidden_channels // 2, 1)
    
    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor
    ) -> torch.Tensor:
        """
        Forward pass using simple message passing.
        
        Args:
            x: Node features [num_nodes, num_features]
            edge_index: Edge connectivity [2, num_edges]
            edge_type: Edge types [num_edges]
            
        Returns:
            Priority scores [num_nodes]
        """
        num_nodes = x.shape[0]
        
        # Project input features
        h = self.input_proj(x)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)
        
        # Message passing (simplified - aggregate neighbor features)
        for _ in range(self.num_layers - 1):
            # Self contribution
            h_new = self.self_weight(h)
            
            # Neighbor contributions per relation type
            for rel in range(self.num_relations):
                rel_mask = edge_type == rel
                if rel_mask.sum() > 0:
                    rel_edges = edge_index[:, rel_mask]
                    src, dst = rel_edges[0], rel_edges[1]
                    
                    # Aggregate: mean of transformed neighbor features
                    neighbor_feats = h[src]
                    transformed = self.relation_weights[rel](neighbor_feats)
                    
                    # Scatter add to destinations
                    h_new.index_add_(0, dst, transformed)
            
            # Normalize by degree (approximate)
            h = self.layer_norm(h_new)
            h = F.relu(h)
            h = F.dropout(h, p=self.dropout, training=self.training)
        
        # Prediction head
        out = self.fc1(h)
        out = F.relu(out)
        out = F.dropout(out, p=self.dropout, training=self.training)
        out = self.fc2(out)
        
        return out.squeeze(-1)


class SimpleRGCNTrainer:
    """Simple trainer that avoids PyG operations."""
    
    def __init__(
        self,
        model: SimpleRGCN,
        learning_rate: float = 0.01,
        weight_decay: float = 5e-4
    ):
        self.model = model
        self.optimizer = torch.optim.Adam(
            model.parameters(),
            lr=learning_rate,
            weight_decay=weight_decay
        )
        self.criterion = nn.MSELoss()
    
    def fit(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        edge_type: torch.Tensor,
        y: torch.Tensor,
        train_mask: torch.Tensor,
        val_mask: torch.Tensor,
        epochs: int = 100,
        early_stopping_patience: int = 10,
        verbose: bool = True
    ) -> Dict:
        """Train the model."""
        
        history = {'train_loss': [], 'val_loss': []}
        best_val_loss = float('inf')
        patience_counter = 0
        best_state = None
        
        progress = ""
        for epoch in range(epochs):
            # Training
            self.model.train()
            self.optimizer.zero_grad()
            
            out = self.model(x, edge_index, edge_type)
            train_loss = self.criterion(out[train_mask], y[train_mask])
            train_loss.backward()
            self.optimizer.step()
            
            # Validation
            self.model.eval()
            with torch.no_grad():
                out = self.model(x, edge_index, edge_type)
                val_loss = self.criterion(out[val_mask], y[val_mask])
            
            history['train_loss'].append(train_loss.item())
            history['val_loss'].append(val_loss.item())
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                best_state = {k: v.cpu().clone() for k, v in self.model.state_dict().items()}
                progress += "↑"
            else:
                patience_counter += 1
                progress += "."
            
            # Progress indicator every 10 epochs
            if verbose and (epoch + 1) % 10 == 0:
                progress += str(epoch + 1)
            
            if patience_counter >= early_stopping_patience:
                if verbose:
                    print(f"Training: [{progress}] Early stop @ {epoch + 1}")
                break
        else:
            if verbose:
                print(f"Training: [{progress}] Done!")
        
        # Restore best model
        if best_state:
            self.model.load_state_dict(best_state)
        
        if verbose:
            print(f"  Final: train_loss={history['train_loss'][-1]:.4f}, val_loss={history['val_loss'][-1]:.4f}")
            print(f"  Best val_loss: {best_val_loss:.4f}")
        
        return history


def train_simple_rgcn(
    cve_features: np.ndarray,
    cve_to_cwe: Dict[int, List[int]],
    cve_labels: np.ndarray,
    train_idx: np.ndarray,
    val_idx: np.ndarray,
    hidden_channels: int = 64,
    num_layers: int = 2,
    dropout: float = 0.2,
    learning_rate: float = 0.01,
    epochs: int = 100,
    early_stopping_patience: int = 10,
    verbose: bool = True
) -> Tuple[SimpleRGCN, SimpleRGCNTrainer, Dict]:
    """
    Train SimpleRGCN model (macOS-safe version).
    
    Args:
        cve_features: Feature matrix [num_cves, num_features]
        cve_to_cwe: Mapping of CVE index to list of related CVE indices
        cve_labels: Target labels [num_cves]
        train_idx: Training indices
        val_idx: Validation indices
        hidden_channels: Hidden dimension
        num_layers: Number of message passing layers
        dropout: Dropout rate
        learning_rate: Learning rate
        epochs: Maximum epochs
        early_stopping_patience: Early stopping patience
        verbose: Print progress
        
    Returns:
        (model, trainer, history)
    """
    print("=" * 50)
    print("SIMPLE RGCN TRAINING (macOS-safe)")
    print("=" * 50)
    
    # Normalize features
    print("\n[1/4] Normalizing features...")
    scaler = StandardScaler()
    features_normalized = scaler.fit_transform(cve_features)
    
    # Build edge lists
    print("[2/4] Building edge lists...")
    src_nodes, dst_nodes = [], []
    for cve_idx, neighbors in cve_to_cwe.items():
        for neighbor_idx in neighbors:
            if neighbor_idx < len(cve_features):
                src_nodes.append(cve_idx)
                dst_nodes.append(neighbor_idx)
    
    # Bidirectional edges with different relation types
    edge_src = src_nodes + dst_nodes
    edge_dst = dst_nodes + src_nodes
    edge_types = [0] * len(src_nodes) + [1] * len(dst_nodes)
    
    print(f"      Edges: {len(edge_src):,}")
    
    # Create tensors
    print("[3/4] Creating tensors...")
    x = torch.tensor(features_normalized, dtype=torch.float32)
    edge_index = torch.tensor([edge_src, edge_dst], dtype=torch.long)
    edge_type = torch.tensor(edge_types, dtype=torch.long)
    y = torch.tensor(cve_labels, dtype=torch.float32)
    
    train_mask = torch.zeros(len(cve_features), dtype=torch.bool)
    train_mask[train_idx] = True
    val_mask = torch.zeros(len(cve_features), dtype=torch.bool)
    val_mask[val_idx] = True
    
    # Create model
    print("[4/4] Training...")
    model = SimpleRGCN(
        num_features=x.shape[1],
        hidden_channels=hidden_channels,
        num_layers=num_layers,
        num_relations=2,
        dropout=dropout
    )
    
    trainer = SimpleRGCNTrainer(model, learning_rate=learning_rate)
    
    history = trainer.fit(
        x, edge_index, edge_type, y,
        train_mask, val_mask,
        epochs=epochs,
        early_stopping_patience=early_stopping_patience,
        verbose=verbose
    )
    
    return model, trainer, history
