"""
Relational Graph Convolutional Network (RGCN) for CVE Prioritization

This module implements an RGCN model to capture CVE-to-CWE relationships
and prioritize vulnerabilities based on graph structure and node features.

Architecture:
- Input: CVE node features + CVE-CWE bipartite graph
- RGCN layers: Learn node embeddings using typed edges
- Output: Priority scores for each CVE

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
from sklearn.preprocessing import StandardScaler
from typing import Dict, List, Tuple, Optional
import logging

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
    """
    
    def __init__(
        self,
        model: RGCNPrioritizer,
        learning_rate: float = 0.01,
        weight_decay: float = 5e-4,
        device: str = None
    ):
        """
        Initialize trainer.
        
        Args:
            model: RGCN model to train
            learning_rate: Learning rate
            weight_decay: L2 regularization
            device: Device to use ('cpu', 'cuda', 'mps')
        """
        self.model = model
        
        # Auto-detect device
        if device is None:
            if torch.cuda.is_available():
                device = 'cuda'
            elif torch.backends.mps.is_available():
                device = 'mps'
            else:
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
                else:
                    patience_counter += 1
                
                if verbose and (epoch + 1) % 10 == 0:
                    logger.info(
                        f"Epoch {epoch+1}/{epochs} - "
                        f"Train Loss: {train_loss:.4f}, "
                        f"Val Loss: {val_loss:.4f}"
                    )
                
                # Early stopping
                if patience_counter >= early_stopping_patience:
                    logger.info(f"Early stopping at epoch {epoch+1}")
                    break
            else:
                if verbose and (epoch + 1) % 10 == 0:
                    logger.info(
                        f"Epoch {epoch+1}/{epochs} - "
                        f"Train Loss: {train_loss:.4f}"
                    )
        
        # Restore best model
        if best_model_state is not None:
            self.model.load_state_dict(best_model_state)
            logger.info(f"Restored best model with val_loss={best_val_loss:.4f}")
        
        return history
    
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
    normalize_features: bool = True
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
        
    Returns:
        (x, edge_index, edge_type, y, train_mask, val_mask, test_mask)
    """
    num_cves = len(cve_features)
    num_features = cve_features.shape[1]
    
    # Normalize features
    if normalize_features:
        scaler = StandardScaler()
        cve_features = scaler.fit_transform(cve_features)
    
    # Build edge list with types
    # Edge type 0: CVE -> CWE
    # Edge type 1: CWE -> CVE
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
    
    # Convert to tensors
    if len(edges) == 0:
        # No edges - create self-loops
        logger.warning("No edges found, creating self-loops")
        edges = [[i, i] for i in range(num_cves)]
        edge_types = [0] * num_cves
    
    edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    edge_type = torch.tensor(edge_types, dtype=torch.long)
    
    # Convert features and labels
    x = torch.tensor(cve_features, dtype=torch.float32)
    y = torch.tensor(cve_labels, dtype=torch.float32)
    
    # Create masks
    train_mask = torch.zeros(num_cves, dtype=torch.bool)
    train_mask[train_idx] = True
    
    val_mask = torch.zeros(num_cves, dtype=torch.bool)
    if val_idx is not None:
        val_mask[val_idx] = True
    
    test_mask = torch.zeros(num_cves, dtype=torch.bool)
    if test_idx is not None:
        test_mask[test_idx] = True
    
    logger.info(f"Prepared RGCN data:")
    logger.info(f"  Nodes: {num_cves}")
    logger.info(f"  Edges: {edge_index.shape[1]}")
    logger.info(f"  Features: {num_features}")
    logger.info(f"  Train/Val/Test: {train_mask.sum()}/{val_mask.sum()}/{test_mask.sum()}")
    
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
    verbose: bool = True
) -> Tuple[RGCNPrioritizer, CVERGCNTrainer, Dict]:
    """
    Train RGCN model end-to-end.
    
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
        device: Device to use
        verbose: Print progress
        
    Returns:
        (model, trainer, history)
    """
    # Prepare data
    x, edge_index, edge_type, y, train_mask, val_mask, test_mask = prepare_rgcn_data(
        cve_features, cve_to_cwe, cve_labels, train_idx, val_idx, test_idx
    )
    
    # Create model
    num_features = x.shape[1]
    model = RGCNPrioritizer(
        num_features=num_features,
        hidden_channels=hidden_channels,
        num_layers=num_layers,
        num_relations=2,  # CVE->CWE and CWE->CVE
        dropout=dropout
    )
    
    # Create trainer
    trainer = CVERGCNTrainer(
        model=model,
        learning_rate=learning_rate,
        device=device
    )
    
    # Train
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
