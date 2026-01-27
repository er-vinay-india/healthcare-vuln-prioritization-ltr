"""
DiffusionRank-style Label Imputation Model

Uses denoising diffusion for weak label refinement with uncertainty estimation.
"""
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple, Dict


class DenoisingMLP(nn.Module):
    """Lightweight denoising MLP for tabular diffusion."""
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 3):
        super().__init__()
        self.input_dim = input_dim
        
        # Time embedding
        self.time_embed = nn.Sequential(
            nn.Linear(1, hidden_dim),
            nn.SiLU(),
            nn.Linear(hidden_dim, hidden_dim)
        )
        
        # Main network
        layers = []
        in_features = input_dim + 1 + hidden_dim
        
        for i in range(num_layers):
            out_features = hidden_dim if i < num_layers - 1 else 1
            layers.append(nn.Linear(in_features, out_features))
            if i < num_layers - 1:
                layers.append(nn.LayerNorm(out_features))
                layers.append(nn.SiLU())
                layers.append(nn.Dropout(0.1))
            in_features = out_features
        
        self.network = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor, noisy_y: torch.Tensor, t: torch.Tensor) -> torch.Tensor:
        t_embed = self.time_embed(t)
        combined = torch.cat([x, noisy_y, t_embed], dim=-1)
        return self.network(combined)


class DiffusionRankImputer:
    """DiffusionRank-style label imputation model with GPU support."""
    
    def __init__(self, input_dim: int, hidden_dim: int = 128, num_layers: int = 3,
                 lr: float = 1e-3, device: str = None):
        # Auto-detect best device if not specified
        if device is None:
            if torch.backends.mps.is_available():
                self.device = torch.device('mps')
            elif torch.cuda.is_available():
                self.device = torch.device('cuda')
            else:
                self.device = torch.device('cpu')
        else:
            self.device = torch.device(device)
        
        self.model = DenoisingMLP(input_dim, hidden_dim, num_layers).to(self.device)
        self.optimizer = torch.optim.AdamW(self.model.parameters(), lr=lr, weight_decay=1e-4)
        self.scaler = StandardScaler()
        self.label_mean = 0.0
        self.label_std = 1.0
    
    def train_quick(self, train_df: pd.DataFrame, feature_cols: List[str], 
                    epochs: int = 5, verbose: bool = True) -> Dict[str, float]:
        """Quick training for comparison study."""
        X = train_df[feature_cols].values.astype(np.float32)
        y = train_df['soft_label'].values.astype(np.float32).reshape(-1, 1)
        
        X_scaled = self.scaler.fit_transform(X)
        self.label_mean = y.mean()
        self.label_std = y.std() + 1e-6
        y_norm = (y - self.label_mean) / self.label_std
        
        X_t = torch.tensor(X_scaled, device=self.device)
        y_t = torch.tensor(y_norm, device=self.device)
        
        losses = []
        for ep in range(epochs):
            self.model.train()
            t = torch.rand(X_t.size(0), 1, device=self.device)
            noise = torch.randn_like(y_t)
            pred = self.model(X_t, y_t + t * noise, t)
            loss = F.mse_loss(pred, noise)
            self.optimizer.zero_grad()
            loss.backward()
            self.optimizer.step()
            losses.append(loss.item())
            if verbose:
                print(f"  Ep {ep+1}/{epochs}: {loss.item():.4f}", flush=True)
        
        return {'final_loss': losses[-1], 'losses': losses}
    
    def predict(self, df: pd.DataFrame, feature_cols: List[str], 
                num_samples: int = 5) -> Tuple[np.ndarray, np.ndarray]:
        """Predict with uncertainty estimation."""
        self.model.eval()
        
        X = df[feature_cols].values.astype(np.float32)
        X_scaled = self.scaler.transform(X)
        X_t = torch.tensor(X_scaled, device=self.device)
        
        all_preds = []
        with torch.no_grad():
            for _ in range(num_samples):
                noisy_y = torch.randn(X_t.size(0), 1, device=self.device)
                t = torch.ones(X_t.size(0), 1, device=self.device)
                pred_noise = self.model(X_t, noisy_y, t)
                denoised = noisy_y - t * pred_noise
                denoised = denoised * self.label_std + self.label_mean
                all_preds.append(denoised.cpu().numpy())
        
        all_preds = np.concatenate(all_preds, axis=1)
        mean_scores = np.clip(all_preds.mean(axis=1), 0, 3)
        uncertainty = all_preds.std(axis=1)
        
        return mean_scores, uncertainty
