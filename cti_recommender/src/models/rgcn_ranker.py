"""
RGCN Relational Model for CVE-Vendor Graph

Implements a simplified Relational Graph Convolutional Network.
"""
import re
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
from typing import List, Tuple, Dict


def extract_vendor_from_description(description: str) -> str:
    """Extract vendor name from CVE description."""
    if pd.isna(description) or not description:
        return "unknown_vendor"
    
    description = str(description).lower()
    
    patterns = [
        r'^([a-zA-Z0-9_\-]+)\s+(?:before|through|prior)',
        r'in\s+([a-zA-Z0-9_\-]+)\s+(?:version|v\d)',
        r'([a-zA-Z0-9_\-]+)\s+(?:allows|has|contains)',
        r'^([a-zA-Z0-9_\-]+)\s+\d+\.',
    ]
    
    for pattern in patterns:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            vendor = match.group(1).strip()
            if len(vendor) >= 2 and vendor not in ['the', 'a', 'an', 'in', 'on']:
                return vendor.lower()
    
    words = description.split()
    if words:
        first_word = re.sub(r'[^a-zA-Z0-9]', '', words[0])
        if len(first_word) >= 2:
            return first_word.lower()
    
    return "unknown_vendor"


class SimpleRGCN(nn.Module):
    """Simplified RGCN for CVE-Vendor graph."""
    
    def __init__(self, cve_dim: int, vendor_dim: int, hidden_dim: int = 64, 
                 output_dim: int = 1, num_layers: int = 2):
        super().__init__()
        
        self.hidden_dim = hidden_dim
        
        self.cve_proj = nn.Linear(cve_dim, hidden_dim)
        self.vendor_proj = nn.Linear(vendor_dim, hidden_dim)
        
        self.cve_to_vendor = nn.ModuleList([
            nn.Linear(hidden_dim, hidden_dim) for _ in range(num_layers)
        ])
        self.vendor_to_cve = nn.ModuleList([
            nn.Linear(hidden_dim, hidden_dim) for _ in range(num_layers)
        ])
        
        self.cve_update = nn.ModuleList([
            nn.Linear(hidden_dim * 2, hidden_dim) for _ in range(num_layers)
        ])
        self.vendor_update = nn.ModuleList([
            nn.Linear(hidden_dim * 2, hidden_dim) for _ in range(num_layers)
        ])
        
        self.output = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim, output_dim)
        )
        
        self.num_layers = num_layers
    
    def forward(self, cve_features: torch.Tensor, vendor_features: torch.Tensor,
                cve_to_vendor_idx: torch.Tensor, vendor_to_cve_idx: torch.Tensor) -> torch.Tensor:
        
        h_cve = F.relu(self.cve_proj(cve_features))
        h_vendor = F.relu(self.vendor_proj(vendor_features))
        
        num_cves = cve_features.size(0)
        num_vendors = vendor_features.size(0)
        
        for layer in range(self.num_layers):
            vendor_msgs = self.cve_to_vendor[layer](h_vendor)
            cve_agg = torch.zeros(num_cves, self.hidden_dim, device=cve_features.device)
            if cve_to_vendor_idx.size(1) > 0:
                cve_idx = cve_to_vendor_idx[0]
                vendor_idx = cve_to_vendor_idx[1]
                cve_agg.index_add_(0, cve_idx, vendor_msgs[vendor_idx])
            
            cve_msgs = self.vendor_to_cve[layer](h_cve)
            vendor_agg = torch.zeros(num_vendors, self.hidden_dim, device=vendor_features.device)
            if vendor_to_cve_idx.size(1) > 0:
                vendor_idx = vendor_to_cve_idx[0]
                cve_idx = vendor_to_cve_idx[1]
                vendor_agg.index_add_(0, vendor_idx, cve_msgs[cve_idx])
            
            h_cve = F.relu(self.cve_update[layer](torch.cat([h_cve, cve_agg], dim=-1)))
            h_vendor = F.relu(self.vendor_update[layer](torch.cat([h_vendor, vendor_agg], dim=-1)))
        
        return self.output(h_cve)


class RGCNRanker:
    """RGCN-based ranker for CVE prioritization."""
    
    def __init__(self, cve_dim: int, hidden_dim: int = 64, num_layers: int = 2,
                 lr: float = 1e-3, device: str = 'cpu'):
        self.device = device
        self.cve_dim = cve_dim
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.lr = lr
        
        self.cve_scaler = StandardScaler()
        self.vendor_to_idx = {}
        self.vendor_features = None
        self.model = None
    
    def _build_graph(self, df: pd.DataFrame, feature_cols: List[str], 
                     is_train: bool = True) -> Tuple[torch.Tensor, torch.Tensor, 
                                                      torch.Tensor, torch.Tensor, List[str]]:
        """Build CVE-Vendor graph."""
        vendors = df['description'].apply(extract_vendor_from_description).tolist()
        
        if is_train:
            unique_vendors = list(set(vendors))
            self.vendor_to_idx = {v: i for i, v in enumerate(unique_vendors)}
        
        unknown_idx = self.vendor_to_idx.get('unknown_vendor', 0)
        vendor_indices = [self.vendor_to_idx.get(v, unknown_idx) for v in vendors]
        
        cve_features = df[feature_cols].values.astype(np.float32)
        if is_train:
            cve_features = self.cve_scaler.fit_transform(cve_features)
        else:
            cve_features = self.cve_scaler.transform(cve_features)
        
        cve_features_t = torch.tensor(cve_features, dtype=torch.float32, device=self.device)
        
        num_vendors = len(self.vendor_to_idx)
        if is_train:
            vendor_stats = defaultdict(list)
            for i, vid in enumerate(vendor_indices):
                vendor_stats[vid].append(cve_features[i])
            
            vendor_features = np.zeros((num_vendors, cve_features.shape[1]), dtype=np.float32)
            for vid, feats in vendor_stats.items():
                vendor_features[vid] = np.mean(feats, axis=0)
            
            self.vendor_features = vendor_features
        
        vendor_features_t = torch.tensor(self.vendor_features, dtype=torch.float32, device=self.device)
        
        cve_indices = list(range(len(df)))
        cve_to_vendor = torch.tensor([cve_indices, vendor_indices], dtype=torch.long, device=self.device)
        vendor_to_cve = torch.tensor([vendor_indices, cve_indices], dtype=torch.long, device=self.device)
        
        return cve_features_t, vendor_features_t, cve_to_vendor, vendor_to_cve, vendors
    
    def train_quick(self, train_df: pd.DataFrame, feature_cols: List[str],
                    epochs: int = 5, verbose: bool = True) -> Dict[str, float]:
        """Quick training for comparison study."""
        cve_t, vendor_t, c2v, v2c, _ = self._build_graph(train_df, feature_cols, is_train=True)
        
        if verbose:
            print(f"  Graph: {cve_t.shape[0]} CVEs, {vendor_t.shape[0]} vendors", flush=True)
        
        y = torch.tensor(train_df['soft_label'].values, dtype=torch.float32, 
                        device=self.device).unsqueeze(-1)
        
        self.model = SimpleRGCN(
            cve_dim=len(feature_cols), vendor_dim=len(feature_cols),
            hidden_dim=self.hidden_dim, output_dim=1, num_layers=self.num_layers
        ).to(self.device)
        
        opt = torch.optim.AdamW(self.model.parameters(), lr=self.lr)
        
        losses = []
        for ep in range(epochs):
            self.model.train()
            pred = self.model(cve_t, vendor_t, c2v, v2c)
            loss = F.mse_loss(pred, y)
            opt.zero_grad()
            loss.backward()
            opt.step()
            losses.append(loss.item())
            if verbose:
                print(f"  Ep {ep+1}/{epochs}: {loss.item():.4f}", flush=True)
        
        return {'final_loss': losses[-1], 'losses': losses}
    
    def predict(self, df: pd.DataFrame, feature_cols: List[str]) -> np.ndarray:
        """Get ranking scores."""
        self.model.eval()
        cve_t, vendor_t, c2v, v2c, _ = self._build_graph(df, feature_cols, is_train=False)
        
        with torch.no_grad():
            scores = self.model(cve_t, vendor_t, c2v, v2c)
        
        return scores.cpu().numpy().flatten()
