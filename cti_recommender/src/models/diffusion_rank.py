"""
DiffusionRank Algorithm

Random walk with restart for vulnerability priority score propagation on graphs.
Useful for leveraging structural relationships between CVEs.
"""

from typing import Dict, Optional
import numpy as np
import networkx as nx
from scipy.sparse import csr_matrix


def diffusion_rank(
    G: nx.Graph,
    seed_scores: Dict[str, float],
    alpha: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6,
    verbose: bool = False
) -> Dict[str, float]:
    """
    DiffusionRank: Random walk with restart for priority score propagation.
    
    Similar to PageRank, but with personalized restart probabilities based on
    seed scores from another model (e.g., LambdaRank predictions).
    
    Algorithm:
    1. Start with seed scores as initial distribution
    2. At each step:
       - With probability (1-alpha): Follow edges to similar nodes
       - With probability alpha: Restart from seed distribution
    3. Iterate until convergence
    
    Args:
        G: NetworkX graph (typically CVE similarity graph)
        seed_scores: Dict mapping node IDs to initial scores
        alpha: Restart probability [0, 1]. Higher = more influence from seeds.
               Typical values: 0.85 (PageRank default), 0.9 (high personalization)
        max_iter: Maximum iterations for convergence
        tol: Convergence tolerance (L1 norm difference)
        verbose: Print convergence progress
    
    Returns:
        Dict mapping node IDs to diffusion scores
    
    Example:
        >>> G = nx.karate_club_graph()
        >>> seed_scores = {0: 1.0, 33: 0.5}  # Two seed nodes
        >>> scores = diffusion_rank(G, seed_scores, alpha=0.85)
        >>> top_nodes = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:5]
    """
    if len(G) == 0:
        return {}
    
    nodes = list(G.nodes())
    n = len(nodes)
    node_to_idx = {node: i for i, node in enumerate(nodes)}
    
    # Initialize seed vector
    seed_vector = np.zeros(n)
    for node, score in seed_scores.items():
        if node in node_to_idx:
            seed_vector[node_to_idx[node]] = score
    
    # Normalize seed vector
    seed_sum = seed_vector.sum()
    if seed_sum > 0:
        seed_vector = seed_vector / seed_sum
    else:
        # No seeds provided, use uniform distribution
        seed_vector = np.ones(n) / n
    
    # Build transition matrix
    adj_matrix = nx.to_numpy_array(G, nodelist=nodes, weight='weight')
    row_sums = adj_matrix.sum(axis=1, keepdims=True)
    row_sums[row_sums == 0] = 1  # Handle nodes with no outgoing edges
    transition_matrix = adj_matrix / row_sums
    
    # Initialize rank vector
    rank_vector = seed_vector.copy()
    
    # Iterative propagation (power iteration)
    for iteration in range(max_iter):
        # PageRank-style update:
        # r_new = (1 - alpha) * M^T * r + alpha * seed
        rank_vector_new = (1 - alpha) * transition_matrix.T @ rank_vector + alpha * seed_vector
        
        # Check convergence
        diff = np.abs(rank_vector_new - rank_vector).sum()
        if verbose and (iteration + 1) % 10 == 0:
            print(f"  Iteration {iteration+1}: L1 diff = {diff:.8f}")
        
        if diff < tol:
            if verbose:
                print(f"  Converged after {iteration+1} iterations")
            break
        
        rank_vector = rank_vector_new
    else:
        if verbose:
            print(f"  Warning: Did not converge after {max_iter} iterations")
    
    # Convert back to dict
    scores = {nodes[i]: float(rank_vector[i]) for i in range(n)}
    return scores


def personalized_pagerank(
    G: nx.Graph,
    personalization: Dict[str, float],
    alpha: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6
) -> Dict[str, float]:
    """
    Wrapper for NetworkX's personalized PageRank (alternative to diffusion_rank).
    
    Uses NetworkX's optimized implementation with sparse matrices.
    
    Args:
        G: NetworkX graph
        personalization: Dict of {node: weight} for restart distribution
        alpha: Damping parameter (1 - restart probability)
        max_iter: Maximum iterations
        tol: Convergence tolerance
    
    Returns:
        Dict of {node: pagerank_score}
    """
    try:
        scores = nx.pagerank(
            G,
            alpha=alpha,
            personalization=personalization,
            max_iter=max_iter,
            tol=tol,
            weight='weight'
        )
        return scores
    except:
        # Fallback to our implementation if NetworkX fails
        return diffusion_rank(G, personalization, alpha, max_iter, tol)


def batch_diffusion_rank(
    G: nx.Graph,
    seed_score_batches: list[Dict[str, float]],
    alpha: float = 0.85,
    max_iter: int = 100,
    tol: float = 1e-6
) -> list[Dict[str, float]]:
    """
    Run DiffusionRank for multiple seed score sets efficiently.
    
    Useful for cross-validation or bootstrap sampling.
    
    Args:
        G: NetworkX graph
        seed_score_batches: List of seed score dicts
        alpha: Restart probability
        max_iter: Maximum iterations
        tol: Convergence tolerance
    
    Returns:
        List of diffusion score dicts (same length as input)
    """
    results = []
    for i, seed_scores in enumerate(seed_score_batches):
        scores = diffusion_rank(G, seed_scores, alpha, max_iter, tol)
        results.append(scores)
    return results


def evaluate_diffusion_quality(
    G: nx.Graph,
    diffusion_scores: Dict[str, float],
    ground_truth_labels: Dict[str, int],
    k: int = 100
) -> Dict[str, float]:
    """
    Evaluate quality of diffusion scores against ground truth.
    
    Args:
        G: NetworkX graph
        diffusion_scores: Output from diffusion_rank()
        ground_truth_labels: Dict of {node: priority_label}
        k: Top-k for evaluation
    
    Returns:
        Dict of evaluation metrics
    """
    # Get top-k nodes by diffusion score
    sorted_nodes = sorted(diffusion_scores.items(), key=lambda x: x[1], reverse=True)
    top_k_nodes = [node for node, score in sorted_nodes[:k]]
    
    # Calculate metrics
    top_k_labels = [ground_truth_labels.get(node, 0) for node in top_k_nodes]
    high_priority_count = sum(1 for label in top_k_labels if label >= 3)
    
    metrics = {
        'precision_at_k': high_priority_count / k,
        'avg_label': np.mean(top_k_labels),
        'coverage': len([n for n in top_k_nodes if n in ground_truth_labels]) / k
    }
    
    return metrics


# Example usage and testing
if __name__ == "__main__":
    # Create a simple test graph
    G = nx.karate_club_graph()
    
    # Define seed scores (e.g., from another model)
    seed_scores = {0: 1.0, 33: 0.8, 1: 0.6}
    
    # Run DiffusionRank
    print("Running DiffusionRank on Karate Club graph...")
    scores = diffusion_rank(G, seed_scores, alpha=0.85, verbose=True)
    
    # Show top-10 nodes
    top_10 = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:10]
    print("\nTop-10 nodes by DiffusionRank score:")
    for node, score in top_10:
        print(f"  Node {node:2d}: {score:.6f}")
    
    # Compare with standard PageRank
    pr_scores = nx.pagerank(G)
    print("\nTop-10 nodes by standard PageRank:")
    top_10_pr = sorted(pr_scores.items(), key=lambda x: x[1], reverse=True)[:10]
    for node, score in top_10_pr:
        print(f"  Node {node:2d}: {score:.6f}")
