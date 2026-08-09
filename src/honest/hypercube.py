"""
hypercube.py — Q₄ graph and walk engine for H.O.N.E.S.T.

The 4D hypercube Q₄:
  - 16 vertices: all 4-bit binary strings (0..15)
  - 4 generators: σ₁..σ₄, each flips one bit (XOR masks 1,2,4,8)
  - Edge (u,v) exists iff u XOR v is a power of 2

Walks are sequences of generator indices (1..4).
Applying a walk to a starting node is O(n) — just XOR each mask.
"""

from __future__ import annotations
from typing import Sequence

# Generator index → XOR bitmask
# σ₁ flips bit 0, σ₂ flips bit 1, etc.
GENERATORS: dict[int, int] = {1: 0b0001, 2: 0b0010, 3: 0b0100, 4: 0b1000}
GEN_SET = frozenset(GENERATORS.keys())
N_VERTICES = 16  # |V(Q₄)| = 2⁴


def apply_generator(node: int, gen: int) -> int:
    """Apply generator σ_gen to node. Returns new node."""
    if gen not in GENERATORS:
        raise ValueError(f"Generator must be in {{1,2,3,4}}, got {gen}")
    return node ^ GENERATORS[gen]


def apply_walk(start: int, walk: Sequence[int]) -> int:
    """
    Apply a sequence of generators to start node.
    Result = start XOR (XOR of all masks in walk).
    O(n) — and because XOR is associative, order only matters for
    the rewriting system, not for endpoint computation.
    """
    node = start
    for gen in walk:
        node = apply_generator(node, gen)
    return node


def walk_endpoint(start: int, walk: Sequence[int]) -> int:
    """Alias for apply_walk. Explicit that we only want the endpoint."""
    return apply_walk(start, walk)


def neighbors(node: int) -> dict[int, int]:
    """Return {generator: neighbor_node} for all 4 generators."""
    return {gen: node ^ mask for gen, mask in GENERATORS.items()}


def node_to_bits(node: int) -> str:
    """Format node as 4-bit binary string."""
    return format(node, '04b')


def walk_to_str(walk: Sequence[int]) -> str:
    """Format walk as 'σ₁σ₃σ₂...' for display."""
    superscripts = {1: '₁', 2: '₂', 3: '₃', 4: '₄'}
    return ''.join(f"σ{superscripts[g]}" for g in walk)


def verify_walk(start: int, walk: Sequence[int], expected_end: int) -> bool:
    """Check that walk leads from start to expected_end."""
    return apply_walk(start, walk) == expected_end


def adjacency_list() -> dict[int, list[int]]:
    """Full adjacency list of Q₄ for reference."""
    return {v: [v ^ mask for mask in GENERATORS.values()] for v in range(N_VERTICES)}


# ── Sanity checks ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Q₄ Hypercube — sanity checks")
    print(f"  Vertices: {N_VERTICES}")
    print(f"  Each vertex degree: 4")

    # Every vertex should have exactly 4 neighbors
    adj = adjacency_list()
    assert all(len(nbrs) == 4 for nbrs in adj.values()), "Degree check failed"

    # Walk of [1,1] should be identity (flipping same bit twice)
    assert apply_walk(0b0101, [1, 1]) == 0b0101, "Double-flip identity failed"

    # XOR commutativity: [1,2] and [2,1] lead to the same endpoint
    assert walk_endpoint(0, [1, 2]) == walk_endpoint(0, [2, 1]), "Endpoint commutativity failed"

    # But [1,2] != [2,1] as walks (important: the graph fools you into thinking order matters)
    # Order matters for the rewriting system, not for Q₄ endpoint — this is intentional.

    print("  All checks passed.")
    print(f"\n  Node 0000 neighbors: { {g: node_to_bits(n) for g, n in neighbors(0).items()} }")
    print(f"  Walk [1,2,3,4] from 0000 → {node_to_bits(walk_endpoint(0, [1,2,3,4]))}")
    print(f"  Walk [1,1,2,2] from 0101 → {node_to_bits(walk_endpoint(0b0101, [1,1,2,2]))} (should be 0101)")
