"""
H.O.N.E.S.T. — Hypercube-Oriented Nonlinear Encryption with Structured Trapdoors

A research-stage cipher exploring rewriting-system based cryptography.
NOT for production use. See README for full scope and limitations.
"""

from .cipher import HonestCipher
from .rewriter import generate_key, export_key, import_key
from .hypercube import apply_walk, walk_endpoint, node_to_bits

__version__ = "0.1.0-research"
__author__ = "Puru"
__status__ = "Research Prototype"

__all__ = [
    "HonestCipher",
    "generate_key",
    "export_key", 
    "import_key",
    "apply_walk",
    "walk_endpoint",
    "node_to_bits",
]
