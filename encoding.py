"""
encoding.py — Plaintext ↔ Walk codec for H.O.N.E.S.T.

Encodes bytes as a walk over Σ = {1,2,3,4} using 2 bits per generator
(since log₂(4) = 2), with entropy injection via a seed.

Each byte = 4 generators (8 bits / 2 bits per generator).
The entropy seed determines the starting node and a per-block XOR mask
that randomizes the walk without changing decodability (given the seed).

Message format:
  [4-byte length] [plaintext bytes] [padding to block boundary]

This is a sketch-level encoding — not PKCS#7, not OAEP.
Proper padding is future work.
"""

from __future__ import annotations
import hashlib
import hmac
import struct
from .hypercube import apply_walk, N_VERTICES

# 2 bits per generator step → 4 steps per byte
BITS_PER_GEN = 2
GENS_PER_BYTE = 8 // BITS_PER_GEN  # = 4

# Map 2-bit values to generators 1..4
_BITS_TO_GEN = {0b00: 1, 0b01: 2, 0b10: 3, 0b11: 4}
_GEN_TO_BITS = {v: k for k, v in _BITS_TO_GEN.items()}


def _derive_start_and_mask(entropy: bytes) -> tuple[int, list[int]]:
    """
    Derive starting node and per-generator entropy mask from entropy seed.
    Uses SHA-256 to expand entropy.
    """
    h = hashlib.sha256(entropy).digest()
    start_node = h[0] % N_VERTICES
    # Expand to a long mask stream via repeated hashing
    mask_bytes = b""
    counter = 0
    while len(mask_bytes) < 65536:  # supports up to ~16KB messages
        mask_bytes += hashlib.sha256(entropy + counter.to_bytes(4, 'big')).digest()
        counter += 1
    # Each mask byte gives 4 generator offsets (2 bits each)
    mask_gens = []
    for byte in mask_bytes:
        for shift in range(4):
            bits = (byte >> (shift * 2)) & 0b11
            mask_gens.append(bits)
    return start_node, mask_gens


def encode(plaintext: bytes, entropy: bytes) -> tuple[int, list[int]]:
    """
    Encode plaintext bytes into (start_node, walk).
    
    Process:
      1. Prepend 4-byte length header
      2. Convert each byte to 4 generator steps (2 bits each)
      3. XOR each generator's 2-bit index with entropy mask (mod 4)
         → randomizes walk without losing decodability
      4. Return starting node + walk
    """
    start_node, mask_gens = _derive_start_and_mask(entropy)

    # Prepend length so decoder knows where message ends
    payload = struct.pack('>I', len(plaintext)) + plaintext

    walk = []
    for i, byte in enumerate(payload):
        for shift in range(3, -1, -1):  # high bits first
            bits = (byte >> (shift * 2)) & 0b11
            # Apply entropy mask: XOR the 2-bit value mod 4
            masked_bits = (bits ^ mask_gens[len(walk)]) & 0b11
            walk.append(_BITS_TO_GEN[masked_bits])

    return start_node, walk


def decode(start_node: int, walk: list[int], entropy: bytes) -> bytes:
    """
    Decode a walk back to plaintext bytes using the same entropy seed.
    
    Reverses the entropy masking, then converts generators back to bytes.
    """
    _, mask_gens = _derive_start_and_mask(entropy)

    bits_buffer = 0
    bit_count = 0
    payload = bytearray()

    for i, gen in enumerate(walk):
        gen_bits = _GEN_TO_BITS[gen]
        # Reverse entropy mask
        unmasked = (gen_bits ^ mask_gens[i]) & 0b11
        bits_buffer = (bits_buffer << 2) | unmasked
        bit_count += 2
        if bit_count == 8:
            payload.append(bits_buffer & 0xFF)
            bits_buffer = 0
            bit_count = 0

    if len(payload) < 4:
        raise ValueError("Decoded payload too short to contain length header")

    # Extract length header
    length = struct.unpack('>I', bytes(payload[:4]))[0]
    plaintext = bytes(payload[4:4 + length])
    return plaintext


def entropy_from_key_and_nonce(key_hash: bytes, nonce: bytes) -> bytes:
    """Derive per-message entropy from key material + nonce.

    Uses HMAC-SHA256(key=key_hash, msg=nonce) rather than SHA-256(key_hash || nonce).
    HMAC is the correct construction for a keyed hash: it avoids length-extension
    properties of raw Merkle-Damgard and matches the pattern already used in diffusion.py.
    """
    return hmac.new(key_hash, nonce, hashlib.sha256).digest()


# ── Sanity checks ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Encoding — sanity checks")

    import secrets
    entropy = secrets.token_bytes(32)
    messages = [
        b"Hello",
        b"Post-quantum",
        b"A" * 100,
        b"\x00\xff\xab\xcd",
    ]

    for msg in messages:
        start, walk = encode(msg, entropy)
        recovered = decode(start, walk, entropy)
        assert recovered == msg, f"Roundtrip failed for {msg!r}"
        print(f"  '{msg[:20]}...' ({len(msg)}B) → walk len {len(walk)} → recovered OK")

    print("\n  All roundtrip checks passed ✓")
    print(f"  Walk length = {GENS_PER_BYTE} × (4 + msg_len) generators per byte overhead")
