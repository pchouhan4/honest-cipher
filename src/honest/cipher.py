"""
cipher.py — H.O.N.E.S.T. encrypt / decrypt pipeline

Encryption pipeline:
  1. Generate nonce
  2. Derive entropy from (key_hash, nonce)
  3. Encode plaintext → (start_node, walk)
  4. Diffuse walk (fixes weak avalanche, ~70% diffusion per position change)
  5. Rewrite walk using private key → ciphertext_walk
  6. Output: {nonce, start, walk}

Decryption pipeline:
  1. Derive entropy from (key_hash, nonce)
  2. Inverse-rewrite ciphertext_walk
  3. Undiffuse walk
  4. Decode → plaintext

Mode options:
  mode='kb'    — KB completion trapdoor + diffusion (default)
  mode='block' — block substitution + diffusion
  mode='block_nodiffuse' — block substitution only (backward-compatible, weak avalanche)

Caveats (honest):
  No IND-CPA proof, no MAC, malleable ciphertext, research only.
"""

from __future__ import annotations
import hashlib
import json
import secrets
from .rewriter import RewritingSystem, generate_key, export_key, import_key
from .encoding import encode, decode, entropy_from_key_and_nonce
from .diffusion import diffuse, undiffuse, diffusion_key_seed
from .hypercube import apply_walk


class HonestCipher:
    def __init__(self, key: RewritingSystem, use_diffusion: bool = True):
        self.key = key
        self.use_diffusion = use_diffusion
        key_data = json.dumps(export_key(key), sort_keys=True).encode()
        self.key_hash = hashlib.sha256(key_data).digest()

    def encrypt(self, plaintext: bytes) -> dict:
        nonce = secrets.token_bytes(16)
        entropy = entropy_from_key_and_nonce(self.key_hash, nonce)

        start_node, walk = encode(plaintext, entropy)

        if self.use_diffusion:
            dseed = diffusion_key_seed(self.key_hash, nonce)
            walk = diffuse(walk, dseed)

        ciphertext_walk = self.key.rewrite(walk)

        assert apply_walk(start_node, walk) == apply_walk(start_node, ciphertext_walk), \
            "BUG: rewriting changed walk endpoint"

        return {
            "nonce": nonce.hex(),
            "start": start_node,
            "walk": ciphertext_walk,
            "diffusion": self.use_diffusion,
        }

    def decrypt(self, ciphertext: dict) -> bytes:
        nonce = bytes.fromhex(ciphertext["nonce"])
        start_node = ciphertext["start"]
        ciphertext_walk = ciphertext["walk"]
        had_diffusion = ciphertext.get("diffusion", False)

        entropy = entropy_from_key_and_nonce(self.key_hash, nonce)

        walk = self.key.inverse_rewrite(ciphertext_walk)

        if had_diffusion:
            dseed = diffusion_key_seed(self.key_hash, nonce)
            walk = undiffuse(walk, dseed)

        return decode(start_node, walk, entropy)

    @classmethod
    def generate(cls, mode: str = 'kb') -> 'HonestCipher':
        """Generate a new cipher. mode='kb' or 'block'."""
        key = generate_key(mode=mode)
        return cls(key, use_diffusion=True)

    def export_key(self) -> dict:
        return export_key(self.key)

    @classmethod
    def from_key_dict(cls, key_dict: dict) -> 'HonestCipher':
        key = import_key(key_dict)
        return cls(key, use_diffusion=True)


# ── Sanity checks ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import time
    print("H.O.N.E.S.T. cipher — sanity checks\n")

    for mode in ('block', 'kb'):
        print(f"Mode: {mode}")
        t0 = time.time()
        cipher = HonestCipher.generate(mode=mode)
        t1 = time.time()
        print(f"  keygen: {(t1-t0)*1000:.0f}ms")

        tests = [b"", b"Hello, world!", b"A" * 256, bytes(range(256))]
        for msg in tests:
            ct = cipher.encrypt(msg)
            pt = cipher.decrypt(ct)
            assert pt == msg, f"Roundtrip failed: {msg[:20]!r}"
            print(f"  [{len(msg):4d}B] walk={len(ct['walk']):5d} → OK ✓")

        kd = cipher.export_key()
        c2 = HonestCipher.from_key_dict(kd)
        ct = cipher.encrypt(b"export test")
        assert c2.decrypt(ct) == b"export test"
        print(f"  export/import: OK ✓\n")
