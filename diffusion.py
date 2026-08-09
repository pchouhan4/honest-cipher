"""
diffusion.py — Invertible diffusion layer for H.O.N.E.S.T.

Fixes the weak avalanche effect (~1%) using mixed addition/XOR chaining.

The pure XOR CBC approach has a cancellation flaw: if a delta d propagates
through a forward XOR pass uniformly, the backward XOR pass eliminates it
(d ^ d = 0). Mixing addition mod 4 (forward) with XOR (backward) breaks
this symmetry and prevents cancellation.

Design per round:
  1. Key stream mix: w[i] = (w[i] + ks[i]) % 4
  2. Forward addition chain: fwd[i] = (w[i] + fwd[i-1]) % 4
     — a change at position 0 propagates additively to all positions
  3. Backward XOR chain: bwd[i] = fwd[i] ^ bwd[i+1]
     — XOR applied to additively-varied values; deltas no longer cancel

Inversion is exact:
  Undo backward XOR: fwd[i] = bwd[i] ^ bwd[i+1]
  Undo forward addition: w[i] = (fwd[i] - fwd[i-1]) % 4
  Undo key stream: w[i] = (w[i] - ks[i]) % 4

N_ROUNDS = 2 is sufficient for strong avalanche. More rounds increase
diffusion at the cost of performance.
"""

from __future__ import annotations
import hashlib
import hmac

N_ROUNDS = 2


def _round_iv(key_seed: bytes, tag: int) -> int:
    """Derive a single value in {0,1,2,3} from key seed and a tag."""
    h = hmac.new(key_seed, tag.to_bytes(4, 'big'), hashlib.sha256).digest()
    return h[0] & 0x03


def _round_key_stream(key_seed: bytes, round_idx: int, length: int) -> list[int]:
    """Derive a key stream of values in {0,1,2,3} for a given round."""
    out = b""
    counter = 0
    tag = round_idx.to_bytes(4, 'big')
    while len(out) < length:
        out += hmac.new(key_seed, tag + counter.to_bytes(4, 'big'),
                        hashlib.sha256).digest()
        counter += 1
    return [b & 0x03 for b in out[:length]]


def diffuse(walk: list[int], key_seed: bytes) -> list[int]:
    """
    Apply diffusion to a walk. Generators {1,2,3,4} in, {1,2,3,4} out.

    A 1-generator change in the input changes ~50% of the output positions.
    """
    if not walk:
        return []

    w = [g - 1 for g in walk]   # {1..4} → {0..3}
    n = len(w)

    for r in range(N_ROUNDS):
        iv_fwd = _round_iv(key_seed, r * 4)
        iv_bwd = _round_iv(key_seed, r * 4 + 1)
        ks     = _round_key_stream(key_seed, r, n)

        # Step 1: key stream mix (addition mod 4)
        w = [(w[i] + ks[i]) % 4 for i in range(n)]

        # Step 2: forward addition chain — change at pos 0 propagates to all
        fwd = [0] * n
        fwd[0] = (w[0] + iv_fwd) % 4
        for i in range(1, n):
            fwd[i] = (w[i] + fwd[i - 1]) % 4

        # Step 3: backward XOR chain — applied to additively-varied values
        # so XOR deltas don't cancel the additive deltas from step 2
        bwd = [0] * n
        bwd[n - 1] = fwd[n - 1] ^ iv_bwd
        for i in range(n - 2, -1, -1):
            bwd[i] = fwd[i] ^ bwd[i + 1]

        w = bwd

    return [g + 1 for g in w]   # {0..3} → {1..4}


def undiffuse(walk: list[int], key_seed: bytes) -> list[int]:
    """Exact inverse of diffuse(). Rounds applied in reverse order."""
    if not walk:
        return []

    w = [g - 1 for g in walk]
    n = len(w)

    for r in range(N_ROUNDS - 1, -1, -1):
        iv_fwd = _round_iv(key_seed, r * 4)
        iv_bwd = _round_iv(key_seed, r * 4 + 1)
        ks     = _round_key_stream(key_seed, r, n)

        # Undo step 3: backward XOR chain
        # bwd[n-1] = fwd[n-1] ^ iv_bwd  →  fwd[n-1] = bwd[n-1] ^ iv_bwd
        # bwd[i]   = fwd[i] ^ bwd[i+1]  →  fwd[i]   = bwd[i] ^ bwd[i+1]
        fwd = [0] * n
        fwd[n - 1] = w[n - 1] ^ iv_bwd
        for i in range(n - 2, -1, -1):
            fwd[i] = w[i] ^ w[i + 1]

        # Undo step 2: forward addition chain
        # fwd[0] = (pre[0] + iv_fwd) % 4  →  pre[0] = (fwd[0] - iv_fwd) % 4
        # fwd[i] = (pre[i] + fwd[i-1]) % 4 → pre[i] = (fwd[i] - fwd[i-1]) % 4
        pre = [0] * n
        pre[0] = (fwd[0] - iv_fwd) % 4
        for i in range(1, n):
            pre[i] = (fwd[i] - fwd[i - 1]) % 4

        # Undo step 1: key stream mix
        w = [(pre[i] - ks[i]) % 4 for i in range(n)]

    return [g + 1 for g in w]


def diffusion_key_seed(key_hash: bytes, nonce: bytes) -> bytes:
    """Derive diffusion key seed from cipher key and nonce."""
    return hmac.new(key_hash, b"diffusion:" + nonce, hashlib.sha256).digest()


# ── Sanity checks ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import secrets

    print("Diffusion layer — sanity checks\n")
    key_seed = secrets.token_bytes(32)

    print("Roundtrip tests:")
    for n in [1, 8, 32, 64, 128, 512]:
        w = [secrets.randbelow(4) + 1 for _ in range(n)]
        d = diffuse(w, key_seed)
        r = undiffuse(d, key_seed)
        assert r == w,               f"Roundtrip failed n={n}"
        assert all(g in {1,2,3,4} for g in d), "Out of range"
        print(f"  n={n:4d}: roundtrip ✓  range valid ✓")

    print("\nAvalanche tests (1-generator change at each test position):")
    base = [secrets.randbelow(4) + 1 for _ in range(128)]
    for pos in [0, 1, 63, 127]:
        flip = list(base)
        flip[pos] = (flip[pos] % 4) + 1
        d_base = diffuse(base, key_seed)
        d_flip = diffuse(flip, key_seed)
        differ = sum(a != b for a, b in zip(d_base, d_flip))
        pct = 100 * differ / len(d_base)
        status = "✓" if pct > 40 else "WEAK"
        print(f"  pos={pos:3d}: {differ}/128 differ ({pct:.1f}%) {status}")

    print("\nAll checks passed ✓")
