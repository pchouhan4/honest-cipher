"""
nonce_reuse_differential.py -- tests whether nonce reuse leaks information
through H.O.N.E.S.T.'s diffusion + rewrite pipeline (docs/open_problems.md
Problem 2, flagged "not analyzed" as of commit e44f2cf).

Threat model: attacker has two-plus ciphertexts under the same secret key
and an accidentally-reused nonce (RNG fault -- nonces aren't attacker-chosen
in the current design), and knows the plaintext of the reused-nonce
messages. Under reuse, entropy = HMAC(key_hash, nonce) and the diffusion
seed are identical across both messages, so the attacker-known plaintext
difference Delta_in = raw(m1) XOR raw(m2) is computable for free (the
shared mask cancels algebraically) -- the open question is whether that
predicts anything about the observed ciphertext difference Delta_out.

Run: python3 docs/experiments/nonce_reuse_differential.py
     (run from the repo root, or see the sys.path line below)
"""
from __future__ import annotations
import sys
import os
import hashlib
import secrets
import random
import statistics

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from honest.cipher import HonestCipher
from honest.encoding import entropy_from_key_and_nonce, _BITS_TO_GEN, _GEN_TO_BITS
from honest.diffusion import diffuse, diffusion_key_seed


def mask_gens_for(entropy: bytes, n: int) -> list[int]:
    """Length-bounded reimplementation of encoding._derive_start_and_mask's
    mask stream. That function always generates a full 64KB keystream
    (2048 SHA-256 calls) regardless of n -- fine for a single encrypt call,
    prohibitively slow at the sample counts this experiment needs. Same
    derivation, just stopped as soon as n generators' worth exist."""
    mask_bytes = b""
    counter = 0
    while len(mask_bytes) < (n // 4 + 1):
        mask_bytes += hashlib.sha256(entropy + counter.to_bytes(4, "big")).digest()
        counter += 1
    out = []
    for byte in mask_bytes:
        for shift in range(4):
            out.append((byte >> (shift * 2)) & 0b11)
            if len(out) >= n:
                return out
    return out


def encrypt_raw_walk(cipher: HonestCipher, raw_walk: list[int], nonce: bytes) -> list[int]:
    """Replicates HonestCipher.encrypt()'s pipeline for an attacker-chosen
    nonce, operating directly on a raw generator walk (bypasses the byte
    encoder so a single generator position can be flipped cleanly).
    Verified during design to produce identical output to cipher.encrypt()
    when given the same nonce, message, and key."""
    entropy = entropy_from_key_and_nonce(cipher.key_hash, nonce)
    mask_gens = mask_gens_for(entropy, len(raw_walk))
    masked = [((_GEN_TO_BITS[g] ^ mask_gens[i]) & 0b11) for i, g in enumerate(raw_walk)]
    walk = [_BITS_TO_GEN[m] for m in masked]
    if cipher.use_diffusion:
        dseed = diffusion_key_seed(cipher.key_hash, nonce)
        walk = diffuse(walk, dseed)
    return cipher.key.rewrite(walk)


def single_flip_trial(
    cipher: HonestCipher, walk_len: int, flip_pos: int, rng: random.Random
) -> tuple[float, float]:
    """One (key, message-pair) sample. Returns (reused_diff_fraction,
    fresh_diff_fraction): the fraction of ciphertext-walk positions that
    differ between two messages differing at exactly one generator
    position, under a shared (reused) nonce vs. under independent fresh
    nonces (the normal, no-correlation-expected case)."""
    w1 = [rng.randint(1, 4) for _ in range(walk_len)]
    w2 = list(w1)
    w2[flip_pos] = (w2[flip_pos] % 4) + 1

    reused_nonce = secrets.token_bytes(16)
    c1 = encrypt_raw_walk(cipher, w1, reused_nonce)
    c2 = encrypt_raw_walk(cipher, w2, reused_nonce)
    reused_frac = sum(a != b for a, b in zip(c1, c2)) / walk_len

    n1, n2 = secrets.token_bytes(16), secrets.token_bytes(16)
    f1 = encrypt_raw_walk(cipher, w1, n1)
    f2 = encrypt_raw_walk(cipher, w2, n2)
    fresh_frac = sum(a != b for a, b in zip(f1, f2)) / walk_len

    return reused_frac, fresh_frac


def run_sweep(
    positions: list[int],
    n_keys: int,
    pairs_per_key: int,
    mode: str,
    seed: int,
) -> dict[int, dict]:
    """Runs the reused-vs-fresh comparison across several walk positions.
    A fresh key is generated per key-batch (averaging over keyspace, not
    one lucky/unlucky key); each key is reused across pairs_per_key
    message-pairs for speed. WALK_LEN=80 matches the length used in the
    existing diffusion avalanche sweep (docs/construction.md section 6)
    for direct comparability."""
    WALK_LEN = 80
    rng = random.Random(seed)
    results: dict[int, dict] = {}
    for pos in positions:
        reused, fresh = [], []
        for _ in range(n_keys):
            cipher = HonestCipher.generate(mode=mode)
            for _ in range(pairs_per_key):
                r, f = single_flip_trial(cipher, WALK_LEN, pos, rng)
                reused.append(r)
                fresh.append(f)
        vr, vf = statistics.variance(reused), statistics.variance(fresh)
        results[pos] = {
            "reused_mean": statistics.mean(reused),
            "reused_var": vr,
            "fresh_mean": statistics.mean(fresh),
            "fresh_var": vf,
            "f_ratio": vr / vf,
            "n": len(reused),
        }
    return results


def print_sweep(results: dict[int, dict], label: str) -> None:
    print(f"--- {label} ---")
    for pos, r in results.items():
        print(f"pos={pos:3d}  reused mean={r['reused_mean']:.3f} var={r['reused_var']:.4f}  "
              f"|  fresh mean={r['fresh_mean']:.3f} var={r['fresh_var']:.4f}  "
              f"|  F={r['f_ratio']:.2f}  n={r['n']}")


if __name__ == "__main__":
    print("=" * 70)
    print("Nonce-reuse differential leakage test")
    print("=" * 70)
    print()
    print("block mode (fast keygen, isolates the diffuse() mechanism under test):")
    block_results = run_sweep(
        positions=[2, 20, 40, 60, 70, 78], n_keys=300, pairs_per_key=20,
        mode="block", seed=7,
    )
    print_sweep(block_results, "block mode, n_keys=300, pairs_per_key=20")
    print()
    print("kb mode (the actual default cipher configuration, smaller n -- KB keygen is slower):")
    kb_results = run_sweep(
        positions=[2, 40, 60, 78], n_keys=30, pairs_per_key=15,
        mode="kb", seed=11,
    )
    print_sweep(kb_results, "kb mode, n_keys=30, pairs_per_key=15")

    # Self-check: structural correctness, not the security conclusion.
    for results in (block_results, kb_results):
        for pos, r in results.items():
            assert 0.0 <= r["reused_mean"] <= 1.0
            assert 0.0 <= r["fresh_mean"] <= 1.0
            assert r["n"] > 0
            assert 0.6 < r["fresh_mean"] < 0.9, (
                f"fresh-nonce baseline at pos={pos} outside the range measured "
                f"in docs/construction.md section 6 (mean avalanche ~72-76%) "
                f"-- investigate before trusting the reused-nonce comparison"
            )
    print()
    print("Self-check passed: fresh-nonce control matches the documented "
          "baseline avalanche range at every position tested.")

    # Secondary check (per the approved spec's "statistical sanity check"):
    # many known plaintexts under ONE reused nonce -- does the aggregate
    # ciphertext-pair frequency distribution skew beyond the fresh-nonce
    # baseline already measured in known_plaintext_pair_recovery.py
    # (chi^2=22.96, 15 dof, 500 messages)? Complements the pairwise
    # differential result above with an aggregate/codebook-style view.
    print()
    print("--- secondary check: pair-frequency under one reused nonce (codebook-style) ---")
    import collections
    import itertools

    codebook_cipher = HonestCipher.generate(mode="kb")
    reused_nonce = secrets.token_bytes(16)
    pair_counts: collections.Counter = collections.Counter()
    total_pairs = 0
    codebook_rng = random.Random(99)
    for _ in range(500):
        walk = [codebook_rng.randint(1, 4) for _ in range(80)]
        ct = encrypt_raw_walk(codebook_cipher, walk, reused_nonce)
        for i in range(0, len(ct) - 1, 2):
            pair_counts[(ct[i], ct[i + 1])] += 1
            total_pairs += 1
    expected = total_pairs / 16
    all_pairs = set(itertools.product(range(1, 5), range(1, 5)))
    chi2 = sum((pair_counts.get(p, 0) - expected) ** 2 / expected for p in all_pairs)
    print(f"500 messages, one reused nonce: chi^2 = {chi2:.2f} on 15 dof "
          f"(fresh-nonce baseline from known_plaintext_pair_recovery.py: 22.96)")
    print("VERDICT:", "consistent with the fresh-nonce baseline -- no aggregate "
          "frequency bias detected from reuse alone" if chi2 < 40.0 else
          "elevated beyond the fresh-nonce baseline -- aggregate bias detected")
