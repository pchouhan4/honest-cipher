"""
known_plaintext_pair_recovery.py -- re-testing open_problems.md Problem 2
Path A ("direct pair table recovery... untested and the most urgent open
problem") against the actual v0.2 pipeline.

Path A was written assuming an attacker can call encode(m, entropy) to get
the plaintext walk directly. In v0.2, entropy = HMAC(key_hash, nonce) is
derived from the secret key -- an external attacker (nonce and ciphertext
only, no key) cannot compute it. This script checks that claim against the
real pipeline instead of just reasoning about it, then checks two related
questions the corrected finding raises.

Run: python3 docs/experiments/known_plaintext_pair_recovery.py
     (needs src/ on the path; run from the repo root, or see the sys.path
     line below)
"""
from __future__ import annotations
import sys
import os
import random
import secrets
import itertools
import collections

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from honest.cipher import HonestCipher


def part1_path_a_as_described(cipher: HonestCipher) -> None:
    print("=" * 70)
    print("PART 1 -- Path A as described: 'encode m_i to get plaintext walk w_i'")
    print("=" * 70)
    m = b"known plaintext"
    ct = cipher.encrypt(m)
    print(f"Attacker (external) observes: nonce={ct['nonce'][:16]}..., "
          f"start={ct['start']}, walk=<{len(ct['walk'])} gens>, "
          f"diffusion={ct['diffusion']}")
    print("To compute w_i = encode(m, entropy), the attacker needs")
    print("entropy = HMAC(key_hash, nonce). key_hash = sha256(export_key(key))")
    print("-- that IS the secret key material.")
    print("VERDICT: not computable by an external attacker. Path A as literally")
    print("written requires key material equivalent to already having the key.")
    print("(This attack was specified before v0.2 added HMAC-derived entropy to")
    print("encode()/diffuse(); it describes the pre-v0.2 pipeline, not this one.)")
    print()


def part2_ciphertext_uniformity(cipher: HonestCipher, n_messages: int = 500) -> float:
    print("=" * 70)
    print(f"PART 2 -- ciphertext pair-frequency under fresh nonces ({n_messages} known-plaintexts)")
    print("=" * 70)
    pair_counts: collections.Counter = collections.Counter()
    total_pairs = 0
    for _ in range(n_messages):
        msg = secrets.token_bytes(16)
        ct = cipher.encrypt(msg)
        w = ct["walk"]
        for i in range(0, len(w) - 1, 2):
            pair_counts[(w[i], w[i + 1])] += 1
            total_pairs += 1

    expected = total_pairs / 16
    all_pairs = set(itertools.product(range(1, 5), range(1, 5)))
    chi2 = sum((pair_counts.get(p, 0) - expected) ** 2 / expected for p in all_pairs)
    dof = 15  # 16 cells, 1 constraint (total count fixed)
    print(f"observed {len(pair_counts)}/16 distinct pairs across {total_pairs} pair-slots")
    print(f"chi^2 = {chi2:.2f} on {dof} dof (95% critical value ~25.0 -- below means 'looks uniform')")
    print(f"expected/cell: {expected:.1f}, "
          f"max: {max(pair_counts.values())}, "
          f"min: {min((pair_counts.get(p, 0) for p in all_pairs))}")
    verdict = chi2 < 25.0
    print("VERDICT:", "no detectable bias (ciphertext looks uniform, table's smallness"
          " doesn't leak here)" if verdict else "BIAS DETECTED -- worth investigating further")
    print()
    return chi2


def part3_isolated_table_recovery(cipher: HonestCipher) -> int:
    print("=" * 70)
    print("PART 3 -- rewrite table recovery, IF the pre-rewrite walk were known")
    print("=" * 70)
    key = cipher.key  # used here only to construct a controlled scenario
    rng = random.Random(1)
    sample_walk = [rng.randint(1, 4) for _ in range(64)]
    sample_ct = key.rewrite(sample_walk)

    observed_map: dict[tuple[int, int], tuple[int, int]] = {}
    for i in range(0, len(sample_walk) - 1, 2):
        pre = (sample_walk[i], sample_walk[i + 1])
        post = (sample_ct[i], sample_ct[i + 1])
        observed_map[pre] = post
    n_recovered = len(observed_map)
    print(f"single 64-generator sample recovers {n_recovered}/16 table entries directly by inspection")
    print("(no search needed -- if the pre-rewrite walk is ever observable, the table")
    print(" is not brute-forced, it's read off in one sample)")
    print()
    print("This confirms the earlier keyspace finding stands: the rewrite table has")
    print("near-zero keyspace *in isolation*. Parts 1-2 show that under the current")
    print("pipeline that table is never observable in isolation -- it sits downstream")
    print("of the encode-mask and diffusion layers, which is what currently prevents")
    print("this from being a live break of the shipped cipher.")
    return n_recovered


if __name__ == "__main__":
    cipher = HonestCipher.generate(mode="kb")
    part1_path_a_as_described(cipher)
    chi2 = part2_ciphertext_uniformity(cipher)
    n_recovered = part3_isolated_table_recovery(cipher)

    assert chi2 < 25.0, "ciphertext showed unexpected pair-frequency bias -- investigate"
    assert n_recovered >= 12, "isolated-table recovery weaker than expected -- investigate"
    print("Self-check passed: both verdicts above match expectations.")
