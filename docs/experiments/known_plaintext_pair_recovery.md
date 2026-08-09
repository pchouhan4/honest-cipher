# Experiment: known-plaintext pair-table recovery (re-testing open problem 2, Path A)

**Status:** completed. **Relates to:** open problem 2, Path A.

## What this re-tests

`docs/open_problems.md` Problem 2 Path A was flagged as "untested" and "the most urgent open problem": given known-plaintext pairs, can an attacker directly read off the pair-substitution table by comparing the plaintext walk to the ciphertext walk? Running it against the actual v0.2 pipeline (`docs/experiments/known_plaintext_pair_recovery.py`) instead of just reasoning about it turned up a correction to the record, not a confirmation.

## Result

**Path A as written does not apply to v0.2.** It assumes an attacker can compute `encode(m, entropy)` to get the plaintext walk directly. In v0.2, `entropy = HMAC(key_hash, nonce)` is derived from the secret key. An external attacker — nonce and ciphertext only, no key — cannot compute it; whoever can already has the key. Path A was almost certainly written against the pre-v0.2 pipeline, before HMAC-derived entropy masking was added to `encode()`/`diffuse()`, and was never revisited after that change landed.

That correction doesn't retire the underlying concern (the pair-substitution table's small keyspace), it relocates it. Two follow-up checks against the real pipeline:

1. **Ciphertext looks uniform under fresh nonces.** 500 known-plaintext encryptions, 20,000 generator-pair observations, χ² = 22.96 on 15 degrees of freedom (95% critical value ≈ 25.0) — no detectable bias. The small rewrite table doesn't leak via naive frequency analysis, because by the time `rewrite()` runs, its input has already been masked by the encode-layer entropy stream and the diffusion layer — both HMAC-SHA256-derived, both fresh per nonce. A bijection (which is all `rewrite()` is) applied to output that's already indistinguishable from random stays indistinguishable from random, regardless of how small its own keyspace is.
2. **The table is not brute-forced if it's ever isolated — it's just read off.** In a controlled scenario where the pre-rewrite walk is known directly (simulating a side-channel leak, a debug build, or a future diffusion-less mode), a single 64-generator sample recovered 14 of 16 table entries by direct inspection, no search required.

## What this means, stated plainly

The rewrite table's small keyspace (previously documented in the README as ~2⁷ ≈ 128 possibilities) is real and confirmed again here — but it is **not currently an exploitable weakness of the shipped cipher**, because it sits downstream of two HMAC-SHA256-derived layers that are cryptographically sound on their own terms (assuming HMAC-SHA256 as a PRF, standard) and fresh per nonce. Confidentiality currently comes entirely from those two layers, exactly as the README's limitation #2 says — this experiment is the empirical check behind that claim, not just an assertion of it.

The important research-integrity point is unaffected by this correction: **the trapdoor's smallness means it isn't doing meaningful cryptographic work in the current construction, whether or not that smallness is currently reachable by an attacker.** Whether it's exploitable and whether it's load-bearing are different questions; this experiment answers the first (no, not currently) and the earlier keyspace measurement already answered the second (also no).

## What remains open

- **Nonce reuse.** Not tested here. If a nonce is ever reused (RNG failure, a future deterministic-nonce mode), the entropy mask and diffusion seed become identical across the two messages that share it — analogous to two-time-pad territory for other stream constructions. This construction's diffusion layer was deliberately built with mod-4 addition specifically to resist simple XOR-cancellation attacks (see `diffusion.py`'s docstring), so it is *not* a straightforward two-time-pad break — but whether and how much information leaks under nonce reuse hasn't been analyzed. Flagging this explicitly rather than claiming a break I haven't demonstrated, or safety I haven't verified either.
- **Algebraic/structural attacks on the KB completion itself** (recovering `Rs` from `Rp` directly, without going through ciphertext at all) remain untested, same as before this experiment.

## Files

- `known_plaintext_pair_recovery.py` — self-contained, no external inputs required, includes its own self-check assertions. Runs in a few seconds.
