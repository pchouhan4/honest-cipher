# Open problems

These are the gaps I know about. There are probably gaps I don't — that's the point of publishing early.

Problems 1 and 2 are the ones that could kill the construction entirely. The rest are important but secondary. If you make progress on any of them — partial result, attack, proof sketch — open an issue. You don't need a complete answer to contribute something useful.

---

## Problem 1: LGIP average-case hardness

**Type:** hardness proof or attack  
**Priority:** critical

Is LGIP hard on average over a natural input distribution? The goal is either a reduction from a known hard problem (lattice, code-based, or graph problem with established hardness) or a polynomial-time attack on a non-negligible fraction of instances.

A lower bound on search space size as a function of parameters would already be valuable, even without a full proof.

**Partial negative result (tested).** The framing "the attacker must recover Rs" is too generous to the scheme — an attacker only needs *any* confluent `R*` agreeing with `Rs` on normal forms. Measured: perturbing only the completion algorithm's processing order yields a functionally identical decoder in **30/30** attempts. Separately, the endpoint constraint underlying LGIP is close to vacuous: since φ is an XOR homomorphism, every permutation of a walk shares an endpoint, so each class holds 4ⁿ/8 walks (measured: exactly 12.5% of all walks for n = 4, 6, 8, 10) and is publicly computable in O(n). Any hardness argument has to survive both facts. See `docs/experiments/equivalent_completion_attack.md`.

---

## Problem 2: Rule inference attack

**Type:** known-plaintext attack  
**Priority:** critical

Given k pairs {(mᵢ, cᵢ)} encrypted under the same key, can an adversary recover partial or complete information about Rs?

There are two distinct attack paths that need to be treated separately:

**Path A — Direct pair table recovery.** **Re-tested; the description below is now corrected, see `docs/experiments/known_plaintext_pair_recovery.md` for the full writeup.** With |Σ| = 4, the generator pair space is {1,2,3,4}×{1,2,3,4} = 16 pairs, and the substitution key is a bijective permutation over a small number of equivalence classes of those pairs — that part still holds. What doesn't hold as originally written: "encode mᵢ to get the plaintext walk wᵢ" assumes the attacker can compute `entropy = HMAC(key_hash, nonce)`, which requires the secret key. This attack was specified before v0.2 added HMAC-derived entropy masking to `encode()`/`diffuse()` and was never revisited afterward — as written, it describes the pre-v0.2 pipeline, not the current one. Retested against v0.2 as a strict external attacker: not executable as described.

The underlying concern (the table's small keyspace) is still real, just relocated: a controlled test confirms the table is trivially read off *if it's ever isolated* (14/16 entries from one 64-generator sample with no search), but 500-message frequency analysis against the real pipeline shows ciphertext is statistically indistinguishable from uniform (χ²=22.96 on 15 dof, below the 95% critical value) — the table is currently shielded by the encode-mask and diffusion layers, both fresh per nonce. **Not yet analyzed: nonce reuse**, which would make those layers' keystreams identical across two messages. The diffusion layer's mod-4 addition was deliberately built to resist simple XOR-cancellation, so this isn't assumed to be a straightforward two-time-pad break, but it hasn't been checked either way. That's the actual most-urgent untested item now, not the original Path A framing.

**Update: tested.** A differential test (`docs/experiments/nonce_reuse_differential.py`) confirms nonce reuse is a real leak, not a theoretical one: at most walk positions, ciphertext-difference variance under a reused nonce is ~6x to 38x higher than under fresh nonces (F-ratio), at sample sizes large enough that this isn't noise (n=6000 in block mode, n=450 in kb mode, consistent across repeated runs). The mod-4 addition chain in `diffusion.py` prevents simple XOR-cancellation as designed, but does not prevent this distributional leak. A secondary check shows the leak is specifically pairwise (visible only when comparing two ciphertexts known to share a nonce), not aggregate (a single reused-nonce ciphertext, or many unrelated ones, shows no bias). Full plaintext recovery from this signal is untested and is now the next concrete step — see `docs/experiments/nonce_reuse_differential.md`.

**Path B — Surface-feature fingerprinting (tested, closed under this model).** ML classification on walk unigram/bigram features, with up to 50% of Rs leaked (111 of 222 rules), could not identify canonical equivalence classes. Attacker accuracy stayed at 0.0264 ± 0.003 — indistinguishable from random guessing across all leakage fractions. The delta across conditions never exceeded 0.00001. See `docs/experiments/leakage_analysis.md` for the full writeup. This closes the surface-feature path under this model.

Note: Path B closing does not close Path A. They address different questions — statistical fingerprinting vs. direct algebraic reconstruction.

---

## Problem 3: Quantum advantage

**Type:** theoretical  
**Priority:** high

Does LGIP admit quantum speedup beyond Grover's quadratic? Specifically: do quantum walk algorithms (Childs 2003, Szegedy 2004) apply to the reachability structure of the Rp-rewriting graph? If yes, the quantum resistance claim needs revisiting.

---

## Problem 4: Full KB completion trapdoor

**Type:** implementation  
**Priority:** high

Implement the complete Rp/Rs architecture: generate a non-confluent Rp, run Knuth-Bendix completion to get Rs, verify Rs is private given only Rp (an adversary running KB on Rp alone should not recover Rs), implement encryption using Rp rewrites and decryption using Rs normal forms.

The hard part: KB completion isn't guaranteed to terminate. Parameter selection needs to ensure termination while keeping the completion private.

---

## Problem 5: Diffusion layer

**Type:** construction  
**Priority:** high

The current avalanche effect is ~1% — a 1-bit plaintext change affects one generator pair and nothing else. A real cipher should hit ~50%. Design a diffusion layer for walk-based ciphers that achieves the strict avalanche criterion while staying invertible given the key.

Approaches worth trying: walk-level permutation after block substitution, feedback construction where each generator depends on all previous, hash-based chaining between walk segments.

---

## Problem 6: Formal security model

**Type:** definitions  
**Priority:** medium

Define IND-CPA and IND-CCA2 security for H.O.N.E.S.T. and determine whether the construction achieves either. The current construction almost certainly fails IND-CPA due to the weak avalanche, but a formal proof of failure — or success after adding diffusion — is a concrete result.

---

## Problem 7: Parameter selection

**Type:** concrete security  
**Priority:** medium

For the full LGIP construction, what walk length ℓ as a function of dimension n gives 128-bit security? What rule set size |Rp| ensures the completion Rs \ Rp contains enough private information? What alphabet size |Σ| optimizes the hardness/performance tradeoff? This can't be answered until problem 1 is resolved.

---

## Problem 8: Walk compression

**Type:** engineering  
**Priority:** low

The current encoding uses 4 generators per input byte giving ~4× expansion. Approaches: Huffman coding over the generator alphabet, arithmetic coding, representing walks as integers rather than generator sequences.

---

## Solved problems (v0.2)

> **Correction:** "Problem 4 solved in v0.2" was wrong in a way nobody could see from the outside. A bug in `knuth_bendix_complete()`'s success criterion (it tested "no critical pairs exist" instead of the correct "all critical pairs join") made completion report failure on 100% of runs, so `generate_kb_key()` silently fell back to the trivial `Rs = Rp` on **every key generation**. The KB trapdoor never actually executed in any released version. The bug is now fixed with regression tests, so the trapdoor does run — but re-measuring it against working completion shows it contributes only ~2⁷ keyspace, and that this is structural rather than a parameter choice. See `docs/experiments/equivalent_completion_attack.md`. Problem 4 is better described as *implemented but demonstrated insufficient* than as solved.

**Problem 4 (KB completion trapdoor)** — implemented in v0.2. Generator pairs are now grouped by their Rs-equivalence classes (Rs-normal form), derived from KB completion of the public rule set Rp. The private key is Rs; without it, the grouping cannot be reconstructed. Full walk-level LGIP (non-confluent rewriting at word level) remains open.

**Problem 5 (diffusion layer)** — implemented in v0.2. Multi-round mixed addition/XOR chaining achieves ~72% mean avalanche on a single-generator change, but not uniformly — a reproducible weak zone in roughly the last ⅛ of the walk means ~3-4% of single-position flips fall below the strict-avalanche threshold (see `docs/construction.md` §6). The layer is invertible given the key. Formal proof that it achieves the strict avalanche criterion is still open, and the measured weak zone suggests it currently doesn't.

---

## How to contribute

Open a GitHub issue. Say which problem, what you tried, what you found. Proof-of-concept code for an attack is enough — you don't need a paper. I'll credit you in the README and in any future publication.
