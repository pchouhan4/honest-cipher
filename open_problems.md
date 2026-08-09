# Open problems

These are the gaps I know about. There are probably gaps I don't — that's the point of publishing early.

Problems 1 and 2 are the ones that could kill the construction entirely. The rest are important but secondary. If you make progress on any of them — partial result, attack, proof sketch — open an issue. You don't need a complete answer to contribute something useful.

---

## Problem 1: LGIP average-case hardness

**Type:** hardness proof or attack  
**Priority:** critical

Is LGIP hard on average over a natural input distribution? The goal is either a reduction from a known hard problem (lattice, code-based, or graph problem with established hardness) or a polynomial-time attack on a non-negligible fraction of instances.

A lower bound on search space size as a function of parameters would already be valuable, even without a full proof.

---

## Problem 2: Rule inference attack

**Type:** known-plaintext attack  
**Priority:** critical

Given k pairs {(mᵢ, cᵢ)} encrypted under the same key, can an adversary recover partial or complete information about Rs?

The direct approach: compute the walk encoding of mᵢ to get wᵢ, observe the ciphertext walk cᵢ, identify which generator pairs were substituted, reconstruct the permutation table.

**Partial result (March 2026):** A surface-feature fingerprinting experiment tested whether ML classification on walk unigram/bigram features, with up to 50% of Rs leaked (111 of 222 rules), could identify canonical equivalence classes. Result: attacker accuracy stayed at 0.0264 ± 0.003 — indistinguishable from random guessing across all leakage fractions. The delta across conditions never exceeded 0.00001. See  for the full writeup. This closes the surface-feature path under this model. Direct algebraic recovery of the permutation table from known-plaintext pairs remains open and untested.

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

**Problem 4 (KB completion trapdoor)** — implemented in v0.2. Generator pairs are now grouped by their Rs-equivalence classes (Rs-normal form), derived from KB completion of the public rule set Rp. The private key is Rs; without it, the grouping cannot be reconstructed. Full walk-level LGIP (non-confluent rewriting at word level) remains open.

**Problem 5 (diffusion layer)** — implemented in v0.2. Multi-round mixed addition/XOR chaining achieves ~65% avalanche effect on a single-generator change. The layer is invertible given the key. Formal proof that it achieves the strict avalanche criterion is still open.

---

## How to contribute

Open a GitHub issue. Say which problem, what you tried, what you found. Proof-of-concept code for an attack is enough — you don't need a paper. I'll credit you in the README and in any future publication.
