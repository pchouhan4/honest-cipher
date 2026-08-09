# H.O.N.E.S.T.
### Hypercube-Oriented Nonlinear Encryption with Structured Trapdoors

**Status: research prototype — v0.2.0**  
**Don't use this for production data. Read [limitations](#known-limitations) first.**

---

## What this is

I built this to explore an idea I hadn't seen done before: using a term rewriting system as a cryptographic trapdoor instead of number theory, elliptic curves, or lattices. The hardness assumption underneath it — the Local Grammar Inversion Problem (LGIP) — is new, which means it's either genuinely interesting or broken in a non-obvious way. I don't know which yet. That's why I'm publishing it.

No formal security proof. Documented weaknesses. The point of putting it out now is to get cryptanalysts to look at it — a break is a useful result.

---

## The construction

The system has two layers. The syntactic layer is a rewriting system over words in the generator alphabet Σ = {σ₁, σ₂, σ₃, σ₄}. The semantic layer is a 4D hypercube (Q₄) that gives each generator a geometric meaning — a bit flip.

An attacker sees only the syntactic layer. The owner holds a trapdoor that resolves ambiguity in the rewriting system.

**Three key objects:**

**Public rewriting rules Rp** — terminating, non-confluent, endpoint-preserving substitutions over generator pairs. Non-confluence is intentional: many walks rewrite to the same ciphertext walk, creating ambiguity the attacker has to resolve without the key.

**Private completion rules Rs** — a confluent, terminating completion of Rp via Knuth-Bendix completion. Rs allows unique canonicalization of any ciphertext walk back to its original. Without it, canonicalization is ambiguous.

**The hypercube Q₄** — 16 vertices (4-bit strings), 4 generators (bit-flip operations). The semantic mapping φ: Σ* → {0,1}⁴ maps any walk to its endpoint via XOR. Worth saying clearly: Q₄ contributes zero computational hardness. Endpoints are XOR-computable in O(n). All security lives in the rewriting system.

**The hard problem (LGIP):**

> Given (Σ, Rp, w'), find a walk w such that w →\*Rp w' and w is Rs-minimal.

Without Rs, the attacker faces exponential ambiguity — many walks rewrite to the same w', and identifying the canonical one requires the private completion rules. LGIP hardness is a conjecture. No polynomial-time algorithm is known. This is not a proof.

---

## Implementation status

**What's built (v0.2.0):**

The encrypt/decrypt pipeline runs end-to-end. The key mechanism uses Rs-equivalence classes derived from Knuth-Bendix completion — generator pairs are grouped by their Rs-normal form, and the key is a bijective permutation within each group. A diffusion layer (multi-round mixed addition/XOR chaining over generator values) achieves ~72% mean avalanche on a single-generator change (1000-trial measurement, n=128, N_ROUNDS=2), but avalanche is not uniform across positions — roughly the last ⅛ of the walk has a reproducible weak zone, and about 3-4% of random single-position flips fall below a >40% threshold, occasionally as low as 1-9%. `python3 -m honest.diffusion` now sweeps all 128 positions and reports it directly instead of sampling four hand-picked ones. See [limitations](#known-limitations) and `docs/construction.md` §6.

**What this is not:**

Full word-level LGIP. The current trapdoor operates at generator-pair level — it uses real KB completion to define groups, but encryption is still a bijective table lookup, not word-level non-confluent rewriting. The full LGIP construction (where multiple walks reduce to the same ciphertext, creating genuine preimage ambiguity) is open problem 4.

**Pipeline:**

```
Encrypt: plaintext → encode → diffuse → KB-pair-substitute → ciphertext
Decrypt: ciphertext → inverse-substitute → undiffuse → decode → plaintext
```

**Tests:** 64 passing, deterministically (checked over 12 consecutive runs — two tests were previously flaky because they compared the wrong pair of walks / assumed an incorrect KB-completion invariant; both fixed, see `tests/test_honest.py`). Run `python3 -m pytest tests/ -v` (requires pytest) from the repo root — `pip install pytest` first if needed.

---

## Project structure

```
honest/
├── src/honest/
│   ├── hypercube.py       — Q₄ graph, walk engine, generator definitions
│   ├── encoding.py        — plaintext ↔ walk codec
│   ├── diffusion.py       — invertible diffusion layer (~72% mean avalanche, weak tail near walk end — see limitations)
│   ├── kb_completion.py   — Knuth-Bendix completion trapdoor
│   ├── rewriter.py        — keyed pair substitution (block and KB modes)
│   └── cipher.py          — full encrypt/decrypt pipeline
├── tests/
│   └── test_honest.py     — test suite
├── docs/
│   ├── construction.md    — full mathematical specification
│   ├── open_problems.md   — eight open research questions
│   └── experiments/
│       ├── leakage_analysis.md         — surface-feature fingerprinting experiment
│       └── partial_rule_leakage_sim.py — experiment code
├── demo.py
└── README.md
```

---

## Quickstart

Python 3.10+, no dependencies for the core library.

```bash
git clone https://github.com/pchouhan4/honest-cipher
cd honest-cipher
python demo.py
```

```python
import sys
sys.path.insert(0, 'src')
from honest.cipher import HonestCipher

cipher = HonestCipher.generate()          # KB mode + diffusion by default
ciphertext = cipher.encrypt(b"Hello, post-quantum world.")
plaintext  = cipher.decrypt(ciphertext)
assert plaintext == b"Hello, post-quantum world."

# key serialization
key_data = cipher.export_key()
restored = HonestCipher.from_key_dict(key_data)
assert restored.decrypt(ciphertext) == plaintext
```

---

## Known limitations

These aren't bugs. They're documented properties of the current construction — listed here because honest documentation is what makes a research prototype useful rather than dangerous.

**1. No formal security proof.** LGIP hardness is a conjecture. No reduction to a known hard assumption. IND-CPA and IND-CCA2 security unproven.

**2. The KB trapdoor is currently near-inert — this is the important one.** "Pair-level KB, not full LGIP" (below) undersells the gap. I measured the actual keyspace the trapdoor contributes in the current (v0.2.0) default `kb` mode, across 40 fresh key generations:

- Rs-equivalence groups over the 16 generator-pairs are almost always shaped `[2,2,2,2,2,2,2,1,1]` — seven pairs-of-two and two fixed points. A substitution table built from that shape has a keyspace of **roughly 2⁷ = 128 possibilities**, trivial to brute-force or simply read off *if it were ever the only wall between an attacker and the plaintext* (confirmed directly: see `docs/experiments/known_plaintext_pair_recovery.md`). It currently isn't the only wall — see that writeup for why the shipped cipher isn't breakable through this table today — but that's a property of what's stacked on top of it (the HMAC-derived encode-mask and diffusion layers), not of the trapdoor itself.
- **The grouping is public structure, not private completion.** Six of the nine groups are the transposition pairs `{(a,b),(b,a)}` in *every* key — forced by φ being an XOR homomorphism (φ(σₐσᵦ) = φ(σᵦσₐ) by commutativity), not by anything `Rs` does. Across 40 independent keys only 6 distinct groupings appeared at all. An attacker holding only `Rp` reconstructs the owner's exact grouping in **30/30** trials, by running the same public deterministic algorithm on the same public input.
- **The attacker doesn't even need `Rs`.** Any confluent system `R*` that agrees with `Rs` on normal forms works as a decryption oracle. Perturbing only the completion algorithm's internal processing order — no cryptanalysis — produced a functionally identical `R*` in **30/30** attempts (100% agreement on 300 random test walks). Finding an equivalent decoder isn't hard here; it's the default outcome of running the standard algorithm at all.

**What this means concretely: whatever confidentiality this cipher has right now comes almost entirely from the HMAC-SHA256 keystreams in `encode()` and `diffuse()`, not from the rewriting-system trapdoor.** The trapdoor is real code doing real Knuth-Bendix completion — it is not fake — but it contributes ~7 bits of keyspace to a construction whose entire point is to explore whether a rewriting-system trapdoor *can* carry security.

And the follow-up finding is that **scaling parameters is unlikely to fix this**, which is a change from what an earlier version of this README said. Because φ is an XOR homomorphism, every permutation of a walk has the same endpoint, so each endpoint class holds 4ⁿ/8 walks — exponentially large *and* publicly computable in O(n). The construction is trying to hide a private sub-structure inside a fully public equivalence class, using local rules any completion attempt reconstructs functionally. That's a property of the Q₄/XOR semantic layer, not of the parameter sizes. Full analysis and reproduction: `docs/experiments/equivalent_completion_attack.md`.

> **Correction:** an earlier version of this section reported "12.5% of key generations added zero new rules" and "median ~8 new rules per key." Those numbers were measured without checking `knuth_bendix_complete()`'s success flag, while a bug in its success criterion was causing `generate_kb_key()` to silently fall back to the trivial `Rs = Rp` on **100%** of key generations — meaning the KB trapdoor had never actually run in any released version. The bug is fixed and covered by regression tests; the figures above are re-measured against working completion. The headline conclusion survived; the premise underneath it did not, and is corrected rather than quietly restated.

**3. Pair-level KB, not full LGIP.** The KB completion trapdoor operates on generator pairs, not words. Full word-level non-confluent rewriting — where multiple distinct walks reduce to the same ciphertext, creating genuine preimage ambiguity — is not yet implemented. (This is a separate, larger gap from #2 above: even a keyspace-significant pair-level trapdoor would still not be the LGIP construction motivating this project — see the LGIP definition earlier in this document.)

**4. No message authentication.** Ciphertext is malleable. No MAC, no AEAD. An attacker can modify generator values in the walk and submit the result to a decryption oracle, using the oracle's response to extract structural information about the walk. This is IND-CCA1 failure by construction — it holds regardless of whether LGIP is hard. The scheme cannot be used safely without an outer authentication layer (e.g., Encrypt-then-MAC with a separate key).

**5. Walk expansion.** Ciphertext is ~4× the plaintext size. High compared to AEAD schemes (~0×).

**6. No side-channel analysis.** Not constant-time. No timing, power, or cache-timing analysis performed.

**7. Hypercube contributes no hardness.** Q₄ has 16 nodes. Endpoints are XOR-computable in O(n). Said here because early descriptions of this system overstated the hypercube's role.

---

## Open problems

Eight formal open problems are in `docs/open_problems.md`. Summary:

1. Is LGIP hard on average? Can it be reduced to a known hard problem?
2. Can an adversary recover Rs from known (plaintext, ciphertext) pairs? *(partial result in `docs/experiments/`)*
3. Does the rewriting structure admit quantum speedup beyond Grover?
4. Implement full word-level Rp/Rs non-confluent rewriting.
5. Prove (or disprove) the strict avalanche criterion for the current diffusion layer.
6. Formalize IND-CPA and IND-CCA2 definitions for this construction.
7. Determine concrete security parameters for the full LGIP instantiation.
8. Reduce walk expansion ratio from ~4×.

If you solve one or find an attack, open an issue. A break is more useful than silence.

---

## Empirical work

`docs/experiments/leakage_analysis.md` documents the first attack simulation run against this construction: a surface-feature fingerprinting experiment testing whether ML classification on walk statistics, with up to 50% of Rs leaked (111 of 222 rules), could identify canonical equivalence classes. Attacker accuracy stayed at 0.026 ± 0.003 — random guessing — across all leakage fractions. This closes the surface-feature path under that model. Algebraic attacks remain open.

**Reproducibility note:** the rule files that produced these numbers (`public_rules.json`, `private_rules.json`) and the raw output (`leakage_results.pkl`, `kb_rules_output.txt`) aren't checked into this repo, so the result currently can't be independently rerun from what's here — take the number as reported, not as reproducible. Fixing that (checking in the inputs/outputs, or a seeded regeneration script) is on the to-do list.

`docs/experiments/known_plaintext_pair_recovery.py` re-tests open problem 2's Path A ("direct pair table recovery," previously flagged untested and most urgent) against the real pipeline. Result: the attack as originally described doesn't apply to v0.2 — it assumes an attacker can compute the plaintext walk directly, which requires the secret key under the current HMAC-derived entropy scheme. The underlying concern (the rewrite table's small keyspace) is confirmed still real in isolation, but a 500-message frequency test shows the shipped ciphertext is statistically uniform — the table is currently shielded by the encode-mask and diffusion layers, not by its own size. Nonce reuse is flagged as the actual untested risk now; see `docs/experiments/known_plaintext_pair_recovery.md` for the full writeup, unlike the leakage experiment above this one is fully self-contained and reruns in a few seconds with no external files needed.

Following up on the nonce-reuse question that raised: `docs/experiments/nonce_reuse_differential.py` confirms it's a real leak, not just a theoretical risk flagged for later. At most walk positions, ciphertext-difference variance under a reused nonce runs ~6x to 38x higher than under fresh nonces — large enough at the sample sizes tested (n=6000 block mode, n=450 kb mode, stable across repeated runs) that it isn't noise. `diffusion.py`'s mod-4 addition chain prevents simple XOR-cancellation as designed, but not this distributional leak. See `docs/experiments/nonce_reuse_differential.md` for the full result and what it doesn't yet show (full plaintext recovery from the signal is untested, separate follow-on work).

---

## Why publish this early

Waiting until it's "ready" means waiting for a formal security proof that could take years — if it's even provable. The idea is novel enough that I'd rather get it in front of people who can attack it now.

---

## Contributing

See `CONTRIBUTING.md`. The most useful thing: try to break it. Specifically, the rule inference attack in open problem 2 — can you recover the key or the permutation table from known plaintext pairs algebraically? If you can, that's a critical result.

Don't submit PRs that soften the limitations section.

---

## License

MIT. See `LICENSE`.

---

## Author

Self-taught. Built this because the idea wouldn't leave me alone.  
Questions, cryptanalysis, collaboration — open an issue.

---

*Not affiliated with NIST, the Open Quantum Safe project, or any standards body.*
