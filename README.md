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

The encrypt/decrypt pipeline runs end-to-end. The key mechanism uses Rs-equivalence classes derived from Knuth-Bendix completion — generator pairs are grouped by their Rs-normal form, and the key is a bijective permutation within each group. A diffusion layer (multi-round mixed addition/XOR chaining over generator values) achieves ~50% avalanche on a single-generator change (test threshold: >40% across measured positions with N_ROUNDS=2).

**What this is not:**

Full word-level LGIP. The current trapdoor operates at generator-pair level — it uses real KB completion to define groups, but encryption is still a bijective table lookup, not word-level non-confluent rewriting. The full LGIP construction (where multiple walks reduce to the same ciphertext, creating genuine preimage ambiguity) is open problem 4.

**Pipeline:**

```
Encrypt: plaintext → encode → diffuse → KB-pair-substitute → ciphertext
Decrypt: ciphertext → inverse-substitute → undiffuse → decode → plaintext
```

**Tests:** 50+ passing. Run `python3 -m pytest tests/ -v` (requires pytest).

---

## Project structure

```
honest/
├── src/honest/
│   ├── hypercube.py       — Q₄ graph, walk engine, generator definitions
│   ├── encoding.py        — plaintext ↔ walk codec
│   ├── diffusion.py       — invertible diffusion layer (~65% avalanche)
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
git clone https://github.com/YOUR_USERNAME/honest-cipher
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

**2. Pair-level KB, not full LGIP.** The KB completion trapdoor operates on generator pairs, not words. Full word-level non-confluent rewriting — where multiple distinct walks reduce to the same ciphertext, creating genuine preimage ambiguity — is not yet implemented.

**3. No message authentication.** Ciphertext is malleable. No MAC, no AEAD. An attacker can modify generator values in the walk and submit the result to a decryption oracle, using the oracle's response to extract structural information about the walk. This is IND-CCA1 failure by construction — it holds regardless of whether LGIP is hard. The scheme cannot be used safely without an outer authentication layer (e.g., Encrypt-then-MAC with a separate key).

**4. Walk expansion.** Ciphertext is ~4× the plaintext size. High compared to AEAD schemes (~0×).

**5. No side-channel analysis.** Not constant-time. No timing, power, or cache-timing analysis performed.

**6. Hypercube contributes no hardness.** Q₄ has 16 nodes. Endpoints are XOR-computable in O(n). Said here because early descriptions of this system overstated the hypercube's role.

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
