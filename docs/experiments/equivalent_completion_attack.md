# Experiment: equivalent-completion attack, and a keygen bug that hid it

**Status:** completed. **Relates to:** open problem 1 (LGIP average-case hardness), open problem 2 (rule inference), open problem 4 (full KB trapdoor).

This is the most consequential result in this directory so far. It contains one implementation bug with wide blast radius, one corrected measurement, and one structural finding that constrains any future version of this construction.

---

## 0. First, a bug: the KB trapdoor never ran

`knuth_bendix_complete()` returned `success=True` only when **zero critical pairs existed**. That is not the Knuth-Bendix criterion. The correct test (Newman's Lemma) is that every critical pair **joins** — both sides reduce to the same normal form. A non-trivial rule set keeps producing overlaps no matter how complete it is, so the stricter test can essentially never pass.

Consequence, traced through the call chain:

- `knuth_bendix_complete()` reported `success=False` on **40/40** runs — while the rule sets it produced were in fact already confluent (verified directly: on one run, `success=False` with all 119 remaining critical pairs joining).
- `generate_kb_key()` retries up to 10 times looking for `success=True`, never sees it, and falls through to its documented fallback: `rs = list(rp)`, the trivial `Rs = Rp`.
- Measured: **20/20 key generations hit the trivial fallback.** The KB completion trapdoor — the project's headline mechanism — has never actually executed in any released version.

After the one-line criterion fix: completion succeeds **35/40**, and the trivial-fallback rate drops to **4/20**.

Regression tests are in `tests/test_honest.py::TestKBCompletion` (`test_completion_success_flag_is_accurate`, `test_keygen_does_not_always_hit_trivial_fallback`). Both were confirmed to fail when the old criterion is temporarily restored, so they genuinely catch this rather than passing vacuously.

**This invalidated a measurement previously published in this repo.** The "Measured, not hypothetical" paragraph added to `docs/construction.md` §3 (median `|Rs \ Rp|` ≈ 8, "12.5% of trials added zero new rules") was computed without checking the `success` flag, so it was describing prematurely-terminated rule sets, not genuine completions. Corrected numbers are below. The conclusion that paragraph supported turns out to survive — but it was, at the time it was written, resting on a false premise, and that needed saying rather than quietly restating.

---

## 1. The keyspace result survives the fix — and gets stronger

Re-measured against genuinely completed rule sets:

| measurement | before fix (invalid) | after fix |
|---|---|---|
| completion success rate | 0/40 | 35/40 |
| keygen trivial fallback | 20/20 | 4/20 |
| substitution-table keyspace | ~2⁷ | **exactly 2⁷, in 40/40 keys** |

Group shape over 40 real key generations with working completion: `[2,2,2,2,2,2,2,1,1]` — **every single time**, giving a keyspace of exactly 2·2·2·2·2·2·2 = 128 = 2⁷.

So the README's headline limitation was right, and is now better supported than when it was written: it holds under a *working* trapdoor, not just under the degenerate fallback.

---

## 2. Why it's 2⁷: the grouping is public structure, not private completion

The reason the keyspace is invariant turns out to be structural, and it is the important finding here.

Across 40 independent keys, only **6 distinct group memberships** appeared at all — and **6 of the 9 groups were identical in every single key**:

```
{(1,2),(2,1)}  {(1,3),(3,1)}  {(1,4),(4,1)}
{(2,3),(3,2)}  {(2,4),(4,2)}  {(3,4),(4,3)}
```

These are exactly the transposition pairs `{(a,b),(b,a)}`. They are grouped together **not because of anything `Rs` did**, but because φ is an XOR homomorphism and XOR is commutative: φ(σₐσᵦ) = mask(a) ⊕ mask(b) = mask(b) ⊕ mask(a) = φ(σᵦσₐ). Any endpoint-preserving system whatsoever must place them together. Verified: every off-diagonal group is exactly a transposition pair, across 30 keys.

All the variation `Rs` actually contributes is which of the four diagonal pairs `(1,1),(2,2),(3,3),(4,4)` get paired with each other — and those four all have endpoint 0, so even that choice ranges over a tiny public set.

**Direct consequence, measured:** an attacker holding only `Rp` recovers the key owner's exact grouping in **30/30** trials, by running the same public completion algorithm on the same public input. (Completion is deterministic; verified identical across independent runs including one where `Rp` was serialized and reconstructed, simulating an attacker who only ever saw the published rules.)

---

## 3. "Recover Rs" was never the attacker's real bar

Even granting a hypothetical scheme where `Rs` were somehow hidden, the attacker never needed `Rs` itself. They need **any** confluent, terminating system `R*` whose normal-form function agrees with `Rs`'s on the walks in play — a strictly easier target.

Tested by perturbing only the completion algorithm's internal critical-pair processing order (the one implementation choice not already forced by `Rp` and the shortlex termination order) — no cryptanalysis, just a different tie-breaking order:

- **0-2 of 30** attempts reproduced the reference rule set exactly (incidental, varies by run).
- **30/30** attempts produced a rule set that agrees with the reference `Rs` on **300/300** random test walks — 100% functional equivalence.
- Reproduced on an independent run with a different seed: **15/15** functional matches.

Every attempt yielded a syntactically different but functionally identical decryption oracle. Finding an equivalent `R*` at this scale is not merely feasible — it is the default outcome of running the standard algorithm at all.

---

## 4. What this means for the word-level construction

This is the part that constrains future design, so stating it plainly:

The endpoint constraint every rule must satisfy is nearly vacuous. Because φ is an XOR homomorphism, **every permutation of a walk has the same endpoint** (verified over 200 random walks, all permutations). Each endpoint class therefore contains 4ⁿ/8 walks — measured at exactly 12.5% of all walks for n = 4, 6, 8, 10. That class is exponentially large *and* entirely publicly computable in O(n).

So a rewriting system over this semantic layer is trying to hide a private sub-structure inside an enormous, fully public equivalence class, using local rules that (as §3 shows) any completion attempt reconstructs functionally. Scaling `|Σ|` or rule length does not change the shape of that problem — it changes the constant, while completion remains a public deterministic algorithm and the endpoint class remains public.

**A word-level construction built on the same Q₄/XOR semantic layer inherits all three problems.** If word-level LGIP is to be attempted, the honest prerequisite is a semantic layer whose equivalence classes are *not* publicly computable — which is a different (and much harder) design than the one this project currently describes. This does not prove word-level LGIP impossible; it does mean the current architecture is not a foundation it can be built on.

---

## Reproducing

```
python3 docs/experiments/equivalent_completion_attack.py
```

Self-contained, no external inputs, includes its own self-check. Takes a couple of minutes (completion is O(n²) in rule count and now actually runs to completion instead of bailing early).

## What this doesn't claim

- Not a break of the shipped cipher's confidentiality. As established in `known_plaintext_pair_recovery.md`, the substitution table sits downstream of HMAC-SHA256-derived masking and diffusion; a small or fully-recovered table is not by itself a plaintext-recovery path under fresh nonces. This is a finding about the *trapdoor mechanism's* contribution, which is the project's actual research claim.
- Not a proof that no rewriting-based trapdoor can work. It is a concrete negative result about *this* semantic layer and *this* rule regime, at the parameters tested.
- Not tested at larger alphabets. The structural argument in §4 suggests scale is not the operative variable, but that is an argument, not a measurement.
