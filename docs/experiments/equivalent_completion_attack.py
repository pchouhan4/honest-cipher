"""
equivalent_completion_attack.py -- tests whether an attacker holding only Rp
can find SOME confluent completion R* that functionally matches Rs, without
recovering Rs itself. Relates to open_problems.md Problem 1 (LGIP average-
case hardness).

Why this matters: the natural framing of this scheme's security is "the
attacker can't recover Rs." That's the wrong target. The attacker only needs
ANY confluent, terminating system R* whose normal-form function agrees with
Rs's -- they never need to match the literal rule set. If completion is
insensitive to processing order (which critical pair gets resolved first),
then trivial randomized retries of the standard completion algorithm should
find functionally-equivalent-but-syntactically-different R*'s cheaply, with
no cryptanalytic cleverness at all.

This script tests exactly that: perturb knuth_bendix_complete's internal
critical-pair processing order (the only implementation choice that isn't
already forced by Rp and the shortlex termination order) and check whether
the result (a) is a different rule set from the original Rs, and (b) still
agrees with the original Rs's normal-form function on held-out test walks.

Run: python3 docs/experiments/equivalent_completion_attack.py
     (run from the repo root, or see the sys.path line below)
"""
from __future__ import annotations
import sys
import os
import random
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from honest.kb_completion import (
    generate_public_rules,
    knuth_bendix_complete,
    Rule,
    normalize,
    _critical_pairs,
)

MAX_LHS_LEN = 8  # matches the constant hardcoded inside kb_completion.knuth_bendix_complete


def knuth_bendix_shuffled(
    rules: list[Rule], max_steps: int, shuffle_seed: int
) -> tuple[list[Rule], bool]:
    """Identical algorithm to kb_completion.knuth_bendix_complete, except the
    order critical pairs are processed in is shuffled each round. Simulates
    an attacker who runs a differently-ordered (but equally legitimate)
    completion strategy against the same public Rp -- no special knowledge,
    just a different tie-breaking order."""
    rng = random.Random(shuffle_seed)
    rs = list(rules)
    steps = 0
    while steps < max_steps:
        pairs = _critical_pairs(rs)
        rng.shuffle(pairs)
        # Same success criterion as the fixed knuth_bendix_complete: all
        # critical pairs join (Newman's Lemma), not "no critical pairs exist".
        if all(normalize(u, rs) == normalize(v, rs) for u, v in pairs):
            return rs, True
        resolved_any = False
        for (u, v) in pairs:
            steps += 1
            nu, nv = normalize(u, rs), normalize(v, rs)
            if nu == nv:
                continue
            try:
                new_rule = Rule(nu, nv)
            except AssertionError:
                continue
            if new_rule in rs:
                continue
            if len(new_rule.lhs) > MAX_LHS_LEN:
                continue
            rs.append(new_rule)
            resolved_any = True
            simplified = []
            for old in rs[:-1]:
                new_rhs = normalize(old.rhs, [new_rule])
                if new_rhs != old.rhs:
                    try:
                        simplified.append(Rule(old.lhs, new_rhs))
                    except AssertionError:
                        simplified.append(old)
                else:
                    simplified.append(old)
            rs = simplified + [new_rule]
            if steps >= max_steps:
                break
        if not resolved_any:
            return rs, False
    return rs, False


def run_attack(n_attempts: int, n_test_walks: int, seed: int) -> dict:
    """For a single fixed Rp: run n_attempts differently-ordered completions,
    and for each, check functional agreement with the original Rs against
    n_test_walks random test words. Returns a summary dict."""
    rng = random.Random(seed)
    # Completion doesn't always succeed on the first random Rp (~12.5% of the
    # time per the earlier keyspace-measurement finding) -- retry with fresh
    # entropy rather than asserting on an unlucky draw.
    for _ in range(10):
        entropy = secrets.token_bytes(32)
        rp = generate_public_rules(entropy)
        rs_original, ok0 = knuth_bendix_complete(rp, max_steps=500)
        if ok0:
            break
    else:
        raise RuntimeError("reference completion did not succeed in 10 attempts")

    test_words = [
        tuple(rng.randint(1, 4) for _ in range(rng.randint(3, 12)))
        for _ in range(n_test_walks)
    ]
    orig_normals = [normalize(w, rs_original) for w in test_words]

    exact_matches = 0
    functional_matches = 0
    agree_counts = []
    for attempt_seed in range(n_attempts):
        rs_attempt, ok = knuth_bendix_shuffled(rp, max_steps=500, shuffle_seed=attempt_seed)
        if not ok:
            continue
        set_original = frozenset((r.lhs, r.rhs) for r in rs_original)
        set_attempt = frozenset((r.lhs, r.rhs) for r in rs_attempt)
        if set_attempt == set_original:
            exact_matches += 1

        attempt_normals = [normalize(w, rs_attempt) for w in test_words]
        agree = sum(1 for a, b in zip(orig_normals, attempt_normals) if a == b)
        agree_counts.append(agree)
        if agree == n_test_walks:
            functional_matches += 1

    return {
        "n_attempts": n_attempts,
        "n_test_walks": n_test_walks,
        "exact_matches": exact_matches,
        "functional_matches": functional_matches,
        "agree_counts": agree_counts,
        "rp_size": len(rp),
        "rs_size": len(rs_original),
    }


if __name__ == "__main__":
    print("=" * 70)
    print("Equivalent-completion attack: does Rp alone leak a working decoder?")
    print("=" * 70)
    print()
    result = run_attack(n_attempts=30, n_test_walks=300, seed=1)
    print(f"Rp: {result['rp_size']} rules, reference Rs: {result['rs_size']} rules")
    print(f"{result['n_attempts']} differently-ordered completion attempts against the same Rp:")
    print(f"  exact rule-set matches with original Rs:      {result['exact_matches']}/{result['n_attempts']}")
    print(f"  functional matches (100% normal-form agreement "
          f"on {result['n_test_walks']} random test walks): "
          f"{result['functional_matches']}/{result['n_attempts']}")
    print(f"  agreement counts per attempt: {result['agree_counts']}")
    print()

    if result["functional_matches"] == result["n_attempts"]:
        print("VERDICT: every attempt found a SYNTACTICALLY DIFFERENT rule set that is "
              "FUNCTIONALLY IDENTICAL to the original Rs. No cleverness required -- plain "
              "random reordering of the standard completion algorithm reliably produces a "
              "working decryption oracle. 'Recover Rs' was never the attacker's actual bar; "
              "'find any equivalent R*' is, and it appears to be nearly free at this scale.")
    else:
        print("VERDICT: mixed result -- some attempts diverged functionally from the "
              "original Rs. Re-examine before drawing the same conclusion.")

    # Self-check: the claim that matters is the FUNCTIONAL match rate -- that an
    # attacker reordering the standard algorithm lands on a working decoder. Exact
    # rule-set matches are incidental (a shuffle can coincidentally reproduce the
    # reference ordering) and are reported, not asserted on.
    result2 = run_attack(n_attempts=15, n_test_walks=200, seed=2)
    assert result2["functional_matches"] == result2["n_attempts"], (
        f"expected every differently-ordered attempt to functionally match the original Rs, "
        f"got {result2['functional_matches']}/{result2['n_attempts']} -- re-examine before "
        f"trusting the headline finding"
    )
    print()
    print(f"Self-check passed (independent run, different seed): "
          f"{result2['functional_matches']}/{result2['n_attempts']} functional matches "
          f"reproduced ({result2['exact_matches']} of them also matched the rule set exactly, "
          f"which is incidental).")
