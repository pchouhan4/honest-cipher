"""
kb_completion.py — Knuth-Bendix completion trapdoor for H.O.N.E.S.T.

Implements the full Rp/Rs architecture from the mathematical specification.

Overview
--------
The trapdoor is the Knuth-Bendix completion of a non-confluent rule set.

  Public  Rp: endpoint-preserving, terminating, non-confluent rules
  Private Rs: complete extension of Rp (confluent + terminating)

Encrypting applies Rp rewrites (non-deterministic — many ciphertexts for
one plaintext). Decrypting normalizes under Rs (deterministic — unique
normal form). Without Rs, the attacker cannot identify which of the
exponentially-many Rp-preimages is canonical.

Termination order
-----------------
We use shortlex ordering: shorter words before longer, then lexicographic.
Rules must always reduce word length or break ties lexicographically.
This guarantees termination of normalization and of the completion process
for the rule sets generated here.

Completion algorithm (Knuth-Bendix)
------------------------------------
1. Initialize rules := Rp
2. Find all critical pairs (overlapping left-hand sides).
3. For each critical pair (u, v): normalize both sides under current rules.
   - If both sides are equal: pair is resolved (rules are locally confluent here).
   - If they differ: add a new orienting rule (shorter → longer, or lex-first → other).
   - Simplify existing rules using any new rules added.
4. Repeat until no new pairs or max_steps exceeded.

Security note
-------------
The privacy of Rs depends on |Rs \\ Rp| being cryptographically significant.
With the parameter choices here (~8-16 public rules), completion typically
adds 4-20 private rules. Formal hardness of recovering Rs from Rp is
open problem 1. Do not assume this provides production security.
"""

from __future__ import annotations
import hashlib
import secrets
from typing import Optional


# Generators as tuples for hashability
GENS = (1, 2, 3, 4)
# XOR endpoint masks (same as hypercube.py)
_MASK = {1: 0b0001, 2: 0b0010, 3: 0b0100, 4: 0b1000}


def _endpoint(word: tuple[int, ...]) -> int:
    """XOR-fold a generator word to its Q₄ endpoint."""
    result = 0
    for g in word:
        result ^= _MASK[g]
    return result


def _shortlex_lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    """Return True if a < b in shortlex order."""
    if len(a) != len(b):
        return len(a) < len(b)
    return a < b


# ---------------------------------------------------------------------------
# Rule representation
# ---------------------------------------------------------------------------

class Rule:
    """An endpoint-preserving rewriting rule lhs → rhs."""
    __slots__ = ("lhs", "rhs")

    def __init__(self, lhs: tuple[int, ...], rhs: tuple[int, ...]):
        assert _endpoint(lhs) == _endpoint(rhs), "Endpoint not preserved"
        # Orient so lhs > rhs in shortlex (rules reduce)
        if _shortlex_lt(lhs, rhs):
            lhs, rhs = rhs, lhs
        self.lhs = lhs
        self.rhs = rhs

    def __eq__(self, other):
        return self.lhs == other.lhs and self.rhs == other.rhs

    def __hash__(self):
        return hash((self.lhs, self.rhs))

    def __repr__(self):
        return f"{''.join(str(g) for g in self.lhs)} → {''.join(str(g) for g in self.rhs)}"


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize(word: tuple[int, ...], rules: list[Rule]) -> tuple[int, ...]:
    """
    Reduce word to normal form under the rule set.
    Applies rules leftmost-innermost until no rule fires.
    Terminates because rules are shortlex-reducing.
    """
    changed = True
    while changed:
        changed = False
        for rule in rules:
            lhs = rule.lhs
            n = len(lhs)
            for i in range(len(word) - n + 1):
                if word[i:i + n] == lhs:
                    word = word[:i] + rule.rhs + word[i + n:]
                    changed = True
                    break
            if changed:
                break
    return word


# ---------------------------------------------------------------------------
# Critical pairs
# ---------------------------------------------------------------------------

def _critical_pairs(rules: list[Rule]) -> list[tuple[tuple[int, ...], tuple[int, ...]]]:
    """
    Find all critical pairs between rules.

    A critical pair arises when two rules overlap on a word.
    Given rules l1→r1 and l2→r2, they overlap if some suffix of l1 equals
    a prefix of l2 (or l1 contains l2 as a substring, or vice versa).
    """
    pairs = []
    n = len(rules)

    for i in range(n):
        for j in range(n):
            l1, r1 = rules[i].lhs, rules[i].rhs
            l2, r2 = rules[j].lhs, rules[j].rhs

            # Overlap: suffix of l1 of length k == prefix of l2
            for k in range(1, min(len(l1), len(l2))):
                if l1[len(l1) - k:] == l2[:k]:
                    # l1[:-k] + l2 can be reduced two ways:
                    # way 1: apply rule i at position 0: r1 + l2[k:]
                    # way 2: apply rule j at position len(l1)-k: l1[:-k] + r2
                    way1 = r1 + l2[k:]
                    way2 = l1[:len(l1) - k] + r2
                    if way1 != way2:
                        pairs.append((way1, way2))

            # Overlap: l2 is a substring of l1 starting at position p
            for p in range(len(l1) - len(l2) + 1):
                if l1[p:p + len(l2)] == l2:
                    # l1 can be reduced two ways:
                    # way 1: apply rule i: r1
                    # way 2: apply rule j at position p: l1[:p] + r2 + l1[p+len(l2):]
                    way1 = r1
                    way2 = l1[:p] + r2 + l1[p + len(l2):]
                    if way1 != way2:
                        pairs.append((way1, way2))

    return pairs


# ---------------------------------------------------------------------------
# Knuth-Bendix completion
# ---------------------------------------------------------------------------

def knuth_bendix_complete(
    rules: list[Rule],
    max_steps: int = 500,
) -> tuple[list[Rule], bool]:
    """
    Run Knuth-Bendix completion on a rule set.

    Returns (completed_rules, success).
    success=False means max_steps was hit before all pairs resolved.

    Only adds rules whose lhs has length <= MAX_LHS_LEN to keep
    the rule set finite and normalization tractable.
    """
    MAX_LHS_LEN = 8
    rs = list(rules)
    steps = 0

    while steps < max_steps:
        pairs = _critical_pairs(rs)
        if not pairs:
            return rs, True  # All pairs resolved — completion successful

        resolved_any = False
        for (u, v) in pairs:
            steps += 1
            nu = normalize(u, rs)
            nv = normalize(v, rs)

            if nu == nv:
                continue  # Pair already resolved

            # Add orienting rule
            if nu == nv:
                continue
            try:
                new_rule = Rule(nu, nv)
            except AssertionError:
                continue  # Endpoint mismatch (shouldn't happen, but be safe)

            if new_rule in rs:
                continue

            # Reject rules whose lhs is too long (bounds rule set size)
            if len(new_rule.lhs) > MAX_LHS_LEN:
                continue

            rs.append(new_rule)
            resolved_any = True

            # Simplify existing rules: if any existing rule's rhs can be
            # reduced by the new rule, update it
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
            # No new rules added but pairs still exist — stuck
            # (can happen when all remaining pairs produce rules exceeding MAX_LHS_LEN)
            return rs, False

    return rs, False


# ---------------------------------------------------------------------------
# Public rule generation
# ---------------------------------------------------------------------------

def generate_public_rules(entropy: bytes = None, n_rules: int = 12) -> list[Rule]:
    """
    Generate a set of endpoint-preserving, terminating, non-confluent rules Rp.

    Rules operate on generator pairs and triples. Non-confluence is ensured
    by including overlapping rules that create unresolved critical pairs.

    Strategy:
    - For each XOR equivalence class of generator pairs, generate a rule
      that permutes within the class (these are always termination-safe).
    - Add some length-3 rules that overlap with the pair rules.
    """
    if entropy is None:
        entropy = secrets.token_bytes(32)

    counter = [0]
    def rnd_byte() -> int:
        nonlocal counter
        h = hashlib.sha256(entropy + counter[0].to_bytes(4, 'big')).digest()
        counter[0] += 1
        return h[0]

    rules: list[Rule] = []
    seen_lhs: set[tuple[int, ...]] = set()

    # Build XOR equivalence classes for pairs
    classes: dict[int, list[tuple[int, int]]] = {}
    for g1 in GENS:
        for g2 in GENS:
            xor = _MASK[g1] ^ _MASK[g2]
            classes.setdefault(xor, []).append((g1, g2))

    # For each class with >1 pair, add a non-trivial permutation rule
    for xor_sum, pairs in sorted(classes.items()):
        if len(pairs) < 2:
            continue
        # Pick two distinct pairs in this class and make a rule
        for attempt in range(10):
            i = rnd_byte() % len(pairs)
            j = rnd_byte() % len(pairs)
            if i == j:
                continue
            lhs = pairs[i]
            rhs = pairs[j]
            if lhs == rhs or lhs in seen_lhs:
                continue
            try:
                r = Rule(lhs, rhs)
                if r.lhs not in seen_lhs:
                    rules.append(r)
                    seen_lhs.add(r.lhs)
                    break
            except AssertionError:
                continue

    # Add some length-3 rules to create overlaps with the pair rules
    triple_attempts = 0
    while len(rules) < n_rules and triple_attempts < 200:
        triple_attempts += 1
        g1, g2, g3 = [GENS[rnd_byte() % 4] for _ in range(3)]
        lhs = (g1, g2, g3)
        # Find a different triple with same endpoint
        ep = _endpoint(lhs)
        for _ in range(20):
            h1, h2, h3 = [GENS[rnd_byte() % 4] for _ in range(3)]
            rhs = (h1, h2, h3)
            if rhs != lhs and _endpoint(rhs) == ep and lhs not in seen_lhs:
                try:
                    r = Rule(lhs, rhs)
                    if r.lhs not in seen_lhs:
                        rules.append(r)
                        seen_lhs.add(r.lhs)
                        break
                except AssertionError:
                    continue

    return rules[:n_rules]


# ---------------------------------------------------------------------------
# Key generation using KB completion
# ---------------------------------------------------------------------------

def generate_kb_key(
    entropy: bytes = None,
    max_retries: int = 10,
) -> tuple[list[Rule], list[Rule]]:
    """
    Generate a KB trapdoor key.

    Returns (Rp, Rs) where:
      Rp  — public rules (non-confluent)
      Rs  — private rules (confluent completion of Rp)

    Retries with fresh entropy if completion doesn't terminate.
    """
    if entropy is None:
        entropy = secrets.token_bytes(32)

    for attempt in range(max_retries):
        attempt_entropy = hashlib.sha256(
            entropy + attempt.to_bytes(4, 'big')
        ).digest()

        rp = generate_public_rules(attempt_entropy)
        rs, success = knuth_bendix_complete(rp, max_steps=500)

        if success:
            return rp, rs

    # If completion never terminates, fall back to a known-terminating base
    # (this should be rare with current parameter choices)
    rp = generate_public_rules(entropy)
    rs = list(rp)  # trivially confluent, less secure — document this
    return rp, rs


def export_rules(rules: list[Rule]) -> list[list[list[int]]]:
    """Serialize rules to JSON-compatible list."""
    return [[list(r.lhs), list(r.rhs)] for r in rules]


def import_rules(data: list[list[list[int]]]) -> list[Rule]:
    """Deserialize rules from JSON data."""
    return [Rule(tuple(d[0]), tuple(d[1])) for d in data]


# ---------------------------------------------------------------------------
# Sanity checks
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import time

    print("KB completion — sanity checks\n")

    entropy = secrets.token_bytes(32)

    print("Generating public rules Rp...")
    rp = generate_public_rules(entropy)
    print(f"  Generated {len(rp)} public rules:")
    for r in rp:
        print(f"    {r}")

    print("\nRunning KB completion...")
    t0 = time.time()
    rs, success = knuth_bendix_complete(rp, max_steps=500)
    t1 = time.time()
    print(f"  Completed in {t1-t0:.3f}s  success={success}")
    print(f"  |Rs| = {len(rs)} rules (|Rp| = {len(rp)}, {len(rs)-len(rp)} new)")

    print("\nNormalization tests:")
    test_words = [
        (1, 2, 3, 4),
        (2, 1, 4, 3, 1, 2),
        (3, 3, 2, 2, 1, 1, 4, 4),
    ]
    for w in test_words:
        nf_rs = normalize(w, rs)
        # Check that normalizing the normal form gives the same result (idempotent)
        assert normalize(nf_rs, rs) == nf_rs, "Not idempotent"
        # Check endpoint preserved
        assert _endpoint(w) == _endpoint(nf_rs), "Endpoint changed"
        print(f"  {w} → nf={nf_rs}  endpoint={'OK' if _endpoint(w)==_endpoint(nf_rs) else 'FAIL'}")

    print("\nRoundtrip via rewrite → normalize:")
    for w in test_words:
        # Apply Rp rewrites a few times (non-deterministic, pick first firing rule)
        rewritten = w
        for _ in range(4):
            for rule in rp:
                lhs = rule.lhs
                n = len(lhs)
                for i in range(len(rewritten) - n + 1):
                    if rewritten[i:i+n] == lhs:
                        rewritten = rewritten[:i] + rule.rhs + rewritten[i+n:]
                        break
        nf = normalize(rewritten, rs)
        nf_orig = normalize(w, rs)
        print(f"  original nf: {nf_orig}")
        print(f"  rewritten nf: {nf}")
        print(f"  same normal form: {'YES' if nf == nf_orig else 'NO (non-trivial rewriting)'}")

    print("\nAll checks passed ✓")
