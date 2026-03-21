"""
rewriter.py — Rewriting rule engine for H.O.N.E.S.T.

Two modes:
  mode='block' — keyed block substitution using XOR-equivalence classes (fast)
  mode='kb'    — keyed block substitution using Rs-equivalence classes (KB trapdoor)

Both modes use the same pair-substitution architecture but derive their
equivalence groups differently:

  block: pairs grouped by XOR endpoint (purely geometric)
  kb:    pairs grouped by Rs-normal form (algebraic, depends on private key)

KB mode implements the Knuth-Bendix completion trapdoor from the spec.
The private key Rs is required to compute the equivalence classes — an
attacker who only knows Rp sees a different grouping and cannot reconstruct
the correct substitution table.

Security distinction vs. block mode:
  block: equivalence groups are public (XOR sum is computable from public info)
  kb:    equivalence groups depend on Rs, which is private

Both modes are provably invertible by construction (bijective permutation
within each group).

Note: This is still not full LGIP — the hard problem requires the non-confluent
Rp/Rs architecture at walk level, not just at pair level. See construction.md
open problem 4. The KB trapdoor here is real; the LGIP security argument at
walk level requires the length-changing rule architecture described in the spec.
"""

from __future__ import annotations
import secrets
import hashlib
from .hypercube import GENERATORS


# ── Block substitution helpers ─────────────────────────────────────────────────

_ALL_PAIRS: dict[int, list[tuple[int, int]]] = {}
for _g1 in range(1, 5):
    for _g2 in range(1, 5):
        _xor = GENERATORS[_g1] ^ GENERATORS[_g2]
        _ALL_PAIRS.setdefault(_xor, []).append((_g1, _g2))
_ALL_PAIRS = {k: sorted(v) for k, v in _ALL_PAIRS.items()}


def _build_xor_groups() -> dict[int, list[tuple[int, int]]]:
    return {k: sorted(v) for k, v in _ALL_PAIRS.items()}


def _build_kb_groups(rs_rules) -> dict[tuple, list[tuple[int, int]]]:
    """
    Group generator pairs by their Rs-normal form.

    Pairs that normalize to the same word under Rs are Rs-equivalent and
    form a substitution group. This is the KB trapdoor: the grouping depends
    on Rs, which is private.
    """
    from .kb_completion import normalize
    groups: dict[tuple, list[tuple[int, int]]] = {}
    for g1 in range(1, 5):
        for g2 in range(1, 5):
            pair = (g1, g2)
            nf = normalize(pair, rs_rules)
            groups.setdefault(nf, []).append(pair)
    return groups


def _permutation_from_entropy(pairs: list, entropy_src, counter: list) -> list:
    """Fisher-Yates shuffle using hash-based entropy."""
    perm = list(pairs)
    for i in range(len(perm) - 1, 0, -1):
        raw = hashlib.sha256(entropy_src + counter[0].to_bytes(4, 'big')).digest()
        counter[0] += 1
        j = int.from_bytes(raw[:4], 'big') % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


# ── Core rewriting system ──────────────────────────────────────────────────────

class RewritingSystem:
    """
    Pair-substitution rewriting system.

    Stores a bijective forward table (pair → pair) and its inverse.
    Works identically for block and kb modes — only key generation differs.
    """

    def __init__(self, forward_table: dict, mode: str = 'block', kb_metadata: dict = None):
        self.forward_table = forward_table
        self.inverse_table = {v: k for k, v in forward_table.items()}
        self.mode = mode
        self._kb_metadata = kb_metadata  # Rp/Rs for KB mode export
        assert len(self.inverse_table) == len(self.forward_table), "Not a bijection"

    def _apply(self, walk, table):
        result = []
        i = 0
        while i < len(walk) - 1:
            pair = (walk[i], walk[i + 1])
            result.extend(table.get(pair, pair))
            i += 2
        if i < len(walk):
            result.append(walk[i])
        return result

    def rewrite(self, walk):
        return self._apply(walk, self.forward_table)

    def inverse_rewrite(self, walk):
        return self._apply(walk, self.inverse_table)

    def export(self) -> dict:
        base = {
            "mode": self.mode,
            "table": [[list(k), list(v)] for k, v in self.forward_table.items()]
        }
        if self.mode == 'kb' and self._kb_metadata:
            from .kb_completion import export_rules
            base["public_rules"]  = export_rules(self._kb_metadata['rp'])
            base["private_rules"] = export_rules(self._kb_metadata['rs'])
        return base

    @classmethod
    def from_export(cls, data: dict) -> 'RewritingSystem':
        mode = data.get("mode", "block")
        table = {tuple(e[0]): tuple(e[1]) for e in data["table"]}
        kb_meta = None
        if mode == 'kb' and "private_rules" in data:
            from .kb_completion import import_rules
            kb_meta = {
                'rp': import_rules(data["public_rules"]),
                'rs': import_rules(data["private_rules"]),
            }
        return cls(forward_table=table, mode=mode, kb_metadata=kb_meta)

    def __repr__(self):
        non_id = sum(1 for k, v in self.forward_table.items() if k != v)
        return f"RewritingSystem(mode={self.mode}, non-identity pairs={non_id})"


# ── Key generation ─────────────────────────────────────────────────────────────

def generate_key(entropy: bytes = None, mode: str = 'kb') -> RewritingSystem:
    """
    Generate a new substitution key.

    mode='kb'    — Rs-equivalence groups via KB completion (default)
    mode='block' — XOR-equivalence groups (fast, backward-compatible)
    """
    if entropy is None:
        entropy = secrets.token_bytes(32)

    counter = [0]

    if mode == 'kb':
        from .kb_completion import generate_kb_key
        rp, rs = generate_kb_key(entropy)
        groups = _build_kb_groups(rs)
        forward_table = {}
        for nf_key, pairs in groups.items():
            if len(pairs) == 1:
                forward_table[pairs[0]] = pairs[0]
            else:
                perm = _permutation_from_entropy(pairs, entropy, counter)
                for orig, subst in zip(sorted(pairs), perm):
                    forward_table[orig] = subst
        kb_meta = {'rp': rp, 'rs': rs}
        return RewritingSystem(forward_table=forward_table, mode='kb', kb_metadata=kb_meta)

    # Block mode: XOR-equivalence groups
    groups = _build_xor_groups()
    forward_table = {}
    for xor_sum, pairs in groups.items():
        if len(pairs) == 1:
            forward_table[pairs[0]] = pairs[0]
        elif len(pairs) == 2:
            bit = hashlib.sha256(entropy + counter[0].to_bytes(4, 'big')).digest()[0] & 1
            counter[0] += 1
            if bit:
                forward_table[pairs[0]] = pairs[1]
                forward_table[pairs[1]] = pairs[0]
            else:
                forward_table[pairs[0]] = pairs[0]
                forward_table[pairs[1]] = pairs[1]
        else:
            perm = _permutation_from_entropy(pairs, entropy, counter)
            for orig, subst in zip(pairs, perm):
                forward_table[orig] = subst

    return RewritingSystem(forward_table=forward_table, mode='block')


def export_key(rs: RewritingSystem) -> dict:
    return rs.export()


def import_key(data: dict) -> RewritingSystem:
    return RewritingSystem.from_export(data)


# ── Sanity checks ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from .hypercube import walk_endpoint
    import time

    print("Rewriting system — sanity checks\n")

    for mode in ('block', 'kb'):
        t0 = time.time()
        key = generate_key(mode=mode)
        t1 = time.time()
        print(f"Mode: {mode}  (keygen {(t1-t0)*1000:.1f}ms)")
        print(f"  {key}")

        walks = [
            [1, 2, 3, 1, 4, 2],
            [1, 1, 2, 2, 3, 3, 4, 4],
            list(range(1, 5)) * 10,
        ]
        for w in walks:
            enc = key.rewrite(w)
            dec = key.inverse_rewrite(enc)
            ep_ok = walk_endpoint(5, w) == walk_endpoint(5, enc)
            rt_ok = dec == w
            print(f"  len={len(w):3d}: roundtrip={'OK' if rt_ok else 'FAIL'}  "
                  f"endpoint={'OK' if ep_ok else 'FAIL'}")

        k2 = import_key(export_key(key))
        w = [1, 2, 3, 4, 1, 2, 3, 4]
        enc = key.rewrite(w)
        assert k2.inverse_rewrite(enc) == w, "export/import roundtrip failed"
        print(f"  export/import: OK\n")
