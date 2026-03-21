"""
tests/test_honest.py — Test suite for H.O.N.E.S.T.

Run with: pytest tests/ -v
"""

import sys
import os
import secrets
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from honest.hypercube import (
    apply_walk, walk_endpoint, apply_generator,
    neighbors, node_to_bits, N_VERTICES, GENERATORS
)
from honest.rewriter import generate_key, export_key, import_key, RewritingSystem
from honest.encoding import encode, decode
from honest.cipher import HonestCipher


# ── Hypercube Tests ────────────────────────────────────────────────────────────

class TestHypercube:

    def test_vertex_count(self):
        assert N_VERTICES == 16

    def test_generator_count(self):
        assert len(GENERATORS) == 4

    def test_double_flip_identity(self):
        """Applying same generator twice returns to start."""
        for node in range(N_VERTICES):
            for gen in [1, 2, 3, 4]:
                assert apply_walk(node, [gen, gen]) == node

    def test_all_generators_distinct(self):
        """All four generators produce different results from node 0."""
        results = [apply_generator(0, g) for g in [1, 2, 3, 4]]
        assert len(set(results)) == 4

    def test_endpoint_commutativity(self):
        """Walk endpoint is XOR-based — order of distinct generators doesn't change endpoint."""
        assert walk_endpoint(0, [1, 2]) == walk_endpoint(0, [2, 1])
        assert walk_endpoint(0, [1, 2, 3, 4]) == walk_endpoint(0, [4, 3, 2, 1])

    def test_each_node_has_four_neighbors(self):
        for node in range(N_VERTICES):
            nbrs = neighbors(node)
            assert len(nbrs) == 4

    def test_node_to_bits_format(self):
        assert node_to_bits(0) == "0000"
        assert node_to_bits(15) == "1111"
        assert node_to_bits(5) == "0101"

    def test_walk_full_cycle(self):
        """Walk through all four generators from 0 reaches 1111."""
        assert walk_endpoint(0, [1, 2, 3, 4]) == 0b1111

    def test_invalid_generator_raises(self):
        with pytest.raises(ValueError):
            apply_generator(0, 5)


# ── Rewriting System Tests ─────────────────────────────────────────────────────

class TestRewritingSystem:

    def setup_method(self):
        self.key = generate_key()

    def test_roundtrip_even_length(self):
        walk = [1, 2, 3, 4, 1, 2]
        enc = self.key.rewrite(walk)
        dec = self.key.inverse_rewrite(enc)
        assert dec == walk

    def test_roundtrip_odd_length(self):
        """Odd-length walks: last generator passes through unchanged."""
        walk = [1, 2, 3, 4, 1]
        enc = self.key.rewrite(walk)
        dec = self.key.inverse_rewrite(enc)
        assert dec == walk

    def test_endpoint_preserved(self):
        """Rewriting must not change walk endpoint."""
        walk = [1, 2, 3, 1, 4, 2, 3, 4]
        enc = self.key.rewrite(walk)
        start = 0b0101
        assert walk_endpoint(start, walk) == walk_endpoint(start, enc)

    def test_key_export_import_roundtrip(self):
        data = export_key(self.key)
        restored = import_key(data)
        walk = [1, 2, 3, 4, 2, 1]
        assert self.key.rewrite(walk) == restored.rewrite(walk)

    def test_different_keys_different_output(self):
        key2 = generate_key()
        walk = [1, 2, 3, 4, 1, 2, 3, 4]
        # Different keys should (almost always) produce different rewrites
        # Not guaranteed but overwhelmingly likely
        results = [self.key.rewrite(walk), key2.rewrite(walk)]
        # At minimum, both should decrypt correctly
        assert self.key.inverse_rewrite(results[0]) == walk
        assert key2.inverse_rewrite(results[1]) == walk

    def test_bijection_property(self):
        """forward_table must be a bijection."""
        fwd = self.key.forward_table
        inv = self.key.inverse_table
        assert len(fwd) == len(inv)
        for k, v in fwd.items():
            assert inv[v] == k

    def test_empty_walk(self):
        assert self.key.rewrite([]) == []
        assert self.key.inverse_rewrite([]) == []

    def test_single_generator(self):
        walk = [3]
        enc = self.key.rewrite(walk)
        dec = self.key.inverse_rewrite(enc)
        assert dec == walk


# ── Encoding Tests ─────────────────────────────────────────────────────────────

class TestEncoding:

    def setup_method(self):
        self.entropy = secrets.token_bytes(32)

    def test_roundtrip_short(self):
        msg = b"Hello"
        start, walk = encode(msg, self.entropy)
        assert decode(start, walk, self.entropy) == msg

    def test_roundtrip_empty(self):
        msg = b""
        start, walk = encode(msg, self.entropy)
        assert decode(start, walk, self.entropy) == msg

    def test_roundtrip_binary(self):
        msg = bytes(range(256))
        start, walk = encode(msg, self.entropy)
        assert decode(start, walk, self.entropy) == msg

    def test_roundtrip_long(self):
        msg = secrets.token_bytes(1000)
        start, walk = encode(msg, self.entropy)
        assert decode(start, walk, self.entropy) == msg

    def test_walk_length_formula(self):
        """Walk length = 4 * (4 + len(msg)) generators."""
        for size in [0, 1, 10, 100]:
            msg = b"A" * size
            _, walk = encode(msg, self.entropy)
            assert len(walk) == 4 * (4 + size)

    def test_different_entropy_different_walk(self):
        msg = b"Same message"
        entropy2 = secrets.token_bytes(32)
        _, walk1 = encode(msg, self.entropy)
        _, walk2 = encode(msg, entropy2)
        assert walk1 != walk2

    def test_all_generators_in_valid_range(self):
        msg = b"Test message"
        _, walk = encode(msg, self.entropy)
        assert all(g in {1, 2, 3, 4} for g in walk)


# ── Cipher Tests ───────────────────────────────────────────────────────────────

class TestCipher:

    def setup_method(self):
        self.cipher = HonestCipher.generate()

    def test_roundtrip_basic(self):
        msg = b"Hello, world!"
        assert self.cipher.decrypt(self.cipher.encrypt(msg)) == msg

    def test_roundtrip_empty(self):
        msg = b""
        assert self.cipher.decrypt(self.cipher.encrypt(msg)) == msg

    def test_roundtrip_binary(self):
        msg = bytes(range(256))
        assert self.cipher.decrypt(self.cipher.encrypt(msg)) == msg

    def test_roundtrip_large(self):
        msg = secrets.token_bytes(4096)
        assert self.cipher.decrypt(self.cipher.encrypt(msg)) == msg

    def test_nonce_randomization(self):
        """Same plaintext encrypted twice should produce different ciphertexts."""
        msg = b"Same message"
        ct1 = self.cipher.encrypt(msg)
        ct2 = self.cipher.encrypt(msg)
        assert ct1["nonce"] != ct2["nonce"]
        assert ct1["walk"] != ct2["walk"]

    def test_ciphertext_structure(self):
        ct = self.cipher.encrypt(b"test")
        assert "nonce" in ct
        assert "start" in ct
        assert "walk" in ct
        assert isinstance(ct["nonce"], str)
        assert isinstance(ct["start"], int)
        assert isinstance(ct["walk"], list)

    def test_key_export_import(self):
        msg = b"Key serialization test"
        ct = self.cipher.encrypt(msg)
        key_data = self.cipher.export_key()
        restored = HonestCipher.from_key_dict(key_data)
        assert restored.decrypt(ct) == msg

    def test_wrong_key_fails(self):
        msg = b"Secret message"
        ct = self.cipher.encrypt(msg)
        wrong_cipher = HonestCipher.generate()
        # Wrong key produces garbled output — not necessarily an exception
        # but should not produce the correct plaintext
        try:
            result = wrong_cipher.decrypt(ct)
            assert result != msg, "Wrong key should not decrypt correctly"
        except Exception:
            pass  # Exception on wrong key is also acceptable

    def test_endpoint_preserved_through_encryption(self):
        """The rewriting step must not change walk endpoint."""
        from honest.hypercube import apply_walk
        from honest.encoding import encode, entropy_from_key_and_nonce
        import hashlib, json

        msg = b"Endpoint test"
        ct = self.cipher.encrypt(msg)

        nonce = bytes.fromhex(ct["nonce"])
        key_data = json.dumps(self.cipher.export_key(), sort_keys=True).encode()
        key_hash = hashlib.sha256(key_data).digest()
        from honest.encoding import entropy_from_key_and_nonce
        entropy = entropy_from_key_and_nonce(key_hash, nonce)

        from honest.encoding import encode
        start, original_walk = encode(msg, entropy)
        rewritten_walk = ct["walk"]

        assert apply_walk(start, original_walk) == apply_walk(start, rewritten_walk)


# ── Known Limitations (documented, not bugs) ──────────────────────────────────

class TestKnownLimitations:
    """
    These tests document known limitations of the current construction.
    They are expected to fail or demonstrate weakness.
    They exist to be honest about the system's current state.
    """

    def test_avalanche_is_weak(self):
        """
        KNOWN LIMITATION: 1-bit plaintext change affects ~1% of ciphertext walk.
        A production cipher should achieve ~50% (strict avalanche criterion).
        This is the most significant known cryptographic weakness.
        Diffusion layer is required — not yet implemented.
        """
        from honest.encoding import encode
        entropy = secrets.token_bytes(32)
        msg1 = b"Post-quantum demo message 12345."
        msg2 = bytearray(msg1)
        msg2[0] ^= 0x01
        _, walk1 = encode(msg1, entropy)
        _, walk2 = encode(bytes(msg2), entropy)
        differ = sum(a != b for a, b in zip(walk1, walk2))
        pct = 100 * differ / len(walk1)
        # Document the actual number, assert it's weak
        assert pct < 10, f"Avalanche is {pct:.1f}% — if this passes 50%, diffusion is working"

    def test_hypercube_contributes_no_hardness(self):
        """
        KNOWN LIMITATION: Q4 endpoint is computable in O(n) by XOR.
        The hypercube provides zero computational hardness.
        All security must come from the rewriting system.
        """
        walk = [1, 2, 3, 1, 4, 2, 3]
        start = 0b0101
        # Compute endpoint by XOR directly
        xor_result = start
        for g in walk:
            xor_result ^= GENERATORS[g]
        # Must equal apply_walk
        assert xor_result == apply_walk(start, walk)

    def test_no_message_authentication(self):
        """
        KNOWN LIMITATION: Ciphertext is malleable.
        No MAC. No AEAD. An attacker can modify the walk without detection.
        """
        cipher = HonestCipher.generate()
        ct = cipher.encrypt(b"Original message")
        # Flip a generator in the walk — this goes undetected
        ct_modified = dict(ct)
        ct_modified["walk"] = list(ct["walk"])
        ct_modified["walk"][0] = (ct["walk"][0] % 4) + 1
        # No authentication error raised
        try:
            cipher.decrypt(ct_modified)
            authenticated = False
        except Exception:
            authenticated = True
        assert not authenticated, "No authentication currently implemented — expected"


# ── Diffusion Tests ────────────────────────────────────────────────────────────

class TestDiffusion:

    def setup_method(self):
        self.key_seed = secrets.token_bytes(32)

    def _make_walk(self, n=128):
        return [secrets.randbelow(4) + 1 for _ in range(n)]

    def test_roundtrip_empty(self):
        from honest.diffusion import diffuse, undiffuse
        assert undiffuse(diffuse([], self.key_seed), self.key_seed) == []

    def test_roundtrip_small(self):
        from honest.diffusion import diffuse, undiffuse
        for n in [1, 2, 4, 8, 16]:
            w = self._make_walk(n)
            assert undiffuse(diffuse(w, self.key_seed), self.key_seed) == w

    def test_roundtrip_large(self):
        from honest.diffusion import diffuse, undiffuse
        for n in [64, 128, 512]:
            w = self._make_walk(n)
            assert undiffuse(diffuse(w, self.key_seed), self.key_seed) == w

    def test_output_in_range(self):
        from honest.diffusion import diffuse
        w = self._make_walk(64)
        d = diffuse(w, self.key_seed)
        assert all(g in {1, 2, 3, 4} for g in d)

    def test_different_keys_produce_different_output(self):
        from honest.diffusion import diffuse
        w = self._make_walk(64)
        d1 = diffuse(w, secrets.token_bytes(32))
        d2 = diffuse(w, secrets.token_bytes(32))
        assert d1 != d2

    def test_avalanche_strong(self):
        """A 1-generator change should affect >40% of output positions."""
        from honest.diffusion import diffuse
        base = self._make_walk(128)
        flip = list(base)
        flip[0] = (flip[0] % 4) + 1  # change first generator
        d_base = diffuse(base, self.key_seed)
        d_flip = diffuse(flip, self.key_seed)
        differ = sum(a != b for a, b in zip(d_base, d_flip))
        pct = 100 * differ / len(d_base)
        assert pct > 40, f"Avalanche too weak: {pct:.1f}% (need >40%)"

    def test_avalanche_midpoint(self):
        """Change in middle of walk still propagates widely."""
        from honest.diffusion import diffuse
        base = self._make_walk(128)
        flip = list(base)
        flip[63] = (flip[63] % 4) + 1
        d_base = diffuse(base, self.key_seed)
        d_flip = diffuse(flip, self.key_seed)
        differ = sum(a != b for a, b in zip(d_base, d_flip))
        pct = 100 * differ / len(d_base)
        assert pct > 40, f"Mid-walk avalanche too weak: {pct:.1f}%"

    def test_deterministic(self):
        """Same walk + same seed always produces same output."""
        from honest.diffusion import diffuse
        w = self._make_walk(32)
        d1 = diffuse(w, self.key_seed)
        d2 = diffuse(w, self.key_seed)
        assert d1 == d2


# ── KB Completion Tests ────────────────────────────────────────────────────────

class TestKBCompletion:

    def test_generates_public_rules(self):
        from honest.kb_completion import generate_public_rules
        rp = generate_public_rules(secrets.token_bytes(32))
        assert len(rp) > 0

    def test_all_rules_endpoint_preserving(self):
        from honest.kb_completion import generate_public_rules, _endpoint
        rp = generate_public_rules(secrets.token_bytes(32))
        for rule in rp:
            assert _endpoint(rule.lhs) == _endpoint(rule.rhs), \
                f"Endpoint not preserved: {rule}"

    def test_completion_terminates(self):
        from honest.kb_completion import generate_public_rules, knuth_bendix_complete
        rp = generate_public_rules(secrets.token_bytes(32))
        rs, success = knuth_bendix_complete(rp, max_steps=500)
        assert len(rs) >= len(rp), "Completion removed rules"

    def test_rs_is_superset_of_rp(self):
        from honest.kb_completion import generate_public_rules, knuth_bendix_complete
        rp = generate_public_rules(secrets.token_bytes(32))
        rs, _ = knuth_bendix_complete(rp, max_steps=500)
        rp_set = set((r.lhs, r.rhs) for r in rp)
        rs_set = set((r.lhs, r.rhs) for r in rs)
        assert rp_set.issubset(rs_set), "Rs must contain all Rp rules"

    def test_normalization_preserves_endpoint(self):
        from honest.kb_completion import generate_kb_key, normalize, _endpoint
        rp, rs = generate_kb_key(secrets.token_bytes(32))
        test_words = [(1,2,3,4), (2,1,4,3,1,2), (3,3,2,2,1,1,4,4)]
        for w in test_words:
            nf = normalize(w, rs)
            assert _endpoint(w) == _endpoint(nf), f"Endpoint changed for {w}"

    def test_normalization_idempotent(self):
        from honest.kb_completion import generate_kb_key, normalize
        rp, rs = generate_kb_key(secrets.token_bytes(32))
        test_words = [(1,2,3,4), (2,1,4,3), (1,1,2,2,3,3)]
        for w in test_words:
            nf = normalize(w, rs)
            assert normalize(nf, rs) == nf, f"Normalization not idempotent for {w}"

    def test_rp_rewrite_rs_normalize_consistent(self):
        """Applying Rp rules then normalizing under Rs gives the same Rs-normal form."""
        from honest.kb_completion import generate_kb_key, normalize
        rp, rs = generate_kb_key(secrets.token_bytes(32))
        w = (1, 2, 3, 4, 2, 1)
        nf_direct = normalize(w, rs)
        # Apply one Rp rule pass
        rewritten = w
        for rule in rp:
            lhs = rule.lhs
            n = len(lhs)
            for i in range(len(rewritten) - n + 1):
                if rewritten[i:i+n] == lhs:
                    rewritten = rewritten[:i] + rule.rhs + rewritten[i+n:]
                    break
        nf_via_rp = normalize(rewritten, rs)
        assert nf_direct == nf_via_rp, "Rs normal form not stable under Rp rewrites"

    def test_export_import_rules(self):
        from honest.kb_completion import generate_kb_key, export_rules, import_rules, normalize
        rp, rs = generate_kb_key(secrets.token_bytes(32))
        rs_back = import_rules(export_rules(rs))
        w = (1, 2, 3, 4, 2, 1, 3)
        assert normalize(w, rs) == normalize(w, rs_back)


# ── KB Cipher Tests ────────────────────────────────────────────────────────────

class TestKBCipher:

    def test_keygen_produces_kb_mode(self):
        cipher = HonestCipher.generate(mode='kb')
        kd = cipher.export_key()
        assert kd.get("mode") == "kb"

    def test_roundtrip_empty(self):
        cipher = HonestCipher.generate(mode='kb')
        assert cipher.decrypt(cipher.encrypt(b"")) == b""

    def test_roundtrip_short(self):
        cipher = HonestCipher.generate(mode='kb')
        msg = b"Hello, post-quantum world."
        assert cipher.decrypt(cipher.encrypt(msg)) == msg

    def test_roundtrip_binary(self):
        cipher = HonestCipher.generate(mode='kb')
        msg = bytes(range(256))
        assert cipher.decrypt(cipher.encrypt(msg)) == msg

    def test_roundtrip_4kb(self):
        cipher = HonestCipher.generate(mode='kb')
        msg = secrets.token_bytes(4096)
        assert cipher.decrypt(cipher.encrypt(msg)) == msg

    def test_nonce_randomization(self):
        cipher = HonestCipher.generate(mode='kb')
        ct1 = cipher.encrypt(b"same message")
        ct2 = cipher.encrypt(b"same message")
        assert ct1["nonce"] != ct2["nonce"]
        assert ct1["walk"] != ct2["walk"]

    def test_wrong_key_fails(self):
        c1 = HonestCipher.generate(mode='kb')
        c2 = HonestCipher.generate(mode='kb')
        ct = c1.encrypt(b"secret")
        result = c2.decrypt(ct)
        assert result != b"secret"

    def test_export_import_roundtrip(self):
        c = HonestCipher.generate(mode='kb')
        ct = c.encrypt(b"key serialization test")
        c2 = HonestCipher.from_key_dict(c.export_key())
        assert c2.decrypt(ct) == b"key serialization test"

    def test_endpoint_preserved(self):
        from honest.hypercube import walk_endpoint
        c = HonestCipher.generate(mode='kb')
        msg = b"endpoint test"
        ct = c.encrypt(msg)
        # Re-encrypt without diffusion to test raw rewriting endpoint
        from honest.encoding import encode, entropy_from_key_and_nonce
        import hashlib, json
        from honest.rewriter import export_key
        nonce = bytes.fromhex(ct["nonce"])
        key_data = json.dumps(export_key(c.key), sort_keys=True).encode()
        key_hash = hashlib.sha256(key_data).digest()
        entropy = entropy_from_key_and_nonce(key_hash, nonce)
        start, walk = encode(msg, entropy)
        cw = c.key.rewrite(walk)
        assert walk_endpoint(start, walk) == walk_endpoint(start, cw)


# ── Update: Known Limitations ──────────────────────────────────────────────────

class TestKnownLimitationsUpdated:

    def test_avalanche_with_diffusion_is_strong(self):
        """With diffusion, avalanche should be >40% (was ~1% in block-only mode)."""
        from honest.encoding import encode
        from honest.diffusion import diffuse, diffusion_key_seed
        import hashlib, json
        from honest.rewriter import export_key

        cipher = HonestCipher.generate(mode='kb')
        key_data = json.dumps(export_key(cipher.key), sort_keys=True).encode()
        key_hash = hashlib.sha256(key_data).digest()

        entropy = secrets.token_bytes(65536)
        key_seed = diffusion_key_seed(key_hash, b'\x00' * 16)

        msg1 = b"Post-quantum demo message 12345."
        msg2 = bytearray(msg1); msg2[0] ^= 0x01

        _, w1 = encode(msg1, entropy)
        _, w2 = encode(bytes(msg2), entropy)

        d1 = diffuse(w1, key_seed)
        d2 = diffuse(w2, key_seed)

        differ = sum(a != b for a, b in zip(d1, d2))
        pct = 100 * differ / max(len(d1), len(d2))
        assert pct > 40, f"Avalanche with diffusion too weak: {pct:.1f}%"

    def test_no_mac(self):
        """Ciphertext is still malleable — no authentication."""
        cipher = HonestCipher.generate()
        ct = cipher.encrypt(b"original")
        ct_tampered = dict(ct)
        ct_tampered["walk"] = [((g % 4) + 1) for g in ct["walk"]]
        result = cipher.decrypt(ct_tampered)
        assert result != b"original", "Ciphertext should be malleable (no MAC)"

    def test_no_formal_security_proof(self):
        """Placeholder: hardness of LGIP is a conjecture, not a theorem."""
        assert True  # This test documents, not verifies
