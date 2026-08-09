"""
demo.py — H.O.N.E.S.T. demonstration

Shows: key generation, encrypt/decrypt roundtrip, avalanche effect,
walk length scaling, and honest caveats.

Run: python3 demo.py
"""

import sys
import os
import time
import json
import secrets

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from honest.cipher import HonestCipher
from honest.encoding import encode
from honest.diffusion import diffuse, diffusion_key_seed
from honest.hypercube import node_to_bits
import hashlib

SEP = "─" * 60


def section(title):
    print(f"\n{SEP}\n  {title}\n{SEP}")


def demo_keygen():
    section("1. Key Generation")
    t0 = time.perf_counter()
    cipher = HonestCipher.generate()          # KB mode + diffusion
    ms = (time.perf_counter() - t0) * 1000
    kd = cipher.export_key()
    print(f"  Mode:     {kd.get('mode', 'block')}")
    print(f"  Keygen:   {ms:.1f}ms")
    print(f"  Key size: {len(json.dumps(kd))} bytes (JSON)")
    n_private = len(kd.get('private_rules', kd.get('table', [])))
    print(f"  Private rules / pairs: {n_private}")
    return cipher


def demo_roundtrip(cipher):
    section("2. Encrypt / Decrypt Roundtrip")
    messages = [
        b"Hello from H.O.N.E.S.T.",
        b"Post-quantum research prototype - not production crypto.",
        b"A" * 128,
    ]
    for msg in messages:
        t0 = time.perf_counter()
        ct = cipher.encrypt(msg)
        t_enc = (time.perf_counter() - t0) * 1000
        t0 = time.perf_counter()
        pt = cipher.decrypt(ct)
        t_dec = (time.perf_counter() - t0) * 1000
        assert pt == msg
        ratio = len(ct["walk"]) / max(len(msg), 1)
        print(f"\n  [{len(msg)}B] {msg[:45]!r}{'...' if len(msg) > 45 else ''}")
        print(f"  Walk: {len(ct['walk'])} generators ({ratio:.1f}×)  "
              f"Node: {node_to_bits(ct['start'])}  "
              f"Enc: {t_enc:.1f}ms  Dec: {t_dec:.1f}ms  ✓")


def demo_avalanche(cipher):
    section("3. Avalanche Effect")
    print("  Measures diffusion layer output — 1-generator change in encoded walk.\n")

    kd = cipher.export_key()
    key_data = json.dumps(kd, sort_keys=True).encode()
    key_hash = hashlib.sha256(key_data).digest()
    nonce = b'\x00' * 16
    dseed = diffusion_key_seed(key_hash, nonce)
    entropy = secrets.token_bytes(65536)

    msg1 = b"Post-quantum demo message 12345."
    msg2 = bytearray(msg1); msg2[0] ^= 0x01

    _, w1 = encode(msg1, entropy)
    _, w2 = encode(bytes(msg2), entropy)

    # Raw encoding difference
    raw_diff = sum(a != b for a, b in zip(w1, w2))
    raw_pct = 100 * raw_diff / max(len(w1), len(w2))

    # After diffusion
    d1 = diffuse(w1, dseed)
    d2 = diffuse(w2, dseed)
    diff_after = sum(a != b for a, b in zip(d1, d2))
    diff_pct = 100 * diff_after / max(len(d1), len(d2))

    print(f"  Original:     {msg1!r}")
    print(f"  1-byte flip:  {bytes(msg2)!r}")
    print(f"\n  Raw encoding:      {raw_diff}/{len(w1)} differ ({raw_pct:.1f}%)  ← known weak")
    print(f"  After diffusion:   {diff_after}/{len(d1)} differ ({diff_pct:.1f}%)  "
          f"{'← strong ✓' if diff_pct > 40 else '← needs work'}")


def demo_walk_stats(cipher):
    section("4. Walk Length Scaling")
    print(f"  Formula: walk_len = 4 × (4 + message_bytes)\n")
    print(f"  {'Msg (B)':>8}  {'Walk':>8}  {'×':>6}  {'Enc (ms)':>10}")
    print(f"  {'─'*8}  {'─'*8}  {'─'*6}  {'─'*10}")
    for size in [8, 16, 32, 64, 128, 256, 512]:
        msg = secrets.token_bytes(size)
        t0 = time.perf_counter()
        ct = cipher.encrypt(msg)
        ms = (time.perf_counter() - t0) * 1000
        ratio = len(ct["walk"]) / size
        print(f"  {size:>8}  {len(ct['walk']):>8}  {ratio:>5.1f}×  {ms:>9.1f}")


def demo_caveats():
    section("5. Honest Caveats")
    caveats = [
        ("LGIP hardness is a conjecture.", True),
        ("No formal IND-CPA or IND-CCA2 proof exists.", True),
        ("KB completion is pair-level, not full word-level LGIP.", True),
        ("No message authentication — ciphertext is malleable.", True),
        ("Not constant-time. No side-channel analysis.", True),
        ("Walk expansion ~4× is high vs AES-GCM (~0×).", True),
        ("Q₄ contributes zero computational hardness.", True),
        ("This is a research prototype. Not production crypto.", True),
    ]
    for text, warn in caveats:
        print(f"  {'⚠' if warn else ' '}  {text}")


def main():
    print("\nH.O.N.E.S.T. — Hypercube-Oriented Nonlinear Encryption")
    print("         with Structured Trapdoors  [v0.2.0 research prototype]\n")

    cipher = demo_keygen()
    demo_roundtrip(cipher)
    demo_avalanche(cipher)
    demo_walk_stats(cipher)
    demo_caveats()

    print(f"\n{SEP}\n  Done.\n{SEP}\n")


if __name__ == "__main__":
    main()
