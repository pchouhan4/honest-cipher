# Mathematical construction

**Version 0.1 — research draft**

Written for someone who wants to understand the construction well enough to attack it. If something is unclear, open an issue — clarity here matters for getting good cryptanalysis.

---

## 1. Preliminaries

### 1.1 Alphabet and words

Let Σ = {σ₁, σ₂, σ₃, σ₄} be an alphabet of four generators. A word is a finite sequence of generators: w = σᵢ₁σᵢ₂...σᵢₙ ∈ Σ\*. The empty word is ε. Word concatenation is uv.

### 1.2 The 4D hypercube Q₄

Q₄ = (V, E) where V = {0,1}⁴ (16 vertices as 4-bit strings) and edges connect vertices differing in exactly one bit.

Each generator σᵢ is a bit-flip operation:

```
mask(σ₁) = 0001₂ = 1
mask(σ₂) = 0010₂ = 2
mask(σ₃) = 0100₂ = 4
mask(σ₄) = 1000₂ = 8
```

### 1.3 Semantic mapping

φ: Σ\* → V is defined by φ(ε) = 0000 and φ(wσᵢ) = φ(w) XOR mask(σᵢ).

**Lemma 1.1:** φ(uv) = φ(u) XOR φ(v). (φ is a monoid homomorphism.)

**Consequence:** φ is computable in O(n). Q₄ contributes zero computational hardness — the endpoint of any walk is trivially computable by XOR. All hardness lives in the rewriting system.

---

## 2. Rewriting systems

### 2.1 Definitions

A rewriting rule (l, r) ∈ Σ\* × Σ\* is endpoint-preserving if φ(l) = φ(r). A rewriting system R is a set of endpoint-preserving rules. We write w →R w' if w' is obtained by replacing one occurrence of some l with r where (l,r) ∈ R. We write w →\*R w' for the reflexive-transitive closure.

A system R is confluent (Church-Rosser) if whenever w →\*R u and w →\*R v, there exists t with u →\*R t and v →\*R t. R is terminating if no infinite reduction sequence exists. R is complete if it is both confluent and terminating — unique normal forms exist.

### 2.2 Two-system architecture

**Public rules Rp:** terminating, non-confluent, endpoint-preserving. Published as part of the public key.

**Private rules Rs:** a complete extension of Rp, obtained via Knuth-Bendix completion of Rp ∪ {additional rules}. The private key. Rs enables unique canonicalization.

The trapdoor is the completion itself — without Rs, the normal form of a ciphertext walk is ambiguous. With Rs, it is unique and efficiently computable.

---

## 3. Key generation

```
KeyGen():
  1. Choose Rp: endpoint-preserving rules, non-confluent
  2. Run Knuth-Bendix completion on Rp → obtain Rs
     (retry if KB fails to terminate)
  3. Public key:  (Q₄, Rp)
  4. Private key: Rs
```

**Critical pair analysis:** KB completion resolves overlaps between rules. For each critical pair (u, v) from Rp, either u and v join under Rp (non-problematic) or they don't (a new rule is added to Rs). The rules in Rs \ Rp constitute the private information.

**Security note:** if Rp has few critical pairs, Rs ≈ Rp and the private key contains little information not already in the public key. Parameter selection must ensure |Rs \ Rp| is cryptographically significant.

---

## 4. Encryption

### 4.1 Encoding: plaintext → walk

Given plaintext m of n bytes:

1. Prepend 4-byte length header: payload = len(m) ‖ m
2. Expand entropy seed via SHA-256 to produce mask stream M
3. For each 2-bit chunk bⱼ of payload (high bits first): compute bⱼ' = bⱼ XOR M[j] mod 4, map to generator σ = BITS_TO_GEN[bⱼ'], append to walk

Output: starting node v₀ (from entropy), walk w ∈ Σ\*. Walk length: |w| = 4 × (4 + n).

### 4.2 Full pipeline

```
Encrypt(m, public_key=(Q₄, Rp), entropy):
  nonce    ← random 16 bytes
  entropy' ← SHA-256(key_hash ‖ nonce)
  (v₀, w) ← Encode(m, entropy')
  w'       ← rewrite(w, Rp)
  return (nonce, v₀, w')

Decrypt(nonce, v₀, w', private_key=Rs):
  entropy' ← SHA-256(key_hash ‖ nonce)
  w        ← normal_form(w', Rs)
  m        ← Decode(v₀, w, entropy')
  return m
```

---

## 5. Security

### 5.1 LGIP

**Definition:** Given (Σ, Rp, w'), find w ∈ Σ\* such that w →\*Rp w' and w is Rs-minimal.

**Conjecture:** LGIP is computationally hard on average over a natural distribution of instances. This is a conjecture. No proof. No reduction to a known hard problem.

### 5.2 Hardness intuition

Without Rs, an adversary must find any preimage of w' under Rp (exponentially many candidates) and then identify the Rs-minimal one among them. Step 2 requires knowledge of Rs — without it, the adversary cannot distinguish the canonical preimage from the non-canonical ones. This is intuition, not a proof.

### 5.3 Quantum security

Grover gives quadratic speedup on unstructured search, halving the effective security parameter. Whether the rewriting structure admits additional quantum speedup beyond Grover is unknown. The accurate claim is "no known quantum polynomial-time algorithm for LGIP" — not "quantum-safe."

---

## 6. Current implementation

**Diffusion layer (v0.2).** A multi-round CBC-like chaining over generator values in {0,1,2,3} (generators 1-4 mapped to 0-3 for arithmetic). Each round applies a key-dependent addition chain (forward) followed by an XOR chain (backward). A 1-generator change propagates to ~65% of output positions. The layer is invertible given the key — no information is lost. See `src/honest/diffusion.py`.

**KB completion trapdoor (v0.2).** The private key is now generated via Knuth-Bendix completion of the public rule set Rp, producing the private complete extension Rs. Generator pairs are grouped by their Rs-normal form rather than XOR sum. The key is a bijective permutation within each Rs-equivalence class — endpoint-preserving and provably invertible.

Distinction from full LGIP: this is pair-level KB (the groups are determined by Rs, but encryption is still a bijective substitution). Full LGIP requires word-level non-confluent rewriting where multiple walks reduce to the same ciphertext walk. That is open problem 4 as originally defined — the pair-level version here is the first concrete step.

**Diffusion + rewriting pipeline:**



Implementation: , , .

---

## 7. Parameters

Current choices are heuristic. Formal analysis is open problem 7.

| Parameter | Current value | Notes |
|-----------|--------------|-------|
| Dimension n | 4 | Fixed. Full LGIP needs larger n. |
| \|Σ\| | 4 | Matches dimension. |
| Walk length | 4 × (4 + \|m\|) | Linear in message length. |
| Key size | ~300 bytes | Permutation table, JSON. |

For a full LGIP instantiation, n should be the security parameter (e.g., 128 or 256) with \|Σ\| = n and walk length ℓ ≈ n log n. These choices are not yet formally justified.
