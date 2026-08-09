# Experiment: nonce-reuse differential leakage

**Status:** completed. **Relates to:** open problem 2 (nonce reuse, flagged in commit `e44f2cf` as the untested item after Path A was corrected).

## What this tests

`diffusion.py`'s docstring states its mod-4-addition-then-XOR-chain design was deliberately chosen to resist simple XOR-cancellation attacks. Under nonce reuse, the encode-mask entropy and diffusion seed become identical across two messages sharing a nonce, so an attacker who knows both plaintexts can compute their difference `Delta_in = raw(m1) XOR raw(m2)` for free (the shared mask cancels algebraically, no secret needed). The open question: does `Delta_in` predict anything about the observed ciphertext difference `Delta_out`?

## Method

Single-generator-flip differential test (mirrors the existing avalanche-test methodology in `diffusion.py`, but under a *known shared mask* instead of no mask). For each of several walk positions, many trials with fresh random keys (averaging over keyspace): measure the ciphertext-difference fraction under (a) a reused nonce with the known fixed `Delta_in`, and (b) independent fresh nonces (the normal operating condition, where no correlation is expected). Variance ratio (F = var_reused / var_fresh) quantifies the gap. A secondary check extends the pair-frequency methodology from `known_plaintext_pair_recovery.py` to a "codebook" scenario: many known plaintexts under one reused nonce, checking for aggregate bias.

## Result: real, statistically significant leak

```
block mode, n_keys=300, pairs_per_key=20 (n=6000 per position)
pos=  2  reused mean=0.816 var=0.0019  |  fresh mean=0.750 var=0.0023  |  F=0.85
pos= 20  reused mean=0.676 var=0.0142  |  fresh mean=0.750 var=0.0024  |  F=5.97
pos= 40  reused mean=0.649 var=0.0432  |  fresh mean=0.751 var=0.0024  |  F=18.13
pos= 60  reused mean=0.638 var=0.0889  |  fresh mean=0.749 var=0.0023  |  F=38.03
pos= 70  reused mean=0.872 var=0.0174  |  fresh mean=0.751 var=0.0024  |  F=7.35
pos= 78  reused mean=0.878 var=0.0209  |  fresh mean=0.750 var=0.0024  |  F=8.88

kb mode, n_keys=30, pairs_per_key=15 (n=450 per position -- the actual default cipher configuration)
pos=  2  reused mean=0.834 var=0.0017  |  fresh mean=0.750 var=0.0022  |  F=0.76
pos= 40  reused mean=0.627 var=0.0419  |  fresh mean=0.749 var=0.0024  |  F=17.69
pos= 60  reused mean=0.589 var=0.0868  |  fresh mean=0.750 var=0.0025  |  F=34.73
pos= 78  reused mean=0.912 var=0.0134  |  fresh mean=0.747 var=0.0024  |  F=5.61
```

At every position tested except the very start of the walk (position 2 of 80: F≈0.76-0.85, no detectable effect), reused-nonce ciphertext differences show dramatically higher variance than the fresh-nonce control — F-ratios of **~6x to 38x** in block mode and **~6x to 35x** in kb mode. Both figures are stable across repeated runs (rerun with fresh random samples: block F-ratios came back 5.81-36.58 on the first pass, 5.97-38.03 on the second; same pattern both times). At these sample sizes, ratios this large are not measurement noise.

**`diffusion.py`'s anti-cancellation design does not fully hold under nonce reuse.** The mod-4 addition chain prevents *simple* XOR-cancellation (an attacker can't just XOR two reused-nonce ciphertexts together and read off the plaintext difference directly, the way a pure-XOR stream cipher would fail) — but it does not prevent *distributional* leakage: the variance of the ciphertext-difference itself is a real signal correlated with where in the walk the known plaintext difference sits.

**The leak is specifically pairwise, not aggregate.** The secondary codebook-style check — 500 known plaintexts under one reused nonce, checking ciphertext-pair frequency in aggregate — showed no bias beyond the fresh-nonce baseline (χ²=6.18 and 18.04 on two runs, both *below* the 22.96 fresh-nonce reference from `known_plaintext_pair_recovery.py`). The leak only shows up when an attacker compares two ciphertexts they know are *related* (same nonce, known plaintext difference) — a single reused-nonce ciphertext, or many unrelated ones, doesn't look anomalous on its own.

## What this does and doesn't mean

**Does mean:** nonce reuse is a genuine, demonstrated confidentiality risk for this construction, not just a theoretical concern. An attacker with two known-plaintext ciphertexts under a reused nonce gains a statistically exploitable signal about where in the message they differ, via the variance/pattern of the ciphertext difference — a real side channel, strongest in the middle-to-late portion of the walk and near-absent at the very start.

**Doesn't mean (not tested here, stated so this isn't overclaimed):**
- Full plaintext recovery under nonce reuse. This experiment demonstrates a distinguishing signal, not a decryption attack. Building the latter from the former is real follow-on work.
- Anything about fresh-nonce security. Nonces are `secrets.token_bytes(16)` generated internally by `HonestCipher.encrypt()` today, not attacker-influenced — this is a fault-tolerance finding (what happens if the RNG fails or a future mode reuses nonces), not a break of the cipher as currently exposed.

## Reproducing this

`python3 docs/experiments/nonce_reuse_differential.py` — self-contained, no external files needed, runs in under a minute. Uses a length-bounded mask-stream helper (`mask_gens_for`) rather than `encoding.py`'s `_derive_start_and_mask` directly, because that function generates a full 64KB keystream (2048 SHA-256 calls) regardless of message length — fine for a single `encrypt()` call, prohibitively slow at the sample counts this experiment needs. Worth fixing in `encoding.py` itself as a performance cleanup (not a security issue) — not done here, out of scope for this experiment.
