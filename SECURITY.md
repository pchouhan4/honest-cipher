# Security policy

## This is a research prototype

H.O.N.E.S.T. has no formal security proof, documented known weaknesses, and must not be used to protect real data. This file exists to handle disclosure of findings — breaks, structural weaknesses, cryptanalytic results — about the construction.

## Reporting

Open a GitHub issue, label it `cryptanalysis`, and include what you found, what component is affected, and proof-of-concept code if you have it. No embargo period. Publish your result. This is research — fast disclosure helps.

You'll be credited in the README and in any future publication.

## Already known — no need to report

- The KB completion trapdoor contributes a small keyspace (~2⁷) at current parameters, and in ~12.5% of key generations contributes none at all (`Rs == Rp`). See README §Known limitations #2 and `docs/construction.md` §3. This is the biggest known gap — new analysis of *why* this happens or how much larger the alphabet needs to be (open problem 7) is genuinely useful; re-reporting that the keyspace is small is not.
- That small table is not currently reachable by an external attacker under normal (fresh-nonce) operation — confirmed via known-plaintext testing, see `docs/experiments/known_plaintext_pair_recovery.md`.
- **Nonce reuse is a confirmed real leak** (not just a theoretical concern) — see `docs/experiments/nonce_reuse_differential.md`. Don't re-report "nonce reuse looks risky," that's now measured (F-ratios of ~6x-38x variance inflation at most walk positions). A working attack that turns the demonstrated distinguishing signal into actual plaintext recovery would be a genuinely useful report — that part is still open.
- Diffusion avalanche has a reproducible weak zone in roughly the last ⅛ of the walk (see `docs/construction.md` §6, `python3 -m honest.diffusion`). Fixed nonce per encryption means this isn't directly exploitable as shipped, but it's a real gap from the strict avalanche criterion (open problem 5).
- Malleable ciphertext with no MAC — this is IND-CCA1-broken by construction, independent of LGIP hardness.
- LGIP hardness is unproven; only pair-level KB is implemented, not the full word-level Rp/Rs system (open problem 4).
- No formal IND-CPA or IND-CCA2 proof, no quantum advantage analysis beyond "no known poly-time attack," no side-channel analysis (not constant-time).

## Scope

In scope: anything related to the mathematical construction, the implementation, or the security claims in README.md and docs/construction.md.

Out of scope: vulnerabilities in Python or the OS. There are no external dependencies.
