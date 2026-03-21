# Security policy

## This is a research prototype

H.O.N.E.S.T. has no formal security proof, documented known weaknesses, and must not be used to protect real data. This file exists to handle disclosure of findings — breaks, structural weaknesses, cryptanalytic results — about the construction.

## Reporting

Open a GitHub issue, label it `cryptanalysis`, and include what you found, what component is affected, and proof-of-concept code if you have it. No embargo period. Publish your result. This is research — fast disclosure helps.

You'll be credited in the README and in any future publication.

## Already known — no need to report

Weak avalanche effect (~1% diffusion on a 1-bit plaintext change), malleable ciphertext with no MAC, LGIP hardness unproven, block substitution standing in for the full Rp/Rs system, no formal IND-CPA or IND-CCA2 proof, no quantum advantage analysis, no side-channel analysis.

## Scope

In scope: anything related to the mathematical construction, the implementation, or the security claims in README.md and docs/construction.md.

Out of scope: vulnerabilities in Python or the OS. There are no external dependencies.
