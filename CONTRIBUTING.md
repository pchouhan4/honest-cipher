# Contributing

## What actually helps

Try to break it. Specifically: given multiple (plaintext, ciphertext) pairs under the same key, can you recover the permutation table? That's open problem 2 and it's the most urgent thing to know. Write the attack, run it, open an issue with what you find.

Other useful contributions: a formal hardness reduction or attack on LGIP, an implementation of the full Rp/Rs Knuth-Bendix trapdoor (open problem 4), a diffusion layer that achieves the strict avalanche criterion (open problem 5), statistical tests against the ciphertext I haven't tried.

## What doesn't help

Pull requests that make the limitations section softer or the security claims stronger. The documentation being honest matters more than the repo looking polished.

## Code

Python 3.10+, stdlib only. Docstrings on everything. Tests go in `tests/test_honest.py`. Known limitations get their own test class — add a comment explaining what fails and why.

## Before a PR

Open an issue first for anything non-trivial. For cryptanalytic results an issue alone is fine, no PR needed.
