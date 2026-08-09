# partial_rule_leakage_sim.py
#
# Surface-Feature Fingerprinting Simulation
# ==========================================
# Question: "Can ML fingerprint canonical equivalence classes from walk
#            surface features, given partial knowledge of private rules?"
#
# This is NOT a key-recovery attack and NOT a rule-inference attack in
# the LGIP sense.  The attacker observes σ-walks reduced with (public +
# leaked-private) rules, extracts shallow statistical features (token
# counts, bigram frequencies, term length), and trains a classifier to
# predict the true canonical class.  If accuracy stays near random
# guessing regardless of how many private rules leak, the rewriting
# system's equivalence-class structure is opaque to surface statistics.

import random
import hashlib
import numpy as np
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import balanced_accuracy_score
import pickle
import time
import json


# ---------------------------
# Helpers
# ---------------------------

SIGMA = ['σ1', 'σ2', 'σ3', 'σ4']


def tokenize_walk(w):
    """Tokenize a σ-encoded walk string into a list of tokens."""
    toks = []
    i = 0
    while i < len(w):
        if w[i] == 'σ':
            i += 1
            num = ''
            while i < len(w) and w[i].isdigit():
                num += w[i]
                i += 1
            toks.append('σ' + num)
        else:
            i += 1
    return toks


def improved_walk_generation(message, entropy, walk_len=24):
    """
    Generate a deterministic walk over generators σ1..σ4 from a message
    and entropy string.  Uses HMAC-style mixing so different messages
    produce distinct, reproducible walks.
    """
    seed_bytes = hashlib.sha256((message + '|' + entropy).encode()).digest()
    rng = random.Random(int.from_bytes(seed_bytes[:8], 'big'))
    walk = []
    for _ in range(walk_len):
        walk.append(rng.choice(SIGMA))
    return ''.join(walk)


def feature_vector(term, noise_std=0.3):
    """Surface features an attacker can compute from a (partially-reduced) term.

    These are *shallow statistical* features only — token unigram counts,
    bigram counts, and term length.  No structural or algebraic features
    are used, because an attacker without full rule knowledge cannot
    reliably compute those.

    Gaussian noise simulates observation imprecision.
    """
    toks = tokenize_walk(term)
    tok_counts = Counter(toks)
    bigrams = [term.count(a + b) for a in SIGMA for b in SIGMA]  # 16 bigram counts
    fv = np.array([
        tok_counts.get('σ1', 0),
        tok_counts.get('σ2', 0),
        tok_counts.get('σ3', 0),
        tok_counts.get('σ4', 0),
        len(toks),
        *bigrams,
    ], dtype=float)
    fv += np.random.normal(0, noise_std, size=fv.shape)
    return fv


def apply_rules_once(term, rules):
    """Leftmost-first single rule application on a σ-string."""
    for left, right in rules:
        pos = term.find(left)
        if pos != -1:
            return term[:pos] + right + term[pos + len(left):]
    return term


def closure_rewrite(term, rules, max_steps=50):
    """Reduce term to normal form (up to max_steps) using rule list."""
    t = term
    for _ in range(max_steps):
        new_t = apply_rules_once(t, rules)
        if new_t == t:
            break
        t = new_t
    return t


def private_canonicalizer(term, all_rules):
    """
    Canonicalize by reducing with ALL rules (public + private).
    A bounded max_steps prevents collapsing every walk to a single
    fixed point while still creating meaningful equivalence classes.
    """
    return closure_rewrite(term, all_rules, max_steps=28)


# ---------------------------
# Experiment runner
# ---------------------------

def fingerprinting_experiment(public_rules, private_rules,
                              trials=50, reveal_fracs=None, n_messages=128):
    """
    Surface-feature fingerprinting simulation.

    For each leakage fraction, the attacker:
      1. Reduces walks using public + leaked private rules.
      2. Extracts shallow surface features (token counts, bigrams, length).
      3. Trains a Random Forest to predict the true canonical class.

    If accuracy remains flat and near the random baseline across all
    leakage fractions, surface features carry no usable signal about
    canonical class identity — even when the attacker knows many rules.
    """
    if reveal_fracs is None:
        reveal_fracs = [0.0, 0.01, 0.05, 0.10, 0.25, 0.50]

    random.seed(42)
    np.random.seed(42)
    all_rules = public_rules + private_rules
    results = {}

    # Generate dataset: message -> walk -> canonical label
    messages = [format(i, '08b') for i in range(n_messages)]
    encoded_walks = []
    labels = []
    for m in messages:
        entropy = hashlib.sha256(m.encode()).hexdigest()
        walk = improved_walk_generation(m, entropy)
        encoded_walks.append(walk)
        labels.append(private_canonicalizer(walk, all_rules))

    n_unique_labels = len(set(labels))
    baseline_acc = 1.0 / max(n_unique_labels, 1)
    print(f"Dataset: {len(messages)} messages, {n_unique_labels} unique canonical classes")
    print(f"Random-guess baseline: {baseline_acc:.4f}\n")

    for frac in reveal_fracs:
        p_success = []
        start = time.time()
        k = int(len(private_rules) * frac)
        print(f"[leak {frac*100:.1f}%] revealing {k}/{len(private_rules)} "
              f"private rules, {trials} trials ...")

        for trial in range(trials):
            # Attacker's rule set: public + random subset of private
            revealed = random.sample(private_rules, k) if k > 0 else []
            attacker_rules = public_rules + revealed

            # Reduce each walk with attacker's rules, extract surface features
            X, Y = [], []
            for w, label in zip(encoded_walks, labels):
                t_reduced = closure_rewrite(w, attacker_rules, max_steps=28)
                X.append(feature_vector(t_reduced))
                Y.append(label)

            X = np.array(X)
            Y = np.array(Y)

            # Need at least 2 classes to train a classifier
            if len(set(Y)) < 2:
                p_success.append(1.0)
                continue

            X_tr, X_te, y_tr, y_te = train_test_split(
                X, Y, test_size=0.3, random_state=trial % 123
            )

            # Need at least 2 classes in training set
            if len(set(y_tr)) < 2:
                p_success.append(baseline_acc)
                continue

            clf = RandomForestClassifier(
                n_estimators=50, max_depth=8, random_state=trial % 123
            )
            clf.fit(X_tr, y_tr)
            y_pred = clf.predict(X_te)
            acc = balanced_accuracy_score(y_te, y_pred)
            p_success.append(acc)

        elapsed = time.time() - start
        results[frac] = {
            'mean_success': float(np.mean(p_success)),
            'std_success': float(np.std(p_success)),
            'trials': trials,
            'k_revealed': k,
            'time_s': round(elapsed, 2),
        }
        print(f"  -> mean fingerprinting accuracy: {results[frac]['mean_success']:.3f} "
              f"± {results[frac]['std_success']:.3f}  "
              f"({elapsed:.1f}s)\n")

    return results


# ---------------------------
# Withstand capacity metrics
# ---------------------------

def compute_withstand_capacity(results, baseline_acc, threshold_factor=5.0):
    """
    Absolute withstand capacity: leakage fraction at which attacker
    accuracy first exceeds `threshold_factor` × random-guess baseline.

    Returns interpolated fraction, or 1.0 if threshold is never crossed.
    """
    threshold = min(baseline_acc * threshold_factor, 1.0)
    fracs_sorted = sorted(results.keys())
    accs = [results[f]['mean_success'] for f in fracs_sorted]

    if accs[0] >= threshold:
        return 0.0

    for i in range(1, len(fracs_sorted)):
        if accs[i] >= threshold:
            f0, f1 = fracs_sorted[i - 1], fracs_sorted[i]
            a0, a1 = accs[i - 1], accs[i]
            frac = f0 + (threshold - a0) * (f1 - f0) / (a1 - a0)
            return frac

    return 1.0


def compute_delta_withstand_capacity(results, delta_threshold=0.02):
    """
    Delta-based withstand capacity: leakage fraction at which attacker
    accuracy first exceeds 0%-leakage accuracy by `delta_threshold`.

    Directly answers "does leaking rules help the attacker?"
    Returns interpolated fraction, or 1.0 if threshold is never crossed.
    """
    fracs_sorted = sorted(results.keys())
    accs = [results[f]['mean_success'] for f in fracs_sorted]
    baseline_at_zero = accs[0]
    threshold = baseline_at_zero + delta_threshold

    for i in range(1, len(fracs_sorted)):
        if accs[i] >= threshold:
            f0, f1 = fracs_sorted[i - 1], fracs_sorted[i]
            a0, a1 = accs[i - 1], accs[i]
            frac = f0 + (threshold - a0) * (f1 - f0) / (a1 - a0)
            return frac

    return 1.0


# ---------------------------
# Utilities
# ---------------------------

def dedup_rules(rules):
    """Remove duplicate LHS entries, keeping the first occurrence."""
    seen = set()
    unique = []
    for lhs, rhs in rules:
        if lhs not in seen:
            seen.add(lhs)
            unique.append([lhs, rhs])
    return unique


# ---------------------------
# Main
# ---------------------------

if __name__ == "__main__":
    with open('public_rules.json', 'r') as f:
        public_rules = dedup_rules(json.load(f))
    with open('private_rules.json', 'r') as f:
        private_rules = dedup_rules(json.load(f))

    print(f"Loaded {len(public_rules)} public rules, "
          f"{len(private_rules)} private rules\n")

    reveal_fracs = [0.0, 0.01, 0.05, 0.10, 0.25, 0.50]
    res = fingerprinting_experiment(
        public_rules, private_rules,
        trials=50,
        reveal_fracs=reveal_fracs,
        n_messages=512,
    )

    with open('leakage_results.pkl', 'wb') as out:
        pickle.dump(res, out)

    # --- Summary ---
    all_rules_tmp = public_rules + private_rules
    sample_walks = []
    for i in range(512):
        m = format(i, '08b')
        e = hashlib.sha256(m.encode()).hexdigest()
        w = improved_walk_generation(m, e)
        sample_walks.append(private_canonicalizer(w, all_rules_tmp))
    n_classes = len(set(sample_walks))
    baseline_acc = 1.0 / max(n_classes, 1)

    print("\n=== Summary ===")
    print(f"Question: Can ML fingerprint canonical classes from surface features?")
    for frac, r in sorted(res.items()):
        print(f"  {frac*100:5.1f}% leaked ({r['k_revealed']} rules): "
              f"accuracy = {r['mean_success']:.3f} ± {r['std_success']:.3f}")

    # --- Withstand Capacity (absolute, 5× baseline) ---
    tf = 5.0
    wc = compute_withstand_capacity(res, baseline_acc, threshold_factor=tf)
    print(f"\n=== Withstand Capacity (absolute, {tf}× baseline) ===")
    print(f"  Random-guess baseline:      {baseline_acc:.4f}")
    print(f"  Threshold ({tf}× baseline):   {min(baseline_acc * tf, 1.0):.4f}")
    print(f"  Withstand capacity:          {wc*100:.1f}% rule leakage")
    if wc >= 1.0:
        print("  → Surface features carry no usable signal about canonical "
              "classes, even at 50% rule leakage.")
    elif wc <= 0.0:
        print("  → Surface features already leak class identity at 0% "
              "rule leakage.")
    else:
        print(f"  → Surface features become informative once ~{wc*100:.1f}% "
              f"of private rules are leaked.")

    # --- Withstand Capacity (delta-based) ---
    delta = 0.02
    zero_leak_acc = res[0.0]['mean_success']
    dwc = compute_delta_withstand_capacity(res, delta_threshold=delta)
    print(f"\n=== Withstand Capacity (delta-based, Δ={delta}) ===")
    print(f"  Accuracy at 0% leakage:     {zero_leak_acc:.4f}")
    print(f"  Threshold (0%-leak + {delta}):{zero_leak_acc + delta:.4f}")
    print(f"  Delta withstand capacity:    {dwc*100:.1f}% rule leakage")
    if dwc >= 1.0:
        print(f"  → Leaking rules does NOT improve fingerprinting (< +{delta*100:.0f}pp).")
    else:
        print(f"  → Fingerprinting improves by +{delta*100:.0f}pp once "
              f"~{dwc*100:.1f}% of rules are leaked.")

    # --- Conclusion ---
    flat = all(
        abs(res[f]['mean_success'] - zero_leak_acc) < delta
        for f in reveal_fracs
    )
    print("\n=== Conclusion ===")
    if flat:
        print("  Answer: NO — ML cannot fingerprint canonical classes from")
        print("  walk surface features under this model, regardless of")
        print("  partial rule knowledge (tested up to 50% leakage).")
    else:
        print("  Answer: YES — surface features become informative as")
        print("  more private rules are revealed.")

    print("\nResults saved to leakage_results.pkl")
