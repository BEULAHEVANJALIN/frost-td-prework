# Trusted-dealer key generation.
#
# Responsibilities:
#   1) Sample a degree-(t-1) polynomial f(x) over Z_q with secret s = f(0).
#   2) Compute Feldman coefficient commitments φ_k = a_k * G.
#   3) Distribute per-index shares s_j = f(j) to j=1..n.
#   4) Verify each share via Feldman:  g^{s_j} ?= Σ j^k * φ_k.
#   5) Show Lagrange-at-0 reconstruction s = Σ λ_i(0) s_i for any t shares.
#   6) Prepare `Participant` objects preloaded with aggregate shares, commitments, and Y,
#      so signing demos can use them directly.
#
# Notes:
#   - This module *uses* vendored frost primitives and only adds orchestration/printing.
#   - Deterministic mode: `--seed` yields reproducible coefficients and shares for demos.
#   - Safety: input validation, fail-fast error messages, and clear, typed structure.

from __future__ import annotations

import argparse
import os
import random
from itertools import combinations
from typing import Dict, List, Tuple

from frost.point import Point, G
from frost.participant import Participant

from workshop.utils import (
    banner,
    kv,
    mod_q,
    coefficient_commitments,
    eval_poly,
    expected_public_share_from_commitments,
    print_feldman_share_check,
    lagrange_basis_at_zero,
    reconstruct_constant_from_shares,
    public_shares_from_commitments,
    print_share_vs_commitment,
    point_str,
)

# ---------- Deterministic coefficient sampling (optional) ----------

def _sample_coefficients(t: int, *, seed: int | None = None) -> Tuple[int, ...]:
    """
    Sample coefficients (a0,...,a_{t-1}) in Z_q.

    If `seed` is provided, sampling is deterministic via Python's `random`.
    Otherwise, defer to `secrets` path by calling back into utils via a small local sampler.
    (We avoid re-implementing any frost internals; this is demo orchestration.)
    """
    if t <= 0:
        raise ValueError("threshold t must be >= 1")

    if seed is None:
        # Use Python's secrets via random.SystemRandom for strong randomness
        sysrand = random.SystemRandom()
        return tuple(mod_q(sysrand.getrandbits(256)) for _ in range(t))
    else:
        rnd = random.Random(seed)
        return tuple(mod_q(rnd.getrandbits(256)) for _ in range(t))


# ---------- Orchestration ----------

def keygen_trusted_dealer(t: int = 2, n: int = 3, *, seed: int | None = None, quiet: bool = False):
    """
    Perform trusted-dealer key generation for FROST, returning a state bundle:
        {
          "t": threshold,
          "n": participants,
          "coeffs": (a0,...,a_{t-1}),
          "commitments": (phi_0,...,phi_{t-1}),
          "Y": group public key (phi_0),
          "shares": { j: s_j },
          "parties": [Participant(...), ...]  # preloaded for signing
        }

    Args:
        t: threshold (degree = t-1)
        n: total participants
        seed: optional deterministic seed for demo reproducibility
        quiet: suppress prints if True (useful when called from other modules)
    """
    if t < 1:
        raise ValueError("threshold t must be >= 1")
    if n < t:
        raise ValueError("participants n must be >= threshold t")

    if not quiet:
        banner("Trusted-dealer key generation")
        kv("Threshold t", t)
        kv("Participants n", n)
        if seed is not None:
            kv("Deterministic seed", seed)

    # 1) Sample polynomial coefficients over Z_q; secret is a0
    coeffs = _sample_coefficients(t, seed=seed)
    a0 = coeffs[0]
    if not quiet:
        banner("Polynomial coefficients over Z_q")
        for k, ak in enumerate(coeffs):
            kv(f"a{k}", ak)
        kv("Group secret s = a0", a0)

    # 2) Feldman coefficient commitments φ_k = a_k * G
    commitments = coefficient_commitments(coeffs)
    Y = commitments[0]
    if not quiet:
        banner("Feldman coefficient commitments (φ_k = a_k * G)")
        for k, phi in enumerate(commitments):
            kv(f"phi_{k}", phi)
        kv("Group public key Y = phi_0", Y)

    # 3) Distribute per-index shares s_j = f(j), j=1..n
    shares: Dict[int, int] = {j: eval_poly(coeffs, j) for j in range(1, n + 1)}
    if not quiet:
        banner("Shares distribution (s_j = f(j))")
        for j in range(1, n + 1):
            kv(f"s_{j}", shares[j])

    # 4) Feldman VSS verification per share:  g^{s_j} ?= Σ j^k * φ_k
    if not quiet:
        banner("Feldman VSS share checks")
    all_ok = True
    for j in range(1, n + 1):
        ok = print_feldman_share_check(shares[j], commitments, j, label_prefix="")
        all_ok &= ok
    if not quiet:
        print(f"All Feldman checks passed? {all_ok}")

    # Cross-check via pre-computed RHS public shares:
    if not quiet:
        banner("Public per-index Y_j from commitments vs s_j * G")
    Yj_from_commit = public_shares_from_commitments(commitments, n)
    for j in range(1, n + 1):
        print_share_vs_commitment(shares[j], commitments, j)

    # 5) Reconstruction sanity (any t shares reconstruct s = a0)
    if not quiet:
        banner(f"Lagrange-at-0 reconstruction tests (choose any {t} shares)")
    for subset in combinations(range(1, n + 1), t):
        sub_shares = {j: shares[j] for j in subset}
        s_rec = reconstruct_constant_from_shares(sub_shares)
        print(f"Subset {subset} → reconstructed s' = {s_rec}  == a0 ? {s_rec == a0}")

    # 6) Prepare Participant objects (preloaded with everything needed for signing)
    parties: List[Participant] = [Participant(i, t, n) for i in range(1, n + 1)]
    for P in parties:
        P.aggregate_share = shares[P.index]   # s_i
        P.group_commitments = commitments     # (φ_0,...,φ_{t-1})
        P.public_key = Y                      # Y = φ_0

    if not quiet:
        banner("State summary")
        kv("Y", Y)
        print("Participants (index → public verification share Y_i):")
        for P in parties:
            Yi = P.public_verification_share()
            print(f"  i={P.index}: {point_str(Yi)}")

    return {
        "t": t,
        "n": n,
        "coeffs": coeffs,
        "commitments": commitments,
        "Y": Y,
        "shares": shares,
        "parties": parties,
    }


# ---------- CLI ----------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Trusted-dealer key generation for FROST (BIP340-compatible)."
    )
    p.add_argument("--t", type=int, default=2, help="threshold (degree = t-1)")
    p.add_argument("--n", type=int, default=3, help="number of participants")
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="deterministic seed for reproducible coefficients/shares",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress prints (useful when driving from other modules)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    keygen_trusted_dealer(t=args.t, n=args.n, seed=args.seed, quiet=args.quiet)


if __name__ == "__main__":
    main()
