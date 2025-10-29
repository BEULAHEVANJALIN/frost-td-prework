# Distributed Key Generation (DKG)
#
# Responsibilities
#   1) Each dealer i samples a degree-(t-1) polynomial f_i(x) over Z_q.
#   2) Each dealer computes Feldman commitments φ_{i,k} = a_{i,k} * G.
#   3) Dealer i privately “sends” s_{i→j} = f_i(j) to each participant j.
#   4) Each receiver j verifies each dealer’s share via:
#        g^{s_{i→j}}  ?=  Σ_{k=0}^{t-1} j^k * φ_{i,k}
#   5) Aggregate shares: s_j = Σ_i f_i(j). Aggregate commitments per k:
#        Φ_k = Σ_i φ_{i,k};  Group public key Y = Φ_0
#   6) Public check per j:
#        s_j * G  ?=  Σ j^k * Φ_k
#   7) (Optional) Reconstruct Y from any t public Y_j using Lagrange weights.
#   8) Return state including preloaded Participant objects ready for signing.
#
# Notes
#   - Uses vendored frost primitives (Point, G, Participant) and utils.
#   - Deterministic mode (`--seed`) gives reproducible coefficients.
#   - Input validation and explicit prints for clarity.

from __future__ import annotations

import argparse
import random
from itertools import combinations
from typing import Dict, List, Sequence, Tuple

from frost.point import Point, G
from frost.participant import Participant
from frost.constants import Q

from workshop.utils import (
    banner,
    kv,
    mod_q,
    coefficient_commitments,
    eval_poly,
    expected_public_share_from_commitments,
    print_feldman_share_check,
    sum_commitment_tuples,
    public_shares_from_commitments,
    lagrange_basis_at_zero,
    point_str,
)

# ---- Deterministic coefficient sampler (per-dealer) -------------------------

def _sample_coefficients_per_dealer(t: int, *, base_seed: int | None, dealer_index: int) -> Tuple[int, ...]:
    """
    Sample (a_{i,0},...,a_{i,t-1}) ∈ Z_q for dealer i.
    If base_seed is provided, derive a per-dealer PRNG stream deterministically.

    We do NOT re-implement frost internals here; this is only demo orchestration.

    Args:
        t: threshold
        base_seed: optional global seed
        dealer_index: 1..n

    Returns:
        tuple of t scalars mod q
    """
    if t <= 0:
        raise ValueError("threshold t must be >= 1")

    if base_seed is None:
        sysrand = random.SystemRandom()
        return tuple(mod_q(sysrand.getrandbits(256)) for _ in range(t))

    # Deterministic stream per dealer:
    rnd = random.Random((base_seed << 8) ^ dealer_index)
    return tuple(mod_q(rnd.getrandbits(256)) for _ in range(t))


# ---- Orchestration ----------------------------------------------------------

def keygen_dkg(t: int = 2, n: int = 3, *, seed: int | None = None, quiet: bool = False):
    """
    Execute a simple DKG flow (Feldman-style commitments, no complaints/accusations path):

      - Every participant acts as a “dealer” once.
      - All shares verify against the publishing dealer’s commitments.
      - Aggregate per-index shares and per-degree commitments to obtain group key.

    Returns:
        {
          "t": t, "n": n,
          "commitments": (Φ_0,...,Φ_{t-1}),
          "Y": Y,
          "shares": { j: s_j },
          "parties": [Participant(...), ...]
        }
    """
    if t < 1:
        raise ValueError("threshold t must be >= 1")
    if n < t:
        raise ValueError("participants n must be >= threshold t")

    if not quiet:
        banner("DKG key generation")
        kv("Threshold t", t)
        kv("Participants n", n)
        if seed is not None:
            kv("Deterministic base seed", seed)

    # 1) Each dealer samples polynomial and publishes coefficient commitments
    #    φ_{i,k} = a_{i,k} * G
    dealer_coeffs: Dict[int, Tuple[int, ...]] = {}
    dealer_comms: Dict[int, Tuple[Point, ...]] = {}

    for i in range(1, n + 1):
        coeffs_i = _sample_coefficients_per_dealer(t, base_seed=seed, dealer_index=i)
        dealer_coeffs[i] = coeffs_i
        comms_i = coefficient_commitments(coeffs_i)
        dealer_comms[i] = comms_i

        if not quiet:
            banner(f"Dealer {i}: coefficients and commitments")
            for k, ak in enumerate(coeffs_i):
                kv(f"a_{i},{k}", ak)
            for k, phi in enumerate(comms_i):
                kv(f"phi_{i},{k}", phi)

    # 2) Dealer i privately “sends” s_{i→j} = f_i(j) to each j
    #    (Here we compute locally for demonstration)
    shares_ij: Dict[Tuple[int, int], int] = {}
    for i in range(1, n + 1):
        for j in range(1, n + 1):
            shares_ij[(i, j)] = eval_poly(dealer_coeffs[i], j)

    # 3) Receivers verify each s_{i→j} using Feldman:
    #      g^{s_{i→j}} ?= Σ j^k * φ_{i,k}
    if not quiet:
        banner("Per-dealer Feldman VSS checks at receivers")
    all_ok = True
    for j in range(1, n + 1):
        if not quiet:
            print(f"[Receiver j={j}] verifying dealers’ shares...")
        for i in range(1, n + 1):
            s_ij = shares_ij[(i, j)]
            ok = print_feldman_share_check(s_ij, dealer_comms[i], j)
            all_ok &= ok
    if not quiet:
        print(f"All per-dealer Feldman checks passed? {all_ok}")

    # 4) Aggregate shares per participant j and aggregate commitments per degree k
    #    s_j = Σ_i f_i(j)       and       Φ_k = Σ_i φ_{i,k}
    agg_shares: Dict[int, int] = {
        j: sum(shares_ij[(i, j)] for i in range(1, n + 1)) % Q
        for j in range(1, n + 1)
    }
    group_commitments: Tuple[Point, ...] = sum_commitment_tuples(tuple(dealer_comms[i] for i in range(1, n + 1)))
    Y: Point = group_commitments[0]

    if not quiet:
        banner("Aggregate (public) coefficient commitments Φ_k and group key")
        for k, Phi_k in enumerate(group_commitments):
            kv(f"Φ_{k}", Phi_k)
        kv("Group public key Y = Φ_0", Y)

        banner("Aggregate per-index shares s_j = Σ_i f_i(j)")
        for j in range(1, n + 1):
            kv(f"s_{j}", agg_shares[j])

    # 5) Public check per j:
    #      s_j * G  ?=  Σ j^k * Φ_k
    if not quiet:
        banner("Public per-index checks: s_j*G vs Σ j^k * Φ_k")
    all_ok2 = True
    for j in range(1, n + 1):
        lhs = agg_shares[j] * G
        rhs = expected_public_share_from_commitments(group_commitments, j)
        ok = (lhs.x == rhs.x) and (lhs.y == rhs.y)
        kv(f"j={j}  LHS s_j*G", lhs)
        kv(f"j={j}  RHS Σ j^k * Φ_k", rhs)
        print(f"  result: {ok}")
        all_ok2 &= ok
    if not quiet:
        print(f"All public per-index checks passed? {all_ok2}")

    # 6) (Optional) Reconstruct Y from any t public Y_j = s_j * G with Lagrange λ_i(0)
    if not quiet:
        banner(f"Reconstruct Y from any {t} public Y_j via Lagrange at x=0")
    Yj_points: Dict[int, Point] = {j: agg_shares[j] * G for j in range(1, n + 1)}
    for subset in combinations(range(1, n + 1), t):
        indexes = list(subset)
        # Y' = Σ λ_i(0) * Y_i
        Y_rec = Point()
        lambdas: Dict[int, int] = {}
        for i in indexes:
            lam = lagrange_basis_at_zero(indexes, i)
            lambdas[i] = lam
            Y_rec = Y_rec + (lam * Yj_points[i])
        ok = (Y_rec.x == Y.x) and (Y_rec.y == Y.y)
        print(f"Subset {subset} → λ = {lambdas} → matches Y? {ok}")

    # 7) Prepare Participant objects ready for signing
    parties: List[Participant] = [Participant(i, t, n) for i in range(1, n + 1)]
    for P in parties:
        P.aggregate_share = agg_shares[P.index]
        P.group_commitments = group_commitments
        P.public_key = Y

    if not quiet:
        banner("State summary")
        kv("Y", Y)
        print("Participants (index → public verification share Y_i = s_i*G):")
        for P in parties:
            Yi = P.public_verification_share()
            print(f"  i={P.index}: {point_str(Yi)}")

    return {
        "t": t,
        "n": n,
        "commitments": group_commitments,
        "Y": Y,
        "shares": agg_shares,
        "parties": parties,
    }


# ---- CLI --------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="DKG key generation for FROST (BIP340-compatible)."
    )
    p.add_argument("--t", type=int, default=2, help="threshold (degree = t-1)")
    p.add_argument("--n", type=int, default=3, help="number of participants")
    p.add_argument(
        "--seed",
        type=int,
        default=None,
        help="deterministic base seed (per-dealer seeds derived from this)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress prints (useful when driving from other modules)",
    )
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    keygen_dkg(t=args.t, n=args.n, seed=args.seed, quiet=args.quiet)


if __name__ == "__main__":
    main()