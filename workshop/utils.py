# Utilities for FROST TD workshop that rely on the vendored `frost` package.
# Focus: high-signal printing, sanity checks, and small wrappers around common tasks.
#
# We intentionally DO NOT re-implement anything already in the frost subtree that
# performs cryptographic core logic. These helpers are glue around:
#   - modular-arithmetic conveniences
#   - polynomial evaluation over Z_q (for demos)
#   - Feldman VSS share verification (prints both sides)
#   - Lagrange interpolation at x=0 (for reconstruction / signing weights)
#   - commitments aggregation (DKG)
#   - Schnorr equation verification (explicit z*G == R + c*Y)
#   - pretty-printers for points and big integers

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple, Union, Optional

from frost.constants import Q
from frost.point import Point, G
from frost.aggregator import Aggregator


# ---------- Basic modular helpers ----------

def mod_q(x: int) -> int:
    """
    Reduce an integer modulo the secp256k1 group order Q.

    This is the scalar field for BIP340 Schnorr over secp256k1.

    Args:
        x: Any Python int (possibly negative or very large).

    Returns:
        x modulo Q as a non-negative representative in [0, Q-1].
    """
    if not isinstance(x, int):
        raise TypeError("mod_q expects an int")
    return x % Q


def inv_q(x: int) -> int:
    """
    Multiplicative inverse in Z_q using Fermat's little theorem.

    Computes x^{-1} mod Q as x^(Q-2) mod Q.

    Raises:
        ZeroDivisionError: if x == 0 (no inverse).
    """
    if not isinstance(x, int):
        raise TypeError("inv_q expects an int")
    if x % Q == 0:
        raise ZeroDivisionError("cannot invert 0 mod Q")
    return pow(x, Q - 2, Q)


# ---------- Pretty printing ----------

def int_hex(x: int, pad: int = 64) -> str:
    """
    Render a non-negative int as lowercase hex, zero-padded to `pad` nybbles.
    """
    if x < 0:
        raise ValueError("int_hex expects non-negative integer")
    s = hex(x)[2:]
    if len(s) < pad:
        s = "0" * (pad - len(s)) + s
    return s


def point_str(P: Point) -> str:
    """
    Render an EC Point as '(x=..., y=...)' in hex, or '∞' for infinity.
    """
    if P.x is None or P.y is None:
        return "∞"
    return f"(x=0x{int_hex(P.x)}, y=0x{int_hex(P.y)})"


def banner(title: str) -> None:
    """
    Print a strongly visible section banner.
    """
    line = "=" * max(8, len(title))
    print(f"\n{line}\n{title}\n{line}")


def kv(label: str, value: Union[int, str, Point, Tuple, List, Dict]) -> None:
    """
    Key-value printer with type-aware formatting.
    """
    if isinstance(value, Point):
        print(f"{label}: {point_str(value)}")
    elif isinstance(value, int):
        print(f"{label}: {value} (0x{int_hex(value)})")
    else:
        print(f"{label}: {value}")


# ---------- Polynomial utilities over Z_q (purely for demos/printing) ----------

def eval_poly(coeffs: Sequence[int], x: int) -> int:
    """
    Evaluate a polynomial f(X) = c_0 + c_1*X + ... + c_{t-1}*X^{t-1} over Z_q at integer x,
    using Horner's rule.

    Args:
        coeffs: coefficients (c_0,...,c_{t-1}) in Z_q.
        x: evaluation point (Python int).

    Returns:
        f(x) mod Q.
    """
    if len(coeffs) == 0:
        raise ValueError("eval_poly: empty coefficient sequence")
    if not all(isinstance(c, int) for c in coeffs):
        raise TypeError("eval_poly: coefficients must be ints")
    if not isinstance(x, int):
        raise TypeError("eval_poly: x must be int")

    y = 0
    for c in reversed(coeffs):
        y = (y * x + c) % Q
    return y


def coefficient_commitments(coeffs: Sequence[int]) -> Tuple[Point, ...]:
    """
    Feldman commitments to coefficients:
        phi_k = c_k * G  for k = 0..t-1.

    NOTE: This is a small wrapper that uses the vendored Point/G. It does not
    replace any frost logic; it's just a convenience for your demos.

    Args:
        coeffs: scalar coefficients in Z_q.

    Returns:
        Tuple of EC points (phi_0, ..., phi_{t-1}).
    """
    if len(coeffs) == 0:
        raise ValueError("coefficient_commitments: empty coefficient sequence")
    if not all(isinstance(c, int) for c in coeffs):
        raise TypeError("coefficient_commitments: coefficients must be ints")
    return tuple((c % Q) * G for c in coeffs)


def expected_public_share_from_commitments(commitments: Sequence[Point], index: int) -> Point:
    """
    Compute the committed public share Y_index from Feldman coefficient commitments:
        Y_index = sum_{k=0}^{t-1} (index^k mod q) * phi_k.

    Args:
        commitments: (phi_0,...,phi_{t-1})
        index: participant index (positive int)

    Returns:
        EC Point representing g^{f(index)} if commitments are correct.
    """
    if len(commitments) == 0:
        raise ValueError("expected_public_share_from_commitments: empty commitments")
    if not isinstance(index, int) or index <= 0:
        raise ValueError("index must be a positive integer")

    acc = Point()  # infinity
    for k, phi_k in enumerate(commitments):
        if not isinstance(phi_k, Point):
            raise TypeError("commitments must be Points")
        acc += (pow(index, k, Q)) * phi_k
    return acc


def print_feldman_share_check(
    share_scalar: int,
    commitments: Sequence[Point],
    index: int,
    *,
    label_prefix: str = ""
) -> bool:
    """
    Perform and PRINT a Feldman VSS share check:
        LHS = g^{s_index}
        RHS = Σ index^k * phi_k

    Returns:
        bool indicating equality.

    This is a pure *verification and explanation* helper; it doesn't mutate any state.
    """
    if not isinstance(share_scalar, int):
        raise TypeError("share_scalar must be int")

    if label_prefix:
        print(f"{label_prefix}Feldman VSS check for j={index}:")
    lhs = (share_scalar % Q) * G
    rhs = expected_public_share_from_commitments(commitments, index)
    kv("  LHS g^{s_j}", lhs)
    kv("  RHS Σ j^k * phi_k", rhs)
    ok = (lhs.x == rhs.x) and (lhs.y == rhs.y)
    print(f"  result: {ok}")
    return ok


# ---------- Lagrange interpolation at x=0 ----------

def lagrange_basis_at_zero(indexes: Sequence[int], i: int) -> int:
    """
    Lagrange basis λ_i(0) for the set of distinct indexes S = {i_1,...,i_t}:

        λ_i(0) = Π_{j ∈ S, j ≠ i} (0 - j) * (i - j)^{-1}   mod q

    This weight reconstructs f(0) from the values {f(i)} when deg(f) ≤ t-1.

    Args:
        indexes: distinct positive integers (participant indexes) used in interpolation
        i: the particular index whose basis we compute; must be in `indexes`

    Returns:
        λ_i(0) ∈ Z_q
    """
    if len(indexes) == 0:
        raise ValueError("lagrange_basis_at_zero: empty index set")
    if len(indexes) != len(set(indexes)):
        raise ValueError("lagrange_basis_at_zero: indexes must be distinct")
    if i not in indexes:
        raise ValueError("lagrange_basis_at_zero: i not in indexes")
    for idx in indexes:
        if not isinstance(idx, int) or idx <= 0:
            raise ValueError("lagrange_basis_at_zero: indexes must be positive ints")

    num = 1
    den = 1
    for j in indexes:
        if j == i:
            continue
        num = (num * (-j % Q)) % Q           # (0 - j) mod q
        den = (den * ((i - j) % Q)) % Q      # (i - j) mod q
    return (num * inv_q(den)) % Q


def reconstruct_constant_from_shares(shares: Dict[int, int]) -> int:
    """
    Reconstruct f(0) from t shares { (i, s_i) } with distinct i using Lagrange at 0.

        s = Σ λ_i(0) * s_i   (mod q)
        where λ_i(0) is computed over the set of all provided indexes.

    Args:
        shares: mapping index -> share scalar

    Returns:
        s in Z_q (the constant term f(0))
    """
    if len(shares) == 0:
        raise ValueError("reconstruct_constant_from_shares: empty shares")

    indexes = list(shares.keys())
    if len(indexes) != len(set(indexes)):
        raise ValueError("reconstruct_constant_from_shares: duplicate indexes")

    acc = 0
    for i in indexes:
        lam = lagrange_basis_at_zero(indexes, i)
        acc = (acc + lam * (shares[i] % Q)) % Q
    return acc


# ---------- DKG utilities ----------

def sum_commitment_tuples(commitment_tuples: Sequence[Sequence[Point]]) -> Tuple[Point, ...]:
    """
    Element-wise sum of per-dealer coefficient commitments:

        Given C^{(dealer)} = (phi_0^{(d)},...,phi_{t-1}^{(d)}),
        produce Φ_k = Σ_d phi_k^{(d)} for each k.

    Args:
        commitment_tuples: sequence of tuples, each of equal length t.

    Returns:
        Tuple (Φ_0,...,Φ_{t-1})
    """
    if len(commitment_tuples) == 0:
        raise ValueError("sum_commitment_tuples: empty input")
    t = len(commitment_tuples[0])
    if any(len(ct) != t for ct in commitment_tuples):
        raise ValueError("sum_commitment_tuples: all tuples must have equal length")
    for ct in commitment_tuples:
        for P in ct:
            if not isinstance(P, Point):
                raise TypeError("sum_commitment_tuples: commitments must be Points")

    # Initialize with infinity points
    sums: List[Point] = [Point() for _ in range(t)]
    for ct in commitment_tuples:
        for k in range(t):
            sums[k] = sums[k] + ct[k]
    return tuple(sums)


def print_commitment_tuple(label: str, ct: Sequence[Point]) -> None:
    """
    Pretty-print a coefficient commitment tuple (phi_0..phi_{t-1} or Φ_0..Φ_{t-1}).
    """
    print(label + ":")
    for k, Pk in enumerate(ct):
        print(f"  [{k}] {point_str(Pk)}")


# ---------- Schnorr verification (explicit) ----------

def schnorr_verify_explicit(R: Point, z: int, Y: Point, message: bytes, *, verbose: bool = True) -> bool:
    """
    Verify the BIP340-style Schnorr equation explicitly:

        z * G  ==  R  +  c * Y

    where c = H_2(R, Y, m) computed by the vendored Aggregator.challenge_hash.

    Args:
        R: group commitment point (R != infinity)
        z: aggregate signature scalar
        Y: public key point
        message: bytes of the message preimage
        verbose: if True, prints the equation sides and c

    Returns:
        bool
    """
    if not isinstance(z, int):
        raise TypeError("z must be int")
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes-like")
    if R.x is None or R.y is None:
        raise ValueError("R is infinity")
    if Y.x is None or Y.y is None:
        raise ValueError("Y is infinity")

    c = Aggregator.challenge_hash(R, Y, message)
    lhs = (z % Q) * G
    rhs = R + (c * Y)

    if verbose:
        banner("Schnorr verification")
        kv("Challenge c = H_2(R,Y,m)", c)
        kv("LHS  z*G", lhs)
        kv("RHS  R + c*Y", rhs)
        print("Result:", (lhs.x == rhs.x) and (lhs.y == rhs.y))

    return (lhs.x == rhs.x) and (lhs.y == rhs.y)


# ---------- Public share derivation & printing ----------

def public_shares_from_commitments(commitments: Sequence[Point], n: int) -> Dict[int, Point]:
    """
    Derive Y_j = Σ j^k * phi_k for j in {1..n}.

    Useful for displaying/validating that s_j*G equals this derived point.

    Args:
        commitments: (phi_0..phi_{t-1})
        n: number of participants

    Returns:
        dict j -> Point
    """
    if not isinstance(n, int) or n <= 0:
        raise ValueError("n must be positive int")
    ys: Dict[int, Point] = {}
    for j in range(1, n + 1):
        ys[j] = expected_public_share_from_commitments(commitments, j)
    return ys


def print_share_vs_commitment(share_scalar: int, commitments: Sequence[Point], j: int) -> None:
    """
    Explain the equality:
        s_j * G  ?=  Σ j^k * phi_k
    """
    banner(f"Share vs commitment (j={j})")
    _ = print_feldman_share_check(share_scalar, commitments, j, label_prefix="")