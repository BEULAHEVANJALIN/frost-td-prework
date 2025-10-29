from __future__ import annotations
import argparse
from typing import Dict, List, Tuple

from frost.constants import Q
from frost.point import Point
from frost.participant import Participant
from frost.aggregator import Aggregator

from workshop.utils import (
    banner, kv, schnorr_verify_explicit, lagrange_basis_at_zero,
)
from workshop.keygen_trusted_dealer import keygen_trusted_dealer
from workshop.keygen_dkg import keygen_dkg


# ------------------------- helpers & small utilities -------------------------

def _parse_signers(s: str | None, t: int, n: int) -> Tuple[int, ...]:
    """
    Parse comma-separated originals (e.g., "2,3"). No remap; we use true ids.
    """
    if s is None:
        # default: first t originals
        return tuple(range(1, t + 1))
    try:
        idxs = sorted({int(x.strip()) for x in s.split(",") if x.strip()})
    except Exception:
        raise ValueError("--signers must be a comma-separated list of integers, e.g., 1,3")
    if len(idxs) < t:
        raise ValueError(f"need at least t={t} signers, got {len(idxs)}")
    if any(i < 1 or i > n for i in idxs):
        raise ValueError(f"signer ids must be in [1..{n}]")
    return tuple(idxs)


def _message_from_args(args: argparse.Namespace) -> bytes:
    if args.msg_utf8 and args.msg_hex:
        raise ValueError("Provide only one of --msg-utf8 or --msg-hex")
    if args.msg_utf8:
        return args.msg_utf8.encode("utf-8")
    if args.msg_hex:
        s = args.msg_hex.strip().lower()
        if s.startswith("0x"):
            s = s[2:]
        if len(s) % 2:
            s = "0" + s
        return bytes.fromhex(s)
    return b"FROST-BIP340 demo"


def _pad_nonce_pairs(n: int, chosen: Tuple[int, ...], parties: List[Participant]) -> Tuple[Tuple(Point, Point), ...]:
    """
    Build a tuple of nonce-commitment pairs where index (i-1) holds pair for signer i.
    Gaps (non-participants < max(chosen)) are filled with (∞,∞) so the list is indexable.
    Aggregator.* methods will only iterate over 'participant_indexes', so gaps are ignored.
    """
    k = max(chosen)
    pairs: List[Tuple[Point, Point]] = [(Point(), Point())] * k  # points-at-infinity by default
    for i in chosen:
        P = parties[i - 1]
        P.generate_nonce_pair()
        pairs[i - 1] = P.nonce_commitment_pair
    return tuple(pairs)


def _sign_share_with_fixed_transcript(
    *,
    participant: Participant,
    signer_index: int,                      # original id i
    message: bytes,
    nonce_commitment_pairs: Tuple[Tuple[Point, Point], ...],
    participant_indexes: Tuple[int, ...],  # the true original ids set S (e.g., (2,3))
    R_even: Point,                          # normalized R (even-y) – for clarity/logs
    Y_even: Point,                          # normalized Y (even-y)
    c: int,                                 # challenge over (R_even, Y_even, m)
    r_odd: bool,                            # whether R_raw had odd y
    y_odd: bool,                            # whether Y_eff had odd y
) -> int:
    """
    Deterministic per-signer share using the *same* transcript (R_even, Y_even, c).
    Mirrors Participant.sign math with explicit parity & λ handling:
        z_i = d_i' + e_i' * p_i + λ_i(0) * s_i' * c   (mod q)
    where ' indicates parity-adjusted values.
    """
    if participant.nonce_pair is None:
        raise ValueError("nonce_pair missing; call generate_nonce_pair() first")
    if participant.aggregate_share is None:
        raise ValueError("aggregate_share missing")

    d_i, e_i = participant.nonce_pair
    s_i = participant.aggregate_share

    # Parity fixes derived from raw parity flags:
    # - If R_raw was odd: negate both nonces.
    # - If (tweaked) Y_eff was odd: negate the share.
    if r_odd:
        d_i = (Q - d_i) % Q
        e_i = (Q - e_i) % Q
    if y_odd:
        s_i = (Q - s_i) % Q

    # Binding value p_i and Lagrange λ_i(0) at the *true* index set S
    p_i = Aggregator.binding_value(signer_index, message, nonce_commitment_pairs, participant_indexes)

    # λ_i(0) = ∏_{j∈S, j≠i} (0 - j)/(i - j) mod q
    num, den = 1, 1
    for j in participant_indexes:
        if j == signer_index:
            continue
        num = (num * (Q - j)) % Q            # (0 - j)
        den = (den * ((signer_index - j) % Q)) % Q
    lam_i = (num * pow(den, Q - 2, Q)) % Q   # den^{-1} via Fermat since Q is prime

    # Final partial
    z_i = (d_i + (e_i * p_i) % Q + ((lam_i * s_i) % Q) * c) % Q
    return z_i


# ------------------------------ main orchestrator ----------------------------

def run_signing_demo(
    mode: str = "trusted",
    t: int = 2,
    n: int = 3,
    seed: int | None = None,
    signer_indexes: Tuple[int, ...] | None = None,
    message: bytes = b"FROST-BIP340 demo",
    bip32_tweak: int | None = None,
    taproot_tweak: int | None = None,
) -> Dict[str, object]:
    """
    Execute a complete threshold signing round with explicit, parity-safe transcript.

    Steps:
      1) Build key material (trusted-dealer or DKG).
      2) Pick an arbitrary signer subset S (size ≥ t), using true original ids.
      3) Each signer generates nonces → we assemble index-addressable pairs (with gaps).
      4) Compute raw group commitment R_raw, then normalize to R_even (even-y).
      5) Build effective pubkey Y_eff (optionally tweaked), then normalize to Y_even.
      6) Challenge c = H_2(R_even, Y_even, m).
      7) Each signer computes z_i with parity-corrected (d,e) and s, and λ_i(0).
      8) Aggregate z = Σ z_i (mod q) and verify: z·G == R_even + c·Y_even.
    """
    if t < 1:
        raise ValueError("threshold t must be >= 1")
    if n < t:
        raise ValueError("n must be >= t")
    if mode not in ("trusted", "dkg"):
        raise ValueError("--mode must be 'trusted' or 'dkg'")

    # 1) Key material
    state = (
        keygen_trusted_dealer(t=t, n=n, seed=seed, quiet=True)
        if mode == "trusted"
        else keygen_dkg(t=t, n=n, seed=seed, quiet=True)
    )
    parties: List[Participant] = state["parties"]
    Y: Point = state["Y"]

    # 2) Choose signers (true ids, no remap)
    S = signer_indexes or tuple(range(1, t + 1))
    if len(S) < t:
        raise ValueError("pick at least t signers")

    banner("Signing")
    kv("Mode", mode)
    kv("t", t)
    kv("n", n)
    if seed is not None:
        kv("Seed", seed)
    kv("Signers (original ids)", S)
    kv("Message len", len(message))

    # 3) Nonces & padded commitment pairs (indexable up to max(S))
    padded_pairs = _pad_nonce_pairs(n, S, parties)

    # 4) Group commitment (raw), then normalize to even-y (BIP340)
    banner("Commitment & challenge")
    R_raw: Point = Aggregator.group_commitment(message, padded_pairs, S)
    r_odd = (R_raw.y % 2) != 0
    R_even: Point = -R_raw if r_odd else R_raw
    kv("R (even-y)", R_even)

    # 5) Effective pubkey: tweak (optional), then normalize to even-y
    if bip32_tweak is not None and taproot_tweak is not None:
        Y_eff, parity = Aggregator.tweak_key(bip32_tweak, taproot_tweak, Y)
        kv("Y' (pre-norm)", Y_eff)
    else:
        Y_eff, parity = Y, 0
    y_odd = (Y_eff.y % 2) != 0
    Y_even: Point = -Y_eff if y_odd else Y_eff
    kv("Y (even-y)", Y_even)

    # 6) Challenge over normalized points
    c = Aggregator.challenge_hash(R_even, Y_even, message)
    kv("c", c)

    # 7) Partials, showing λ_i(0) explicitly, fixed transcript for everyone
    banner("Partials")
    partials: Dict[int, int] = {}
    for i in S:
        kv(f"λ_{i}(0)", lagrange_basis_at_zero(S, i))
        z_i = _sign_share_with_fixed_transcript(
            participant=parties[i - 1],
            signer_index=i,
            message=message,
            nonce_commitment_pairs=padded_pairs,
            participant_indexes=S,
            R_even=R_even,
            Y_even=Y_even,
            c=c,
            r_odd=r_odd,
            y_odd=y_odd,
        )
        kv(f"z_{i}", z_i)
        partials[i] = z_i

    # 8) Aggregate & verify against the same normalized transcript
    banner("Aggregate signature")
    z = sum(partials.values()) % Q
    kv("z = Σ z_i (mod q)", z)

    ok = schnorr_verify_explicit(R_even, z, Y_even, message, verbose=True)

    return {
        "mode": mode,
        "t": t,
        "n": n,
        "signers": S,
        "message": message,
        "Y": Y,
        "R": R_even,
        "c": c,
        "partials": partials,
        "z": z,
        "ok": ok,
    }


# ------------------------------------ CLI ------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="FROST threshold signing demo (parity-safe, any signer subset)."
    )
    p.add_argument("--mode", choices=["trusted", "dkg"], default="trusted",
                   help="Key material source")
    p.add_argument("--t", type=int, default=2, help="threshold")
    p.add_argument("--n", type=int, default=3, help="number of participants")
    p.add_argument("--seed", type=int, default=None,
                   help="optional deterministic seed for demo reproducibility")
    p.add_argument("--signers", type=str, default=None,
                   help="comma-separated original ids, e.g. '2,3' (default first t)")
    msg = p.add_mutually_exclusive_group()
    msg.add_argument("--msg-utf8", type=str, default=None,
                     help="message as UTF-8 text")
    msg.add_argument("--msg-hex", type=str, default=None,
                     help="message as hex (with or without 0x)")
    p.add_argument("--bip32-tweak", type=int, default=None,
                   help="optional bip32 tweak (int)")
    p.add_argument("--taproot-tweak", type=int, default=None,
                   help="optional taproot tweak (int)")
    return p


def main() -> None:
    args = _build_parser().parse_args()
    S = _parse_signers(args.signers, args.t, args.n)
    m = _message_from_args(args)
    run_signing_demo(
        mode=args.mode,
        t=args.t,
        n=args.n,
        seed=args.seed,
        signer_indexes=S,
        message=m,
        bip32_tweak=args.bip32_tweak,
        taproot_tweak=args.taproot_tweak,
    )


if __name__ == "__main__":
    main()