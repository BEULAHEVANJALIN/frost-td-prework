
# FROST Workshop

> **t-of-n Schnorr (BIP-340) with Trusted-Dealer & DKG flows**

This repo contains a minimal FROST implementation wired to a small set of workshop scripts:

* `workshop/keygen_trusted_dealer.py` - 1-round keygen with a trusted dealer
* `workshop/keygen_dkg.py` - interactive DKG with Feldman VSS checks
* `workshop/signing.py` - parity-safe FROST signing over BIP-340 (any signer subset)

A vendored library, `vendor/frost`, provides the reusable primitives (points, participants, aggregator, constants).

---

## 1) Quick start

### Python & environment

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -U pip
python -m pip install -e vendor/frost

# verify imports resolve to the vendored package
python -c "import frost, sys; print('py:', sys.version); print('frost at:', frost.__file__)"
```

### Smoke demo

Run any of these to see the end-to-end flows:

```bash
# Trusted-dealer keygen
python -m workshop.keygen_trusted_dealer --t 2 --n 3 --seed 7

# DKG keygen
python -m workshop.keygen_dkg --t 2 --n 3 --seed 7

# Signing with *trusted* keygen material
python -m workshop.signing --mode trusted --t 2 --n 3 --signers 1,2 --msg-utf8 "hello"

# Signing with *DKG* material and arbitrary subset (no remap)
python -m workshop.signing --mode dkg --t 2 --n 3 --seed 7 --signers 2,3 --msg-hex 74657374
```

**Notes**

* `--seed` makes demos deterministic (good for tests/docs).
* `--signers` accepts any subset of original IDs, size ≥ `t` (e.g., `2,3`).
* `--msg-utf8` and `--msg-hex` are mutually exclusive. Default message: `b"FROST-BIP340 demo"`.
* Optional tweaks:

  ```bash
  python -m workshop.signing --mode trusted --t 2 --n 3 --signers 1,2 \
    --bip32-tweak 1 --taproot-tweak 0
  ```

  If both tweaks are provided, the signer uses a tweaked effective key (see §4.4).

---

## 2) Project layout

```
.
├── docs
│   ├── NOTES_math.md         # (optional) deeper math notes - see §4 below
│   └── README_run.md         # (optional) quick-run crib sheet - see §3
├── frost-td-workshop.mediawiki
├── README.md                 # you are here
├── vendor
│   └── frost/                # vendored library used
└── workshop
    ├── keygen_trusted_dealer.py
    ├── keygen_dkg.py
    ├── signing.py
    └── utils.py
```

---

## 3) Run cookbook

### 3.1 Trusted-dealer keygen

```bash
python -m workshop.keygen_trusted_dealer --t 2 --n 3 --seed 7
```

**Outputs**

* Dealer polynomial coefficients `a_0, a_1, … a_{t-1}` (mod q)
* Feldman commitments `Φ_k = a_k·G`
* Per-party secret shares `s_i = f(i)`
* Group public key `Y = a_0·G`
* Witnessed checks: `s_i·G == Σ i^k · Φ_k`

### 3.2 DKG keygen (Feldman VSS)

```bash
python -m workshop.keygen_dkg --t 2 --n 3 --seed 7
```

Each dealer j picks a degree-(t-1) polynomial `f_j(x)`, hands out `s_{j→i} = f_j(i)` to every i, and publishes commitments `{Φ_{j,k}}`. Each receiver i checks:

```
(Σ_j s_{j→i})·G  ?=  Σ_j  Σ_k  i^k · Φ_{j,k}
```

After all checks pass, parties sum their received shares to obtain their **aggregate share** `s_i = Σ_j s_{j→i}` and the group commitment `Y = Σ_j Φ_{j,0}`.

### 3.3 Signing (any subset, size ≥ t)

Trusted-dealer:

```bash
python -m workshop.signing --mode trusted --t 2 --n 3 --signers 1,2 --msg-utf8 "hello"
```

DKG with arbitrary IDs `2,3`:

```bash
python -m workshop.signing --mode dkg --t 2 --n 3 --seed 7 --signers 2,3 --msg-hex 74657374
```

**What happens**

1. Selected signers generate nonce pairs `(d_i, e_i)` and publish commitments `(D_i, E_i)`.
2. Aggregator computes raw group commitment `R_raw` from `(D_i, E_i)` and message.
3. We **normalize to even-y**: `R_even = (y(R_raw) odd) ? -R_raw : R_raw`.
4. Effective key `Y_eff` (tweaked if requested) then **normalize** `Y_even` the same way.
5. Compute challenge `c = H_2(R_even, Y_even, m)` per BIP-340.
6. Each signer computes binding value `p_i` and Lagrange weight `λ_i(0)` at their **true index** i.
7. Apply parity corrections to `(d_i, e_i)` if `R_raw` was odd; to `s_i` if `Y_eff` was odd.
8. Signer returns partial

   `z_i = d_i' + e_i'·p_i + λ_i(0)·s_i'·c   (mod q)`
9. Aggregator returns `z = Σ z_i (mod q)` and verifies: `z·G == R_even + c·Y_even`.

---

## 4) Math primer (crash!)

### 4.1 Group & constants

* Curve: secp256k1 over prime field `F_p` with base point `G` of order `q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141`.
* Scalar arithmetic is mod `q`. Point arithmetic is on the elliptic curve group.

### 4.2 Shamir secret sharing & Feldman VSS

* Dealer picks a random polynomial `f(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1}` in `F_q`.
* Participant i receives `s_i = f(i)`.
* **Feldman commitments**: publish `Φ_k = a_k · G` so anyone can verify shares without learning `a_k`.
* Verify a share for participant i:

  `s_i · G  ?=  Σ_{k=0}^{t-1}  (i^k) · Φ_k`

### 4.3 Lagrange interpolation at 0

Given a subset `S ⊆ {1..n}`, `|S| = t`, the Lagrange coefficient at 0 for index i in S is

```
λ_i(0) = ∏_{j∈S, j≠i} (0 - j)/(i - j)  mod q
       = ∏_{j∈S, j≠i} (−j) · (i − j)^{-1} mod q
```

It reconstructs `a_0` (the secret) from any `t` shares: `a_0 = Σ_{i∈S} λ_i(0) · s_i`.

### 4.4 BIP-340 parity normalization (critical!)

BIP-340 defines Schnorr verification over **x-only** public keys but fixes a canonical representative point by requiring **even y** lifts. In threshold contexts this affects both the nonce aggregate `R` and the (possibly tweaked) key `Y_eff`.

* Normalize once:

  * `R_even = (y(R_raw) odd) ? -R_raw : R_raw`
  * `Y_even = (y(Y_eff) odd) ? -Y_eff : Y_eff`
* Challenge: `c = H_2(R_even, Y_even, m)`.
* To keep signing consistent with verification, apply matching flips to the **secret-side** values:

  * If `y(R_raw)` was odd → negate both nonces `(d_i, e_i)` **for every signer**.
  * If `y(Y_eff)` was odd → negate each share `s_i`.

This guarantees `z·G == R_even + c·Y_even`.

### 4.5 Nonce binding & adaptor to FROST

FROST prevents cross-round nonce reuse and rogue-key style malleability by including a **binding value** `p_i` that depends on all commitments and indexes. Intuitively, `p_i` makes a signer’s response stick to the current round. Our code uses the library’s `Aggregator.binding_value(i, m, pairs, S)`.

### 4.6 Final signature equation

Per-signer:

```
z_i = d_i' + e_i'·p_i + λ_i(0)·s_i'·c  (mod q)
```

Aggregate and check:

```
z = Σ z_i (mod q)
assert   z·G == R_even + c·Y_even
```

---

## 5) CLI reference

### `workshop.keygen_trusted_dealer`

```
usage: python -m workshop.keygen_trusted_dealer [--t T] [--n N] [--seed SEED] [--quiet]
```

* `--t` threshold, `--n` participants, `--seed` for reproducibility
* Prints coefficients, commitments, shares, and verifies Feldman checks.

### `workshop.keygen_dkg`

```
usage: python -m workshop.keygen_dkg [--t T] [--n N] [--seed SEED] [--quiet]
```

* Runs DKG, prints each dealer’s commitments, and each receiver’s Feldman checks.

### `workshop.signing`

```
usage: python -m workshop.signing --mode {trusted,dkg} [--t T] [--n N]
       [--seed SEED] [--signers i,j[,...]] [--msg-utf8 TEXT | --msg-hex HEX]
       [--bip32-tweak INT --taproot-tweak INT]
```

* **Any** signer subset is allowed (e.g., `--signers 2,3`).
* Optional tweaks enable an effective tweaked key; parity is normalized post-tweak.

---

## 6) Reproducibility & determinism

* Use `--seed` to fix RNG in examples.
* Output values (coefficients, shares, commitments) will repeat across runs with same seed, `t`, `n`.

---

## 8) Security footguns (read this!)

* **Nonce reuse kills keys.** Never reuse `(d_i, e_i)` across sessions or messages.
* **Secrets in logs.** Our workshop scripts print many values for clarity—don’t use them in production.
* **Dealer honesty.** Trusted-dealer is only for demos. Use DKG in real systems.
* **Tweaks.** If you tweak keys, always normalize parity **after** tweak and flip shares accordingly.
