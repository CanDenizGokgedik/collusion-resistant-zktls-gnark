# tls-gnark

End-to-end Go implementation of the **Π_coll-min dx-DCTLS** protocol from
["Publicly Verifiable and Collusion-Resistant TLS Notarization"](#paper),
built on **gnark v0.10 / BLS12-381**.

This is a complete port of [tls-cosnark](../tls-cosnark) (Rust/arkworks) to Go/gnark.
Every component maps 1-to-1 to the paper's construction.

---

## Architecture

```
tls-gnark/
├── internal/
│   ├── circuit/
│   │   ├── tls_key.go      Mode 1 — K_MAC split commitment (~1 R1CS)
│   │   ├── tls_prf.go      Mode 2 — full TLS-PRF HMAC-SHA256 (~1.37M R1CS)
│   │   ├── pgp.go          PGP ZKP circuit — MiMC(KMacP, KMacV)
│   │   └── native.go       native off-circuit helpers
│   ├── cosnark/
│   │   ├── prover.go       Groth16 setup + central-mode prove/verify
│   │   ├── mpc.go          2-party co-SNARK: additive blinding protocol
│   │   └── dmsm.go         genuine distributed MSM for Groth16
│   ├── dvrf/
│   │   └── dvrf.go         DVRF — DDH-VRF on secp256k1, t-of-n Feldman VSS
│   ├── frost/
│   │   └── frost.go        FROST — threshold Schnorr on secp256k1, Feldman VSS
│   ├── deco/
│   │   └── deco.go         dx-DCTLS — HSP / QP / PGP phases
│   └── onchain/
│       └── verifier.go     SC.Verify(σ, pk) Go simulator + ABI encoder
└── cmd/
    ├── bench_dctls/        Isolated HSP overhead benchmark (§IX)
    └── bench_pipeline/     Full pipeline RC→Attest→Sign→OnChain (Table II)
```

---

## Quick start

```bash
# Fetch dependencies
go mod tidy

# Run all unit tests (no Groth16 proving, fast):
go test ./...

# Run all unit tests with verbose output:
go test -v ./...

# Run a specific package:
go test ./internal/dvrf/...
go test ./internal/frost/...
go test ./internal/cosnark/...
go test ./internal/deco/...
go test ./internal/onchain/...

# Stub benchmark — no real proving, just pipeline timing (< 5s):
go run ./cmd/bench_pipeline --stub

# HSP overhead benchmark — Mode 1 (K_MAC split, ~1ms prove):
go run ./cmd/bench_dctls --mode key

# HSP overhead benchmark — Mode 2 (full TLS-PRF, ~15s prove):
go run ./cmd/bench_dctls --mode prf

# Full pipeline benchmark — Mode 2, all 9 t-of-n configs:
go run ./cmd/bench_pipeline --mode prf

# Full pipeline benchmark — Mode 1:
go run ./cmd/bench_pipeline --mode key
```

---

## Running tests

```bash
# All packages, short mode
go test -count=1 ./...

# Skip slow Groth16 tests (unit-only)
go test -short ./...

# With race detector
go test -race ./internal/dvrf/... ./internal/frost/...

# Benchmarks (FROST, DVRF)
go test -bench=. ./internal/frost/...
go test -bench=. ./internal/dvrf/...
```

---

## Benchmark results

Results measured on **Apple M-series (ARM64)**, Go 1.22, gnark v0.10.

### Mode 2 — Full TLS-PRF pipeline

CRS setup: **340,295 ms one-time** (reused for all rows below)
R1CS constraints: **1,370,734**

```
Config       RC (ms)   Attest (ms)   Sign (ms)   OnChain (ms)   Total (ms)
────────────────────────────────────────────────────────────────────────────
2-of-3             5        13,839           2              0       13,846
3-of-5             9        14,173           4              0       14,186
5-of-9            20        14,076          10              0       14,106
7-of-13           38        14,086          16              0       14,140
10-of-19          75        14,262          31              0       14,368
15-of-29         192        14,284          67              0       14,543
20-of-39         429        14,246         107              0       14,782
30-of-59       1,522        14,187         251              0       15,960
50-of-99       8,411        14,256         626              0       23,293
```

Column definitions:
- **RC** — Randomness Committee phase: DVRF DKG (Feldman VSS) + PartialEval + Combine + Verify
- **Attest** — dx-DCTLS: HSP (ECDH + PRF + co-SNARK) + QP + PGP + VerifyDxDctlsProof
- **Sign** — FROST: DKG Reload + Round1 + Round2 + VerifySignatureShare + Aggregate + Verify
- **OnChain** — SC.Verify(σ, pk) Go simulation (~0ms, real cost on-chain ~3,272 gas)

**Attest is O(1) in n** — 13,839 ms at 2-of-3, 14,256 ms at 50-of-99 (2.7% variance).
This confirms paper Theorem 1: prover complexity is independent of committee size.

**RC scales with n** — Feldman VSS runs a genuine t-of-n DKG (O(n²·t) verification,
parallelised with goroutines). RC at 50-of-99 is 8,411 ms.

**Sign uses DKG Reload (paper §V)** — FROST signers are constructed from the DVRF
key material; a second DKG is never run. Sign at 50-of-99 is 626 ms.

---

### Mode 1 — K_MAC split only

| Metric | Result |
|---|---|
| R1CS constraints | 1 |
| CRS setup | < 10 ms |
| Prove (avg) | 1 ms |

---

### Paper comparison

| Metric | Paper (M3, gnark) | This repo (M-series, gnark) |
|---|---|---|
| Attest (HSP prove, Mode 2) | ~4,700 ms | ~15,000 ms |
| Mode 2 R1CS | 1,719,598 | 1,370,734 (−20.3%) |

The ~3× attest gap is due to M1/M2 vs M3 performance and the fact that Go's
gnark MSM is not compiled with `target-cpu=native` SIMD by default.
The lower R1CS count reflects gnark v0.10's more efficient SHA256 gadget
compared to the paper's reference version.

---

### Go vs Rust comparison

| Metric | Rust (ark 0.2 / BLS12-377) | Go (gnark / BLS12-381) | Note |
|---|---|---|---|
| CRS setup | 188,824 ms | 340,295 ms | Rust 1.8× faster (SIMD) |
| Attest 2-of-3 | 29,359 ms | 13,839 ms | **Go 2.1× faster** |
| Attest 50-of-99 | 29,411 ms | 14,256 ms | **Go 2.1× faster** |
| RC 50-of-99 | 33,458 ms | 8,411 ms | Both run real distributed DKG |
| Sign 50-of-99 | 64 ms | 626 ms | Rust has hand-optimised secp256k1 asm |
| Mode 2 R1CS | 1,719,598 | 1,370,734 | Go −20.3% (gnark v0.10 SHA256) |

**Key observations:**

- **Attest is ~2× faster in Go** — gnark/BLS12-381 MSM outperforms arkworks 0.2/BLS12-377.
- **RC is now comparable** — both repos run a real Feldman VSS DKG; Go is faster
  because goroutine-parallelised feldman verification reduces wall time.
- **Sign is 14× slower in Go** — gnark-crypto secp256k1 lacks Rust's hand-optimised
  assembly. The Go Sign time dropped from 11,500 ms to 923 ms after the DKG Reload
  fix (paper §V: FROST signers reuse DVRF key material, no second DKG).
- **CRS setup is 2× slower in Go** — no `target-cpu=native` SIMD in standard Go
  build; addressable with CGO backends.
- **R1CS delta −20.3%** — gnark v0.10 SHA256 has fewer constraints per compression
  than the paper's reference version.

---

## Protocol components

### DVRF (§III)
DDH-based distributed VRF on secp256k1 with Feldman VSS DKG.

- `RunDKG(n, t)` — real t-of-n Feldman VSS; no trusted dealer
- `PartialEval(p, α)` — γ_i = SK_i · H(α) with DLEQ proof
- `VerifyPartialEval(ev, vk, α)` — verifies DLEQ proof per evaluator
- `Combine(evals, α)` — Lagrange interpolation → VRF output
- `Verify(gk, α, evals, vks, out)` — full DVRF output verification (paper §III.B)

### FROST (§IV)
2-round threshold Schnorr signatures on secp256k1 with Feldman VSS DKG.

- `RunDKG(n, t)` — real t-of-n Feldman VSS; no trusted dealer
- `SignersFromKeyMaterial(...)` — DKG Reload: construct signers from DVRF key material
- `Round1` — nonce + commitment
- `Round2` — signature share z_i = d + e·ρ + λ·sk·c
- `VerifySignatureShare(...)` — per-share verification before aggregation (paper §III.C)
- `Aggregate` + `Verify`

### co-SNARK (§V, §VI)
Groth16 on BLS12-381 with additive blinding and genuine distributed MSM.

- `Setup(mode)` — compile circuit + Groth16 trusted setup
- `ExecuteDistributedMSM(...)` — genuine distributed MSM: each party contributes only
  its own G1/G2 elements; coordinator never sees private scalars (paper §VI)
- `ExecuteSplit(...)` — additive blinding protocol: commit-then-reveal over goroutines
- `Execute(...)` — central mode (reference / testing)
- `VerifyMpc(...)` — verifier check using public commitment

### dx-DCTLS (§VIII)
- **HSP** — ECDH handshake, TLS-PRF K_MAC derivation, field-additive split, co-SNARK
- **QP** — HMAC-SHA256(K_MAC, Q‖R) transcript commitment
- **PGP** — cross-binding hash + Groth16 ZKP (MiMC) over K_MAC shares
- **VerifyDxDctlsProof** — three-condition auxiliary verifier (π_HSP + π_PGP + DVRF.Verify)

### On-chain verifier (§VIII.B, §IX)
- `VerifySchnorr(sig, gk, msg)` — Go simulation of SC.Verify: S·G == R + c·PK
- `EncodeVerifyCall(...)` — ABI encoding for `SchnorrVerifier.verify(...)`
- `ComputeEcrecoverParams(...)` — ecrecover trick parameters
- Gas estimate: ~3,272 gas (verification logic only, excluding base tx)
- Solidity contract: `contracts/SchnorrVerifier.sol`

---

## Test coverage

```bash
go test -v ./...
```

```
ok  internal/circuit     8 tests   native helpers, Groth16 prove/verify, wrong commitment rejection
ok  internal/cosnark    10 tests   setup, central, split, verify, tamper, distributed MSM, vs-central
ok  internal/deco        8 tests   HSP, VerifyHSP, QP determinism, transcript verify, PGP ZKP, full DVRF pipeline
ok  internal/dvrf        6 tests   DKG, partial eval, verify partial, combine, verify, consistency
ok  internal/frost       7 tests   DKG, 2-of-3, 3-of-5, 5-of-9, wrong message, threshold>n, VerifySignatureShare
ok  internal/onchain     5 tests   SC.Verify valid, wrong message, wrong PK, ABI encoding, gas estimate
```

---

## Rust vs Go — full component comparison

| Component | tls-cosnark (Rust) | tls-gnark (Go) |
|---|---|---|
| Language | Rust 2021 | Go 1.22 |
| ZK backend | arkworks 0.2 / BLS12-377 | gnark 0.10 / BLS12-381 |
| HMAC-SHA256 circuit | Manual R1CS gadget | gnark std/hash/sha2 |
| Distributed MSM | collaborative-zksnark (real MPC) | dmsm.go (genuine distributed MSM) |
| Additive blinding | — | mpc.go (goroutine model) |
| DVRF | Rust secp256k1 + Pedersen VSS | gnark-crypto secp256k1 + Feldman VSS |
| FROST | frost-secp256k1 crate | Native implementation |
| DKG Reload | Yes | Yes (SignersFromKeyMaterial) |
| VerifySignatureShare | Yes | Yes |
| On-chain verifier | Solidity | Go simulator + SchnorrVerifier.sol |
| Attest speedup | baseline | **~2× faster** |

---

## Paper

> "Publicly Verifiable and Collusion-Resistant TLS Notarization"
> [docs/article.pdf](docs/article.pdf)

Key sections:
- §III — DVRF construction
- §IV — FROST threshold signatures
- §V-VI — co-SNARK and collusion resistance
- §VIII — dx-DCTLS full protocol
- §IX — benchmark methodology (Table I, Table II)

---

## License

MIT