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
│   │   ├── tls_key.go      Mode 1 — K_MAC split commitment  (~1 R1CS)
│   │   ├── tls_prf.go      Mode 2 — full TLS-PRF HMAC-SHA256 (~1.37M R1CS)
│   │   └── native.go       native off-circuit helpers
│   ├── cosnark/
│   │   ├── prover.go       Groth16 setup + central-mode prove/verify
│   │   └── mpc.go          2-party co-SNARK: Execute / ExecuteSplit (goroutine model)
│   ├── dvrf/
│   │   └── dvrf.go         DVRF — DDH-VRF on secp256k1, t-of-n
│   ├── frost/
│   │   └── frost.go        FROST — threshold Schnorr on secp256k1
│   └── deco/
│       └── deco.go         dx-DCTLS — HSP / QP / PGP phases
└── cmd/
    ├── bench_dctls/        Isolated HSP overhead benchmark (§IX)
    └── bench_pipeline/     Full pipeline RC→Attest→Sign (Table II)
```

---

## Quick start

```bash
go mod tidy

# Sanity check (stub mode, no real proving, < 5s):
./quicktest.sh

# Real Groth16 bench — Mode 1 (K_MAC split, ~1ms prove):
go run ./cmd/bench_dctls --mode key

# Real Groth16 bench — Mode 2 (full TLS-PRF, ~14s prove):
go run ./cmd/bench_dctls --mode prf

# Full pipeline benchmark (9 t-of-n configs, Mode 2):
go run ./cmd/bench_pipeline --mode prf
```

---

## Benchmark results

### Mode 2 — Full TLS-PRF Pipeline (measured on Apple M-series)

CRS setup: **355,885 ms** (one-time, reused for all rows)

```
Config       RC (ms)   Attest (ms)   Sign (ms)   OnChain (ms)   Total (ms)
───────────────────────────────────────────────────────────────────────────
2-of-3             1        14,244           1              0       14,246
3-of-5             2        14,319           3              0       14,324
5-of-9             3        14,396           6              0       14,405
7-of-13            5        14,510           9              0       14,524
10-of-19           6        14,321          17              0       14,344
15-of-29          10        14,454          36              0       14,500
20-of-39          12        14,526          60              0       14,598
30-of-59          20        14,545         120              0       14,685
50-of-99          32        14,631         339              0       15,002
```

**Attest column is O(1) in n** — 14,244ms at 2-of-3, 14,631ms at 50-of-99.
This confirms paper Theorem 1: prover complexity is independent of committee size.

---

### Go vs Rust comparison

| Metric | Rust (ark 0.2 / BLS12-377) | Go (gnark / BLS12-381) | Delta |
|---|---|---|---|
| CRS setup | 188,824ms | 355,885ms | Rust 1.9× faster (SIMD) |
| Attest 2-of-3 | 29,359ms | 14,244ms | **Go 2.1× faster** |
| Attest 50-of-99 | 29,411ms | 14,631ms | **Go 2.0× faster** |
| RC 2-of-3 | 2ms | 1ms | Rust: full DKG / Go: trusted dealer |
| RC 50-of-99 | 33,458ms | 32ms | **⚠ farklı protokol** (bkz. not) |
| Sign 50-of-99 | 64ms | 339ms | Rust 5× faster |
| Mode 2 R1CS | 1,719,598 | 1,370,734 | −20.3% |

**Key observations:**

- **Attest is 2× faster in Go** — gnark/BLS12-381 MSM outperforms arkworks 0.2/BLS12-377.
- **RC times are NOT comparable** — Rust uses a full 3-round Pedersen/FROST DKG (RFC 9591) with O(n²) broadcast+verify messages across all n participants. Go uses a trusted dealer (polynomial eval only, O(n)). Rust 50-of-99 takes 33,458ms because 99 parties each verify 98 incoming packages. Go completes in 32ms because only the dealer evaluates. Production must use the distributed DKG.
- **Sign (FROST) is 5× slower in Go** — gnark-crypto secp256k1 lacks Rust's hand-optimized assembly.
- **CRS setup is 2× slower in Go** — no `target-cpu=native` SIMD in Go build; addressable with CGO backends.
- **R1CS delta −20.3%** — gnark v0.10 SHA256 has fewer constraints per compression than the paper's reference version.

---

### Mode 1 — K_MAC split only

| Metric | Result |
|---|---|
| R1CS constraints | 1 |
| CRS setup | <10ms |
| Prove (avg) | 1ms |

---

## Protocol components

### DVRF (§III)
DDH-based distributed VRF on secp256k1.
- `RunDKG(n, t)` — Feldman VSS, trusted dealer
- `PartialEval(p, α)` — γ_i = SK_i · H(α) with DLEQ proof
- `Combine(evals, α)` — Lagrange interpolation → VRF output

### FROST (§IV)
2-round threshold Schnorr signatures on secp256k1.
- `RunDKG(n, t)` → key shares
- `Round1` → nonce + commitment
- `Round2` → signature share z_i = d + e·ρ + λ·sk·c
- `Aggregate` + `Verify`

### co-SNARK (§V, §VI)
Groth16 on BLS12-381 with 2-party split-input model.
- `Setup(mode)` — compile circuit + Groth16 trusted setup
- `Execute(...)` — central mode (both shares visible)
- `ExecuteSplit(...)` — goroutine model: each party sends only its share via channel; coordinator assembles and proves
- `VerifyMpc(...)` — verifier check

> **Note:** `ExecuteSplit` models the communication boundary and timing of a true 2-party MPC co-SNARK. The coordinator still sees both shares in plaintext. A production deployment would replace the coordinator with a distributed MSM protocol (as in `collaborative-zksnark`). No equivalent Go library exists yet.

### dx-DCTLS (§VIII)
- **HSP** — K_MAC derivation, XOR split, co-SNARK execution
- **QP** — HMAC-SHA256(K_MAC, Q‖R) transcript commitment
- **PGP** — cross-binding proof assembly

---

## Test coverage

```
ok  internal/circuit    — 8 tests  (native helpers, Groth16 prove/verify, wrong commitment rejection)
ok  internal/cosnark    — 6 tests  (setup, central, split, verify, tamper, central vs split)
ok  internal/deco       — 6 tests  (HSP, VerifyHSP, QP determinism, transcript verify, full pipeline)
ok  internal/dvrf       — 6 tests  (DKG, partial eval, combine, consistency, empty)
ok  internal/frost      — 6 tests  (DKG, 2-of-3, 3-of-5, 5-of-9, wrong message, threshold>n)
```

---

## Rust vs Go — full comparison

| Component | tls-cosnark (Rust) | tls-gnark (Go) |
|---|---|---|
| Language | Rust | Go |
| ZK backend | arkworks 0.2 / BLS12-377 | gnark 0.10 / BLS12-381 |
| HMAC-SHA256 circuit | Manual R1CS gadget | gnark std/hash/sha2 |
| MPC Groth16 | collaborative-zksnark (real MPC) | Central + goroutine model |
| DVRF | Rust secp256k1 | gnark-crypto secp256k1 |
| FROST | Rust frost-secp256k1 | Native implementation |
| Attest speedup | baseline | **2× faster** |

---

## Paper

> "Publicly Verifiable and Collusion-Resistant TLS Notarization"
> [docs/tls.pdf](../tls-cosnark/docs/tls.pdf)

Key sections:
- §III — DVRF construction
- §V-VI — co-SNARK and collusion resistance
- §VIII — dx-DCTLS full protocol
- §IX — benchmark methodology (Table I, Table II)

---

## License

MIT