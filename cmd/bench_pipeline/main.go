// bench_pipeline benchmarks the full Π_coll-min pipeline:
//
//	RC (DVRF) → Attestation (dx-DCTLS + co-SNARK) → Signing (FROST) → On-chain
//
// Usage:
//
//	go run ./cmd/bench_pipeline [--mode key|prf] [--stub]
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
	"github.com/CanDenizGokgedik/tls-gnark/internal/dvrf"
	"github.com/CanDenizGokgedik/tls-gnark/internal/frost"
)

var (
	stub    = flag.Bool("stub", false, "skip Groth16 proof (CI mode)")
	modeStr = flag.String("mode", "key", "key = Mode 1, prf = Mode 2")
)

var configs = []struct{ T, N int }{
	{2, 3}, {3, 5}, {5, 9}, {7, 13}, {10, 19},
	{15, 29}, {20, 39}, {30, 59}, {50, 99},
}

type row struct {
	Config    string `json:"config"`
	RcMs      int64  `json:"rc_ms"`
	AttestMs  int64  `json:"attest_ms"`
	SignMs    int64  `json:"sign_ms"`
	OnchainMs int64  `json:"onchain_ms"`
	TotalMs   int64  `json:"total_ms"`
}

func main() {
	flag.Parse()
	usePRF := *modeStr == "prf"

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Π_coll-min Full Pipeline — RC → dx-DCTLS → FROST → On-chain    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n  Mode: %s | Backend: gnark/BLS12-381\n\n", *modeStr)

	// ── One-time CRS setup ─────────────────────────────────────────────────
	var cs constraint.ConstraintSystem
	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var setupMs int64

	if !*stub {
		fmt.Print("  [setup] Generating CRS... ")
		var circ frontend.Circuit
		if usePRF {
			circ = &circuit.TlsPrfCircuit{}
		} else {
			circ = &circuit.TlsKeyCircuit{}
		}
		var err error
		t0 := time.Now()
		cs, err = frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circ)
		if err != nil {
			fmt.Fprintf(os.Stderr, "compile: %v\n", err)
			os.Exit(1)
		}
		pk, vk, err = groth16.Setup(cs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "setup: %v\n", err)
			os.Exit(1)
		}
		setupMs = time.Since(t0).Milliseconds()
		fmt.Printf("%d ms  (reused for all rows)\n\n", setupMs)
	}

	// ── Per-config runs ────────────────────────────────────────────────────
	fmt.Printf("  %-14s %8s %12s %10s %12s %12s\n",
		"Config", "RC(ms)", "Attest(ms)", "Sign(ms)", "OnChain(ms)", "Total(ms)")
	fmt.Println("  " + rpt("─", 72))

	var rows []row
	for _, cfg := range configs {
		r := runConfig(cfg.T, cfg.N, cs, pk, vk, usePRF)
		fmt.Printf("  %-14s %8d %12d %10d %12d %12d\n",
			fmt.Sprintf("%d-of-%d", cfg.T, cfg.N),
			r.RcMs, r.AttestMs, r.SignMs, r.OnchainMs, r.TotalMs)
		rows = append(rows, r)
	}

	out := map[string]any{
		"benchmark":     "pi-coll-min-pipeline",
		"backend":       "gnark/BLS12-381",
		"mode":          *modeStr,
		"paper_section": "§VIII, Table II",
		"setup_ms":      setupMs,
		"results":       rows,
	}
	j, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("\nJSON:")
	fmt.Println(string(j))

	fmt.Println()
	fmt.Println("  Paper Table II:")
	fmt.Println("  ┌─────────────────┬──────────┬────────────┬──────────────┐")
	fmt.Println("  │                 │   DECO   │  DECO-DON  │  Π_coll-min  │")
	fmt.Println("  ├─────────────────┼──────────┼────────────┼──────────────┤")
	fmt.Println("  │ Prover Complexity│  O(1)   │   O(n)     │    O(1) ←    │")
	fmt.Println("  │ Public Verif.   │   No     │   Yes      │    Yes       │")
	fmt.Println("  │ Collusion Res.  │   No     │   Yes      │    Yes       │")
	fmt.Println("  │ Aux Node Load   │  N/A     │   Heavy    │  Lightweight │")
	fmt.Println("  └─────────────────┴──────────┴────────────┴──────────────┘")
}

func runConfig(t, n int, cs constraint.ConstraintSystem,
	pk groth16.ProvingKey, vk groth16.VerifyingKey, usePRF bool) row {

	msg := [32]byte{0xEE}
	alpha := [32]byte{0x42}

	// ── RC: DVRF ──────────────────────────────────────────────────────────
	t0 := time.Now()
	dkgOuts, err := dvrf.RunDKG(n, t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dvrf DKG:", err)
		os.Exit(1)
	}
	var partials []*dvrf.Eval
	for i := 0; i < t; i++ {
		pe, err := dvrf.PartialEval(&dkgOuts[i].Participant, alpha)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dvrf eval:", err)
			os.Exit(1)
		}
		partials = append(partials, pe)
	}
	dvrfOut, err := dvrf.Combine(partials, alpha)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dvrf combine:", err)
		os.Exit(1)
	}
	rcMs := time.Since(t0).Milliseconds()
	rand32 := dvrfOut.Rand

	// ── Attestation: co-SNARK ─────────────────────────────────────────────
	t1 := time.Now()
	var pShare, vShare [32]byte
	for i := range pShare {
		pShare[i] = rand32[i] ^ 0xAA
	}
	vShare[0] = 0x55

	commit := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commit.Add(commit, circuit.PackBytes32(rand32))
	commit.Mod(commit, ecc.BLS12_381.ScalarField())

	if !*stub {
		var assignment frontend.Circuit
		if usePRF {
			var pms, cr, sr [32]byte
			a := circuit.NewTlsPrfAssignment(pms, cr, sr, pShare, vShare, rand32)
			a.Commitment = commit
			assignment = a
		} else {
			assignment = &circuit.TlsKeyCircuit{
				PShare:      circuit.PackBytes32(pShare),
				VShare:      circuit.PackBytes32(vShare),
				Commitment:  commit,
				RandBinding: circuit.PackBytes32(rand32),
			}
		}
		wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
		if err != nil {
			fmt.Fprintln(os.Stderr, "witness:", err)
			os.Exit(1)
		}
		proof, err := groth16.Prove(cs, pk, wit)
		if err != nil {
			fmt.Fprintln(os.Stderr, "prove:", err)
			os.Exit(1)
		}
		pubWit, _ := wit.Public()
		if err := groth16.Verify(proof, vk, pubWit); err != nil {
			fmt.Fprintln(os.Stderr, "verify:", err)
			os.Exit(1)
		}
	}
	attestMs := time.Since(t1).Milliseconds()

	// ── Signing: FROST ────────────────────────────────────────────────────
	t2 := time.Now()
	frostOuts, err := frost.RunDKG(n, t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "frost DKG:", err)
		os.Exit(1)
	}
	var nonces []*frost.Nonce
	var commitments []*frost.Commitment
	for i := 0; i < t; i++ {
		no, cm, err := frost.Round1(&frostOuts[i].Signer)
		if err != nil {
			fmt.Fprintln(os.Stderr, "frost r1:", err)
			os.Exit(1)
		}
		nonces = append(nonces, no)
		commitments = append(commitments, cm)
	}
	var shares []*frost.SignatureShare
	for i := 0; i < t; i++ {
		sh, err := frost.Round2(&frostOuts[i].Signer, nonces[i], commitments, msg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "frost r2:", err)
			os.Exit(1)
		}
		shares = append(shares, sh)
	}
	sig, err := frost.Aggregate(commitments, shares, msg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "frost agg:", err)
		os.Exit(1)
	}
	if !frost.Verify(sig, frostOuts[0].GroupKey, msg) {
		fmt.Fprintln(os.Stderr, "frost verify failed")
		os.Exit(1)
	}
	signMs := time.Since(t2).Milliseconds()

	// ── On-chain: ABI encode stub ─────────────────────────────────────────
	t3 := time.Now()
	_ = abiEncode(sig, msg)
	onchainMs := time.Since(t3).Milliseconds()

	return row{
		Config:    fmt.Sprintf("%d-of-%d", t, n),
		RcMs:      rcMs,
		AttestMs:  attestMs,
		SignMs:    signMs,
		OnchainMs: onchainMs,
		TotalMs:   rcMs + attestMs + signMs + onchainMs,
	}
}

func abiEncode(sig *frost.Signature, msg [32]byte) []byte {
	out := make([]byte, 128)
	xb := sig.R.X.BigInt(new(big.Int)).Bytes()
	sb := sig.S.BigInt(new(big.Int)).Bytes()
	copy(out[32-len(xb):32], xb)
	copy(out[64-len(sb):64], sb)
	copy(out[64:96], msg[:])
	return out
}

func rpt(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}