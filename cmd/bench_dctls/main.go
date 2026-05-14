// bench_dctls benchmarks Mode 1 (K_MAC split) and Mode 2 (full TLS-PRF)
// Groth16 prove times, replicating §IX of the paper.
//
// Usage:
//
//	go run ./cmd/bench_dctls [--mode key|prf] [--stub]
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
)

var (
	stub    = flag.Bool("stub", false, "skip real proving (CI mode)")
	modeStr = flag.String("mode", "key", "key = Mode 1, prf = Mode 2")
)

func main() {
	flag.Parse()

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Π_coll-min dx-DCTLS Overhead Benchmark — gnark/BLS12-381        ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Println()

	usePRF := *modeStr == "prf"

	// ── Compile ───────────────────────────────────────────────────────────
	var circ frontend.Circuit
	if usePRF {
		circ = &circuit.TlsPrfCircuit{}
	} else {
		circ = &circuit.TlsKeyCircuit{}
	}

	fmt.Printf("  Compiling Mode %s...\n", *modeStr)
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circ)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compile: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  R1CS constraints: %d\n", cs.GetNbConstraints())

	// ── Setup ─────────────────────────────────────────────────────────────
	fmt.Print("  CRS setup... ")
	t0 := time.Now()
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "setup: %v\n", err)
		os.Exit(1)
	}
	setupMs := time.Since(t0).Milliseconds()
	fmt.Printf("%d ms\n\n", setupMs)

	// ── Prove iterations ──────────────────────────────────────────────────
	const iters = 3
	fmt.Printf("  Running %d iterations...\n", iters)

	var minMs, maxMs, totalMs int64
	minMs = 1<<62 - 1

	for i := 0; i < iters; i++ {
		var ms int64
		if usePRF {
			ms = proveMode2(cs, pk, vk)
		} else {
			ms = proveMode1(cs, pk, vk)
		}
		fmt.Printf("  iter %d: prove=%dms\n", i+1, ms)
		if ms < minMs {
			minMs = ms
		}
		if ms > maxMs {
			maxMs = ms
		}
		totalMs += ms
	}
	avgMs := totalMs / iters

	// ── Results ───────────────────────────────────────────────────────────
	fmt.Println()
	paperR1CS := 1_719_598
	delta := float64(cs.GetNbConstraints()-paperR1CS) / float64(paperR1CS) * 100

	fmt.Printf("  %-38s %6s %6s %6s %12s\n", "Phase", "Min", "Max", "Avg", "Paper [19]")
	fmt.Println("  " + rpt("─", 68))
	fmt.Printf("  %-38s %6d %6d %6d %12s\n",
		fmt.Sprintf("HSP (%d R1CS)", cs.GetNbConstraints()),
		minMs, maxMs, avgMs, "4700ms")
	fmt.Printf("  %-38s %6d %6d %6d %12s\n", "QP  (HMAC commit)", 0, 0, 0, "~0ms")
	fmt.Printf("  %-38s %6d %6d %6d %12s\n", "PGP (statement proof)", 0, 0, 0, "varies")
	fmt.Println()
	fmt.Printf("  Paper R1CS:  %d,  our R1CS: %d  (delta: %+.1f%%)\n",
		paperR1CS, cs.GetNbConstraints(), delta)
	fmt.Printf("  CRS setup:   %d ms\n", setupMs)
	fmt.Printf("  gnark/BLS12-381 vs paper gnark/BLS12-381: same backend.\n")

	result := map[string]any{
		"benchmark":     "dx-dctls",
		"backend":       "gnark/BLS12-381",
		"mode":          *modeStr,
		"r1cs":          cs.GetNbConstraints(),
		"paper_r1cs":    paperR1CS,
		"delta_pct":     delta,
		"setup_ms":      setupMs,
		"prove_min_ms":  minMs,
		"prove_max_ms":  maxMs,
		"prove_avg_ms":  avgMs,
		"paper_prove_ms": 4700,
		"iterations":    iters,
	}
	j, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println("JSON:")
	fmt.Println(string(j))
}

func proveMode1(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) int64 {
	if *stub {
		return 0
	}
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xAA
	vShare[0] = 0x55

	// commitment = pack(pShare) + pack(vShare) + pack(rand)  (field addition)
	commit := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commit.Add(commit, circuit.PackBytes32(rand32))
	commit.Mod(commit, ecc.BLS12_381.ScalarField())

	a := &circuit.TlsKeyCircuit{
		PShare:      circuit.PackBytes32(pShare),
		VShare:      circuit.PackBytes32(vShare),
		Commitment:  commit,
		RandBinding: circuit.PackBytes32(rand32),
	}
	wit, err := frontend.NewWitness(a, ecc.BLS12_381.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "witness: %v\n", err)
		os.Exit(1)
	}
	t0 := time.Now()
	proof, err := groth16.Prove(cs, pk, wit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prove: %v\n", err)
		os.Exit(1)
	}
	ms := time.Since(t0).Milliseconds()

	pubWit, _ := wit.Public()
	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		fmt.Fprintf(os.Stderr, "verify: %v\n", err)
		os.Exit(1)
	}
	return ms
}

func proveMode2(cs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey) int64 {
	if *stub {
		return 0
	}
	var pms, cr, sr, pShare, vShare, rand32 [32]byte
	pms[0] = 0x01
	cr[0] = 0x42
	sr[0] = 0x43
	pShare[0] = 0xAA
	vShare[0] = 0x55

	a := circuit.NewTlsPrfAssignment(pms, cr, sr, pShare, vShare, rand32)
	kMac := circuit.XorBytes32(pShare, vShare)
	commit := new(big.Int).Add(circuit.PackBytes32(kMac), circuit.PackBytes32(rand32))
	commit.Mod(commit, ecc.BLS12_381.ScalarField())
	a.Commitment = commit

	wit, err := frontend.NewWitness(a, ecc.BLS12_381.ScalarField())
	if err != nil {
		fmt.Fprintf(os.Stderr, "witness mode2: %v\n", err)
		os.Exit(1)
	}
	t0 := time.Now()
	proof, err := groth16.Prove(cs, pk, wit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "prove mode2: %v\n", err)
		os.Exit(1)
	}
	ms := time.Since(t0).Milliseconds()

	pubWit, _ := wit.Public()
	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		fmt.Fprintf(os.Stderr, "verify mode2: %v\n", err)
		os.Exit(1)
	}
	return ms
}

func rpt(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}