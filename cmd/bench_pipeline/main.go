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
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"

	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
	"github.com/CanDenizGokgedik/tls-gnark/internal/deco"
	"github.com/CanDenizGokgedik/tls-gnark/internal/dvrf"
	"github.com/CanDenizGokgedik/tls-gnark/internal/frost"
	"github.com/CanDenizGokgedik/tls-gnark/internal/onchain"
)

var (
	stub    = flag.Bool("stub", false, "skip Groth16 proof (CI mode)")
	modeStr = flag.String("mode", "key", "key = Mode 1, prf = Mode 2")
)

// Groth16 CRS is now held as cosnark.CRS and deco.PgpCRS.
// bench_pipeline uses these types instead of raw groth16 variables.
var (
	_ groth16.ProvingKey    // keep imports alive
	_ groth16.VerifyingKey
	_ constraint.ConstraintSystem
)

var configs = []struct{ T, N int }{
	{3, 5}, {5, 9}, {7, 13}, {10, 19},
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
	_ = usePRF // mode selection is handled inside cosnark.Setup

	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  Π_coll-min Full Pipeline — RC → dx-DCTLS → FROST → On-chain    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════╝")
	fmt.Printf("\n  Mode: %s | Backend: gnark/BLS12-381\n\n", *modeStr)

	// ── One-time CRS setup ─────────────────────────────────────────────────
	var hspCRS *cosnark.CRS
	var pgpCRS *deco.PgpCRS
	var setupMs int64

	if !*stub {
		fmt.Print("  [setup] Generating HSP CRS... ")
		t0 := time.Now()
		mode := cosnark.ModeKey
		if usePRF {
			mode = cosnark.ModePRF
		}
		var err error
		hspCRS, _, err = cosnark.Setup(mode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "hsp setup: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("OK (%d ms)\n", time.Since(t0).Milliseconds())

		fmt.Print("  [setup] Generating PGP CRS... ")
		t1 := time.Now()
		pgpCRS, err = deco.SetupPGP()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pgp setup: %v\n", err)
			os.Exit(1)
		}
		setupMs = time.Since(t0).Milliseconds()
		fmt.Printf("OK (%d ms)  (both CRS objects are reused across all rows)\n\n",
			time.Since(t1).Milliseconds())
	}

	// ── Per-config runs ────────────────────────────────────────────────────
	fmt.Printf("  %-14s %8s %12s %10s %12s %12s\n",
		"Config", "RC(ms)", "Attest(ms)", "Sign(ms)", "OnChain(ms)", "Total(ms)")
	fmt.Println("  " + rpt("─", 72))

	var rows []row
	for _, cfg := range configs {
		r := runConfig(cfg.T, cfg.N, hspCRS, pgpCRS)
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

func runConfig(t, n int, hspCRS *cosnark.CRS, pgpCRS *deco.PgpCRS) row {
	msg := [32]byte{0xEE}
	alpha := [32]byte{0x42}
	var certHash [32]byte
	certHash[0] = 0xCE

	// ── RC: DVRF (paper §RC phase) ───────────────────────────────────────
	// Steps: DKG → PartialEval → VerifyPartialEval → Combine → Verify
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
		// Paper §III.B: verify each partial evaluation with its DLEQ proof.
		if !dvrf.VerifyPartialEval(pe, dkgOuts[i].Participant.VK, alpha) {
			fmt.Fprintln(os.Stderr, "dvrf VerifyPartialEval failed (signer", i+1, ")")
			os.Exit(1)
		}
		partials = append(partials, pe)
	}
	dvrfOut, err := dvrf.Combine(partials, alpha)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dvrf combine:", err)
		os.Exit(1)
	}
	// Paper §III.B: verify the combined DVRF output.
	secp256k1VKs := make([]secp256k1.G1Affine, t)
	for i := 0; i < t; i++ {
		secp256k1VKs[i] = dkgOuts[i].Participant.VK
	}
	if !dvrf.Verify(dkgOuts[0].GroupKey, alpha, partials, secp256k1VKs, dvrfOut) {
		fmt.Fprintln(os.Stderr, "dvrf.Verify failed")
		os.Exit(1)
	}
	rcMs := time.Since(t0).Milliseconds()
	rand32 := dvrfOut.Rand

	// ── Attestation: dx-DCTLS (HSP → QP → PGP) ──────────────────────────
	// Paper §V: uses deco.HSP, deco.QP, deco.PGP.
	// In stub mode there is no CRS; only timing is measured.
	t1 := time.Now()
	if hspCRS != nil {
		sess, err := deco.HSP(hspCRS, rand32, certHash)
		if err != nil {
			fmt.Fprintln(os.Stderr, "deco HSP:", err)
			os.Exit(1)
		}
		qr := deco.QP(sess, []byte("GET /oracle"), []byte(`{"v":1}`))
		dvrf_bundle := &deco.DVRFBundle{
			Output: dvrfOut,
			Evals:  partials,
			VKs:    secp256k1VKs,
			GK:     dkgOuts[0].GroupKey,
			Alpha:  alpha,
		}
		piAttest := deco.PGP(sess, qr, []byte("v==1"), pgpCRS, dvrf_bundle)

		// Auxiliary verifier: VerifyDxDctlsProof (Condition 1 + 2 + 3).
		if err := deco.VerifyDxDctlsProof(piAttest, hspCRS, pgpCRS, rand32, certHash); err != nil {
			fmt.Fprintln(os.Stderr, "VerifyDxDctlsProof:", err)
			os.Exit(1)
		}
	}
	attestMs := time.Since(t1).Milliseconds()

	// ── Signing: FROST (paper §Sign phase) ──────────────────────────────
	// Paper §V: "DKG Reload" — the same secp256k1 key material as DVRF is
	// reused; a second DKG is not run.
	// Steps: Reload → Round1 → Round2 → VerifySignatureShare → Aggregate → Verify
	t2 := time.Now()
	indices := make([]int, t)
	sks := make([]fr.Element, t)
	vks := make([]secp256k1.G1Affine, t)
	for i := 0; i < t; i++ {
		indices[i] = dkgOuts[i].Participant.Index
		sks[i] = dkgOuts[i].Participant.SK
		vks[i] = dkgOuts[i].Participant.VK
	}
	frostOuts, err := frost.SignersFromKeyMaterial(
		indices, sks, vks, dkgOuts[0].GroupKey.Point, n, t,
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "frost reload:", err)
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
		// Paper §III.C: verify each share before calling Aggregate.
		if !frost.VerifySignatureShare(sh, commitments[i], frostOuts[i].Signer.VK,
			commitments, frostOuts[0].GroupKey, msg) {
			fmt.Fprintln(os.Stderr, "frost VerifySignatureShare failed (signer", i+1, ")")
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

	// ── On-chain: SC.Verify(σ, pk) — paper §VIII.B, §IX ────────────────
	// Real verification: S·G == R + c·PK  (~3,344 gas via ecrecover trick)
	t3 := time.Now()
	res, err := onchain.VerifySchnorr(sig, frostOuts[0].GroupKey, msg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "SC.Verify:", err)
		os.Exit(1)
	}
	if !res.Valid {
		fmt.Fprintln(os.Stderr, "SC.Verify: signature invalid")
		os.Exit(1)
	}
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


func rpt(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}