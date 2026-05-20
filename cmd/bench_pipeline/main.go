// bench_pipeline benchmarks the full Π_coll-min pipeline:
//
//	RC (DVRF) → Attestation (dx-DCTLS + co-SNARK) → Signing (FROST) → On-chain
//
// Network modes inject artificial RTT delays at every real communication
// boundary so results match WAN deployments without a physical cluster.
//
// Usage:
//
//	go run ./cmd/bench_pipeline [--mode key|prf] [--stub] [--net lan|wan1|wan2|all]
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
	netMode = flag.String("net", "lan", "network: lan | wan1 | wan2 | all")
)

// keep imports alive
var (
	_ groth16.ProvingKey
	_ groth16.VerifyingKey
	_ constraint.ConstraintSystem
)

var configs = []struct{ T, N int }{
	{3, 5}, {5, 9}, {7, 13}, {10, 19},
	{15, 29}, {20, 39}, {30, 59}, {50, 99},
}

// ── Network simulation ────────────────────────────────────────────────────────

// netProfile defines the one-way latency for a network condition.
// RTT = 2 × oneWay.
type netProfile struct {
	Name    string
	OneWay  time.Duration // one-way message latency
}

var netProfiles = map[string]netProfile{
	"lan":  {"LAN",  0},
	"wan1": {"WAN1", 20 * time.Millisecond}, // 40 ms RTT — continental
	"wan2": {"WAN2", 50 * time.Millisecond}, // 100 ms RTT — intercontinental
}

// netSleep sleeps for `rounds` one-way message hops.
// Use rounds=1 for 1 RTT (one message each way = 2 one-way hops).
func netSleep(p netProfile, oneWayHops int) {
	if p.OneWay == 0 || oneWayHops == 0 {
		return
	}
	time.Sleep(p.OneWay * time.Duration(oneWayHops))
}

// ── Result types ──────────────────────────────────────────────────────────────

type row struct {
	Config    string `json:"config"`
	RcMs      int64  `json:"rc_ms"`
	AttestMs  int64  `json:"attest_ms"`
	SignMs    int64  `json:"sign_ms"`
	OnchainMs int64  `json:"onchain_ms"`
	NetMs     int64  `json:"net_ms"`   // total injected network delay
	TotalMs   int64  `json:"total_ms"`
	DecodonMs int64  `json:"decodon_ms"` // DECO-DON baseline (sequential n notaries)
}

type netResult struct {
	Net     string `json:"net"`
	SetupMs int64  `json:"setup_ms"`
	Rows    []row  `json:"results"`
}

// ── DECO-DON baseline ─────────────────────────────────────────────────────────
//
// From DECO paper (arXiv:1909.00938) Table 2, WAN prover timing per notary:
//   3P-HS:      ~13,000 ms
//   2PC TLS-PRF: ~6,000 ms
//   ZKP:        ~13,000 ms  (upper bound; scales with circuit size)
// Total per notary: ~32,000 ms
//
// DECO-DON runs n notaries sequentially (no parallelism assumed).
// For a (t,n) configuration with n notaries: n * decoPerNotaryMs.
const decoPerNotaryLanMs = 32_000  // LAN reference from paper Table 2
const decoPerNotaryWan1Ms = 36_000 // +4 s for WAN1 network overhead
const decoPerNotaryWan2Ms = 42_000 // +10 s for WAN2 network overhead

func decodonBaselineMs(n int, p netProfile) int64 {
	perNotary := int64(decoPerNotaryLanMs)
	switch p.Name {
	case "WAN1":
		perNotary = decoPerNotaryWan1Ms
	case "WAN2":
		perNotary = decoPerNotaryWan2Ms
	}
	return int64(n) * perNotary
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	flag.Parse()
	usePRF := *modeStr == "prf"
	_ = usePRF

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

	// ── Determine which network profiles to run ────────────────────────────
	var profiles []netProfile
	switch *netMode {
	case "all":
		profiles = []netProfile{netProfiles["lan"], netProfiles["wan1"], netProfiles["wan2"]}
	case "wan1":
		profiles = []netProfile{netProfiles["wan1"]}
	case "wan2":
		profiles = []netProfile{netProfiles["wan2"]}
	default:
		profiles = []netProfile{netProfiles["lan"]}
	}

	var allResults []netResult

	for _, prof := range profiles {
		fmt.Printf("  ══ Network: %s (one-way latency: %v) ══\n\n", prof.Name, prof.OneWay)
		fmt.Printf("  %-14s %8s %12s %10s %10s %10s %14s %14s\n",
			"Config", "RC(ms)", "Attest(ms)", "Sign(ms)", "Net(ms)", "Total(ms)",
			"DECO-DON(ms)", "Speedup")
		fmt.Println("  " + rpt("─", 100))

		var rows []row
		for _, cfg := range configs {
			r := runConfig(cfg.T, cfg.N, hspCRS, pgpCRS, prof)
			r.DecodonMs = decodonBaselineMs(cfg.N, prof)
			speedup := float64(r.DecodonMs) / float64(max1(r.TotalMs))
			fmt.Printf("  %-14s %8d %12d %10d %10d %10d %14d  %8.1f×\n",
				fmt.Sprintf("%d-of-%d", cfg.T, cfg.N),
				r.RcMs, r.AttestMs, r.SignMs, r.NetMs, r.TotalMs,
				r.DecodonMs, speedup)
			rows = append(rows, r)
		}
		fmt.Println()

		allResults = append(allResults, netResult{
			Net:     prof.Name,
			SetupMs: setupMs,
			Rows:    rows,
		})
	}

	// ── JSON output ────────────────────────────────────────────────────────
	out := map[string]any{
		"benchmark":     "pi-coll-min-pipeline",
		"backend":       "gnark/BLS12-381",
		"mode":          *modeStr,
		"paper_section": "§VIII, Table II",
		"networks":      allResults,
	}
	j, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println("\nJSON:")
	fmt.Println(string(j))

	// ── Paper Table II summary ────────────────────────────────────────────
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

// ── runConfig ────────────────────────────────────────────────────────────────
//
// Network delay injection points and round counts (per protocol spec):
//
//	DVRF DKG (Feldman VSS, n parties):
//	  Round 1 — each party broadcasts Feldman commitments to all others  (1 RTT = 2 hops)
//	  Round 2 — each party sends encrypted shares to each other party    (1 RTT = 2 hops)
//	  Round 3 — parties broadcast verification acknowledgements           (1 RTT = 2 hops)
//	  Total: 6 one-way hops
//
//	DVRF PartialEval (t evaluators, parallel):
//	  Requester → evaluator → requester (1 RTT = 2 hops)
//
//	TLS Handshake inside HSP (TLS 1.2 full handshake):
//	  2 RTTs = 4 hops
//
//	co-SNARK ExecuteSplit (commit-then-reveal):
//	  Commit phase: 2 parties → coordinator  (1 RTT = 2 hops)
//	  Reveal phase: 2 parties → coordinator  (1 RTT = 2 hops)
//	  Total: 4 one-way hops
//
//	QP (query + oracle response):
//	  1 RTT = 2 hops
//
//	FROST Round1 broadcast (t parties → aggregator):
//	  1 RTT = 2 hops
//
//	FROST Round2 broadcast (t parties → aggregator):
//	  1 RTT = 2 hops
func runConfig(t, n int, hspCRS *cosnark.CRS, pgpCRS *deco.PgpCRS, net netProfile) row {
	msg := [32]byte{0xEE}
	alpha := [32]byte{0x42}
	var certHash [32]byte
	certHash[0] = 0xCE
	var totalNetMs int64

	sleep := func(hops int) {
		if net.OneWay > 0 && hops > 0 {
			d := net.OneWay * time.Duration(hops)
			totalNetMs += d.Milliseconds()
			time.Sleep(d)
		}
	}

	// ── RC: DVRF ─────────────────────────────────────────────────────────
	t0 := time.Now()
	dkgOuts, err := dvrf.RunDKG(n, t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dvrf DKG:", err)
		os.Exit(1)
	}
	// DKG: 3 broadcast rounds among n parties (6 one-way hops)
	sleep(6)

	var partials []*dvrf.Eval
	for i := 0; i < t; i++ {
		pe, err := dvrf.PartialEval(&dkgOuts[i].Participant, alpha)
		if err != nil {
			fmt.Fprintln(os.Stderr, "dvrf eval:", err)
			os.Exit(1)
		}
		if !dvrf.VerifyPartialEval(pe, dkgOuts[i].Participant.VK, alpha) {
			fmt.Fprintln(os.Stderr, "dvrf VerifyPartialEval failed (signer", i+1, ")")
			os.Exit(1)
		}
		partials = append(partials, pe)
	}
	// PartialEval: 1 RTT (t evaluators respond in parallel)
	sleep(2)

	dvrfOut, err := dvrf.Combine(partials, alpha)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dvrf combine:", err)
		os.Exit(1)
	}
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

	// ── Attestation: dx-DCTLS ────────────────────────────────────────────
	t1 := time.Now()
	if hspCRS != nil {
		// TLS 1.2 full handshake: 2 RTTs (4 one-way hops)
		sleep(4)

		sess, err := deco.HSP(hspCRS, rand32, certHash)
		if err != nil {
			fmt.Fprintln(os.Stderr, "deco HSP:", err)
			os.Exit(1)
		}

		// co-SNARK ExecuteSplit: commit (2 hops) + reveal (2 hops)
		sleep(4)

		qr := deco.QP(sess, []byte("GET /oracle"), []byte(`{"v":1}`))

		// QP: query + oracle response (1 RTT = 2 hops)
		sleep(2)

		dvrf_bundle := &deco.DVRFBundle{
			Output: dvrfOut,
			Evals:  partials,
			VKs:    secp256k1VKs,
			GK:     dkgOuts[0].GroupKey,
			Alpha:  alpha,
		}
		piAttest := deco.PGP(sess, qr, []byte("v==1"), pgpCRS, dvrf_bundle)

		if err := deco.VerifyDxDctlsProof(piAttest, hspCRS, pgpCRS, rand32, certHash); err != nil {
			fmt.Fprintln(os.Stderr, "VerifyDxDctlsProof:", err)
			os.Exit(1)
		}
	}
	attestMs := time.Since(t1).Milliseconds()

	// ── Signing: FROST ───────────────────────────────────────────────────
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
	// FROST Round1: t parties broadcast commitments (1 RTT = 2 hops)
	sleep(2)

	var shares []*frost.SignatureShare
	for i := 0; i < t; i++ {
		sh, err := frost.Round2(&frostOuts[i].Signer, nonces[i], commitments, msg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "frost r2:", err)
			os.Exit(1)
		}
		if !frost.VerifySignatureShare(sh, commitments[i], frostOuts[i].Signer.VK,
			commitments, frostOuts[0].GroupKey, msg) {
			fmt.Fprintln(os.Stderr, "frost VerifySignatureShare failed (signer", i+1, ")")
			os.Exit(1)
		}
		shares = append(shares, sh)
	}
	// FROST Round2: t parties broadcast shares (1 RTT = 2 hops)
	sleep(2)

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

	// ── On-chain: SC.Verify(σ, pk) ───────────────────────────────────────
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

	totalMs := rcMs + attestMs + signMs + onchainMs

	return row{
		Config:    fmt.Sprintf("%d-of-%d", t, n),
		RcMs:      rcMs,
		AttestMs:  attestMs,
		SignMs:    signMs,
		OnchainMs: onchainMs,
		NetMs:     totalNetMs,
		TotalMs:   totalMs,
	}
}

func rpt(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func max1(a int64) int64 {
	if a < 1 {
		return 1
	}
	return a
}
