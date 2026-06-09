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
	Name   string
	OneWay time.Duration // one-way message latency
}

var netProfiles = map[string]netProfile{
	"lan":  {"LAN", 0},
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
	Config    string  `json:"config"`
	DkgMs     int64   `json:"dkg_ms"`     // DKG setup (one-time per deployment)
	RcSessMs  int64   `json:"rc_sess_ms"` // PartialEval + Combine, no DKG
	HspMs     int64   `json:"hsp_ms"`     // co-SNARK TLS-PRF proof
	PgpMs     int64   `json:"pgp_ms"`     // DECO PGP ZKP proof
	SignMs    int64   `json:"sign_ms"`    // FROST threshold signature
	OnchainMs int64   `json:"onchain_ms"` // on-chain verification
	NetMs     int64   `json:"net_ms"`     // total injected network delay
	TotalMs   int64   `json:"total_ms"`   // DKG + RcSess + Hsp + Pgp + Sign + Onchain
	CommKB    float64 `json:"comm_kb"`    // analytical communication cost (KB)
}

// ── Communication cost model ──────────────────────────────────────────────────
//
// Follows the same element sizes as the companion Rust repo (DVRF-then-Sign):
//
//	DKG (n parties, t threshold) — per-participant average:
//	  Round 1 (Feldman commitments, compressed secp256k1 G1):  2 × 33·t·(n-1) bytes
//	  Round 2 (encrypted shares):                               2 × 80·(n-1)   bytes
//	  Round 3 (verification responses):                         2 × 64·(n-1)   bytes
//
//	DVRF session (t evaluators) — per-participant:
//	  partial_eval = 33 (G1 point) + 96 (proof gamma/delta) = 129 bytes
//	  send 1, receive t-1  → 129·t total
//
//	FROST TSS (t signers) — per-participant:
//	  Round 1 commitments: 66 bytes (2×33)  → 66·t
//	  Round 2 signatures:  32 bytes (scalar) → 32·t + 64 (final sig)
//
//	ZKP proofs (Groth16 on BLS12-381):
//	  co-SNARK (HSP): 192 bytes
//	  PGP ZKP:        192 bytes
//	  Total:          384 bytes
func commCostKB(t, n int) (session float64, withDKG float64) {
	// session-only (no DKG)
	dvrfSession := float64(129 * t)
	frostSession := float64(66*t) + float64(32*t) + 64
	zkpProofs := float64(384)
	sess := dvrfSession + frostSession + zkpProofs

	// DKG per-participant average
	dkgR1 := float64(2 * 33 * t * (n - 1))
	dkgR2 := float64(2 * 80 * (n - 1))
	dkgR3 := float64(2 * 64 * (n - 1))
	dkg := dkgR1 + dkgR2 + dkgR3

	session = sess / 1024
	withDKG = (sess + dkg) / 1024
	return
}

type netResult struct {
	Net     string `json:"net"`
	SetupMs int64  `json:"setup_ms"`
	Rows    []row  `json:"results"`
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
		fmt.Printf("  %-14s %8s %9s %8s %8s %8s %8s %10s %10s\n",
			"Config", "DKG(ms)", "RCSess(ms)", "HSP(ms)", "PGP(ms)", "Sign(ms)", "Net(ms)", "Total(ms)", "Comm(KB)")
		fmt.Println("  " + rpt("─", 98))

		var rows []row
		for _, cfg := range configs {
			r := runConfig(cfg.T, cfg.N, hspCRS, pgpCRS, prof)
			fmt.Printf("  %-14s %8d %10d %8d %8d %8d %8d %10d %10.2f\n",
				fmt.Sprintf("%d-of-%d", cfg.T, cfg.N),
				r.DkgMs, r.RcSessMs, r.HspMs, r.PgpMs, r.SignMs, r.NetMs, r.TotalMs, r.CommKB)
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

	// ── RC: DKG setup ────────────────────────────────────────────────────
	tDkg := time.Now()
	dkgOuts, err := dvrf.RunDKG(n, t)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dvrf DKG:", err)
		os.Exit(1)
	}
	// DKG: 3 broadcast rounds among n parties (6 one-way hops)
	sleep(6)
	dkgMs := time.Since(tDkg).Milliseconds()

	// ── RC: DVRF session (PartialEval + Combine, keys already established) ──
	tSess := time.Now()
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
	rcSessMs := time.Since(tSess).Milliseconds()
	rand32 := dvrfOut.Rand

	// ── Attestation: HSP (co-SNARK TLS-PRF) ──────────────────────────────
	var hspMs, pgpMs int64
	if hspCRS != nil {
		tHsp := time.Now()
		// TLS 1.2 full handshake: 2 RTTs (4 one-way hops)
		sleep(4)

		sess, err := deco.HSP(hspCRS, rand32, certHash)
		if err != nil {
			fmt.Fprintln(os.Stderr, "deco HSP:", err)
			os.Exit(1)
		}

		// co-SNARK ExecuteSplit: commit (2 hops) + reveal (2 hops)
		sleep(4)
		hspMs = time.Since(tHsp).Milliseconds()

		// ── Attestation: PGP (DECO ZKP) ──────────────────────────────────
		tPgp := time.Now()
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

		if err := deco.VerifyDxDctlsProof(piAttest, hspCRS, pgpCRS, rand32, certHash, sess.KMac); err != nil {
			fmt.Fprintln(os.Stderr, "VerifyDxDctlsProof:", err)
			os.Exit(1)
		}
		pgpMs = time.Since(tPgp).Milliseconds()
	}

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

	totalMs := dkgMs + rcSessMs + hspMs + pgpMs + signMs + onchainMs
	sessKB, _ := commCostKB(t, n)

	return row{
		Config:    fmt.Sprintf("%d-of-%d", t, n),
		DkgMs:     dkgMs,
		RcSessMs:  rcSessMs,
		HspMs:     hspMs,
		PgpMs:     pgpMs,
		SignMs:    signMs,
		OnchainMs: onchainMs,
		NetMs:     totalNetMs,
		TotalMs:   totalMs,
		CommKB:    sessKB,
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
