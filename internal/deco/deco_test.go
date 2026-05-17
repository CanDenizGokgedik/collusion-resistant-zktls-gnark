package deco_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"

	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
	"github.com/CanDenizGokgedik/tls-gnark/internal/deco"
	"github.com/CanDenizGokgedik/tls-gnark/internal/dvrf"
)

var (
	decosCRS *cosnark.CRS
	decoErr  error
	pgpCRS   *deco.PgpCRS
	pgpErr   error
)

func init() {
	decosCRS, _, decoErr = cosnark.Setup(cosnark.ModeKey)
	if decoErr == nil {
		pgpCRS, pgpErr = deco.SetupPGP()
	}
}

func TestHSP_RunsAndProduces_PiHSP(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("example.com", 0x42)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	if len(sess.PiHSP.ProofBytes) == 0 {
		t.Fatal("π_HSP proof bytes are empty")
	}
	if sess.PiHSP.Rand != mock.Nonce {
		t.Fatal("π_HSP.Rand mismatch")
	}
	if sess.PiHSP.KMacCommit == [32]byte{} {
		t.Fatal("π_HSP.KMacCommit is zero")
	}
	if len(sess.PiHSP.CommitFe) == 0 {
		t.Fatal("π_HSP.CommitFe is empty — Groth16 public input missing")
	}
	if len(sess.PMS) == 0 || sess.PMS == [32]byte{} {
		t.Fatal("PMS is zero — ECDH key exchange failed")
	}
	t.Logf("HSP: sess=%x…, prove=%dms, proof=%d bytes, PMS=%x…",
		sess.SessionID[:4], sess.PiHSP.ProveMs, len(sess.PiHSP.ProofBytes), sess.PMS[:4])
}

func TestVerifyHSP_Groth16(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("example.com", 0x01)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}

	// Groth16 verification must pass with correct parameters.
	if err := deco.VerifyHSP(decosCRS, sess.PiHSP, mock.Nonce, mock.CertHash); err != nil {
		t.Fatalf("VerifyHSP failed: %v", err)
	}
	t.Log("VerifyHSP (Groth16): OK")
}

func TestVerifyHSP_WrongRand_Fails(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("example.com", 0x02)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}

	var wrongRand [32]byte
	wrongRand[0] = 0xFF
	if err := deco.VerifyHSP(decosCRS, sess.PiHSP, wrongRand, mock.CertHash); err == nil {
		t.Fatal("VerifyHSP should not pass with a wrong rand")
	}
	t.Log("VerifyHSP: wrong rand correctly rejected")
}

func TestVerifyHSP_WrongCertHash_Fails(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("example.com", 0x03)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}

	var wrongCert [32]byte
	wrongCert[0] = 0xAB
	if err := deco.VerifyHSP(decosCRS, sess.PiHSP, mock.Nonce, wrongCert); err == nil {
		t.Fatal("VerifyHSP should not pass with a wrong certHash")
	}
	t.Log("VerifyHSP: wrong certHash correctly rejected")
}

func TestQP_CommitmentDeterministic(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("bank.com", 0x10)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	query := []byte("GET /balance HTTP/1.1\r\n")
	response := []byte(`{"balance":9999}`)

	qr1 := deco.QP(sess, query, response)
	qr2 := deco.QP(sess, query, response)
	if qr1.TranscriptCommitment != qr2.TranscriptCommitment {
		t.Fatal("QP is not deterministic")
	}
	if qr1.SessionID != sess.SessionID {
		t.Fatal("QP session ID mismatch")
	}
}

func TestQP_VerifyTranscript(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("api.com", 0x20)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	q := []byte("GET /data")
	r := []byte(`{"ok":true}`)

	qr := deco.QP(sess, q, r)
	if !deco.VerifyTranscript(qr, sess.KMac, q, r) {
		t.Fatal("VerifyTranscript failed")
	}
	if deco.VerifyTranscript(qr, sess.KMac, q, []byte("tampered")) {
		t.Fatal("VerifyTranscript should reject a tampered response")
	}
}

func TestPGP_FullPipeline(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("oracle.com", 0x55)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	q := []byte("GET /price?asset=ETH")
	r := []byte(`{"price":"3200"}`)
	statement := []byte("price>3000")

	qr := deco.QP(sess, q, r)
	proof := deco.PGP(sess, qr, statement, pgpCRS, nil)

	if len(proof.PiHSP.ProofBytes) == 0 {
		t.Fatal("PGP: π_HSP proof is empty")
	}
	if proof.ProofDigest == [32]byte{} {
		t.Fatal("PGP: proof digest is zero")
	}
	if proof.CrossBinding == [32]byte{} {
		t.Fatal("PGP: cross binding is zero")
	}
	if pgpCRS != nil && len(proof.PgpProofBytes) == 0 {
		t.Fatal("PGP: π_PGP proof is empty (PgpCRS present but proof generation failed)")
	}
	t.Logf("PGP: digest=%x…, πPGP=%d bytes", proof.ProofDigest[:8], len(proof.PgpProofBytes))
}

func TestPGP_ZKP_Verify(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	if pgpErr != nil {
		t.Skipf("PGP CRS setup failed: %v", pgpErr)
	}
	mock := deco.NewMock("zkp-test.example", 0x77)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	qr := deco.QP(sess, []byte("Q"), []byte("R"))
	proof := deco.PGP(sess, qr, []byte("stmt"), pgpCRS, nil)

	if len(proof.PgpProofBytes) == 0 {
		t.Fatal("π_PGP üretilemedi")
	}

	// VerifyDxDctlsProof — Condition 1 + Condition 2 (Condition 3 skipped without DVRF bundle).
	if err := deco.VerifyDxDctlsProof(proof, decosCRS, pgpCRS, mock.Nonce, mock.CertHash); err != nil {
		t.Fatalf("VerifyDxDctlsProof failed: %v", err)
	}
	t.Log("VerifyDxDctlsProof (Condition 1 + 2): OK")
}

func TestFullDxDctls_HSP_QP_PGP(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("chainlink-node.example", 0x99)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	t.Logf("HSP done: %dms, PMS=%x…", sess.HSPMs, sess.PMS[:4])

	qr := deco.QP(sess, []byte("query"), []byte("response"))
	t.Logf("QP done: commitment=%x…", qr.TranscriptCommitment[:8])

	proof := deco.PGP(sess, qr, []byte("b=true"), pgpCRS, nil)
	t.Logf("PGP done: digest=%x…, πPGP=%d bytes", proof.ProofDigest[:8], len(proof.PgpProofBytes))

	// Auxiliary verifier checks: Groth16 π_HSP verification.
	if err := deco.VerifyHSP(decosCRS, proof.PiHSP, mock.Nonce, mock.CertHash); err != nil {
		t.Fatalf("auxiliary verifier: VerifyHSP failed: %v", err)
	}
	t.Log("VerifyHSP (Groth16): OK")

	// Transcript integrity.
	if !deco.VerifyTranscript(qr, sess.KMac, []byte("query"), []byte("response")) {
		t.Fatal("auxiliary verifier: VerifyTranscript failed")
	}
	t.Log("Full dx-DCTLS pipeline: OK")
}

func TestVerifyDxDctlsProof_WithDVRF(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	if pgpErr != nil {
		t.Skipf("PGP CRS setup failed: %v", pgpErr)
	}

	// ── DVRF: DKG + PartialEval + Combine ────────────────────────────────────
	dkgOuts, err := dvrf.RunDKG(3, 2)
	if err != nil {
		t.Fatalf("DVRF DKG: %v", err)
	}

	mock := deco.NewMock("dvrf-full.example", 0xAB)
	alpha := mock.Nonce

	// t=2 participant evaluations are sufficient.
	threshEvals := make([]*dvrf.Eval, 2)
	threshVKs := make([]secp256k1.G1Affine, 2)
	for i := 0; i < 2; i++ {
		ev, eerr := dvrf.PartialEval(&dkgOuts[i].Participant, alpha)
		if eerr != nil {
			t.Fatalf("PartialEval %d: %v", i, eerr)
		}
		threshEvals[i] = ev
		threshVKs[i] = dkgOuts[i].Participant.VK
	}

	vrfOut, cerr := dvrf.Combine(threshEvals, alpha)
	if cerr != nil {
		t.Fatalf("DVRF Combine: %v", cerr)
	}

	dvrf_bundle := &deco.DVRFBundle{
		Output: vrfOut,
		Evals:  threshEvals,
		VKs:    threshVKs,
		GK:     dkgOuts[0].GroupKey,
		Alpha:  alpha,
	}

	// ── HSP + QP + PGP pipeline ───────────────────────────────────────────────
	sess, err := deco.HSP(decosCRS, vrfOut.Rand, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	qr := deco.QP(sess, []byte("GET /data"), []byte(`{"v":1}`))
	proof := deco.PGP(sess, qr, []byte("v==1"), pgpCRS, dvrf_bundle)

	// ── VerifyDxDctlsProof: all three conditions ─────────────────────────────
	if err := deco.VerifyDxDctlsProof(proof, decosCRS, pgpCRS, vrfOut.Rand, mock.CertHash); err != nil {
		t.Fatalf("VerifyDxDctlsProof (all conditions): %v", err)
	}
	t.Log("VerifyDxDctlsProof (Condition 1 + 2 + 3 — including DVRF): OK")
}