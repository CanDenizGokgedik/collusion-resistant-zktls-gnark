package deco_test

import (
	"testing"

	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
	"github.com/CanDenizGokgedik/tls-gnark/internal/deco"
)

var (
	decosCRS *cosnark.CRS
	decoErr  error
)

func init() {
	decosCRS, _, decoErr = cosnark.Setup(cosnark.ModeKey)
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
		t.Fatal("π_HSP proof bytes empty")
	}
	if sess.PiHSP.Rand != mock.Nonce {
		t.Fatal("π_HSP.Rand mismatch")
	}
	t.Logf("HSP: sess=%x…, prove=%dms, proof=%d bytes",
		sess.SessionID[:4], sess.PiHSP.ProveMs, len(sess.PiHSP.ProofBytes))
}

func TestVerifyHSP(t *testing.T) {
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("example.com", 0x01)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	if !deco.VerifyHSP(sess.PiHSP, mock.Nonce) {
		t.Fatal("VerifyHSP failed")
	}
	// Wrong rand should fail.
	var wrongRand [32]byte
	wrongRand[0] = 0xFF
	if deco.VerifyHSP(sess.PiHSP, wrongRand) {
		t.Fatal("VerifyHSP should fail for wrong rand")
	}
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
		t.Fatal("QP not deterministic")
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
	// Tampered response should fail.
	if deco.VerifyTranscript(qr, sess.KMac, q, []byte("tampered")) {
		t.Fatal("VerifyTranscript should fail for tampered response")
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
	proof := deco.PGP(sess, qr, statement)

	if len(proof.PiHSP.ProofBytes) == 0 {
		t.Fatal("PGP: π_HSP proof empty")
	}
	if proof.ProofDigest == [32]byte{} {
		t.Fatal("PGP: proof digest all zeros")
	}
	if proof.CrossBinding == [32]byte{} {
		t.Fatal("PGP: cross binding all zeros")
	}
	t.Logf("PGP: digest=%x…", proof.ProofDigest[:8])
}

func TestFullDxDctls_HSP_QP_PGP(t *testing.T) {
	// End-to-end: run full dx-DCTLS protocol once.
	if decoErr != nil {
		t.Skip("CRS setup failed:", decoErr)
	}
	mock := deco.NewMock("chainlink-node.example", 0x99)
	sess, err := deco.HSP(decosCRS, mock.Nonce, mock.CertHash)
	if err != nil {
		t.Fatalf("HSP: %v", err)
	}
	t.Logf("HSP done: %dms", sess.HSPMs)

	qr := deco.QP(sess, []byte("query"), []byte("response"))
	t.Logf("QP done: commitment=%x…", qr.TranscriptCommitment[:8])

	proof := deco.PGP(sess, qr, []byte("b=true"))
	t.Logf("PGP done: digest=%x…", proof.ProofDigest[:8])

	// Auxiliary verifier checks: π_HSP bound to rand ✓
	if !deco.VerifyHSP(proof.PiHSP, mock.Nonce) {
		t.Fatal("auxiliary verifier: VerifyHSP failed")
	}
	// Transcript integrity ✓
	if !deco.VerifyTranscript(qr, sess.KMac, []byte("query"), []byte("response")) {
		t.Fatal("auxiliary verifier: VerifyTranscript failed")
	}
	t.Log("Full dx-DCTLS pipeline: OK")
}