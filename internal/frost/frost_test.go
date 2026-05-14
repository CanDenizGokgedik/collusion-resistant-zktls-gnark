package frost_test

import (
	"testing"

	"github.com/CanDenizGokgedik/tls-gnark/internal/frost"
)

var message = [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

func TestDKG_Structure(t *testing.T) {
	outs, err := frost.RunDKG(5, 3)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	if len(outs) != 5 {
		t.Fatalf("expected 5 signers, got %d", len(outs))
	}
	for i, o := range outs {
		if o.Signer.Index != i+1 {
			t.Errorf("signer[%d].Index = %d", i, o.Signer.Index)
		}
	}
}

func TestFullProtocol_2of3(t *testing.T) {
	runFrost(t, 2, 3)
}

func TestFullProtocol_3of5(t *testing.T) {
	runFrost(t, 3, 5)
}

func TestFullProtocol_5of9(t *testing.T) {
	runFrost(t, 5, 9)
}

func runFrost(t *testing.T, thr, n int) {
	t.Helper()
	outs, err := frost.RunDKG(n, thr)
	if err != nil {
		t.Fatalf("DKG(%d,%d): %v", thr, n, err)
	}

	// Round 1: all t signers generate nonces.
	nonces := make([]*frost.Nonce, thr)
	commitments := make([]*frost.Commitment, thr)
	for i := 0; i < thr; i++ {
		no, cm, err := frost.Round1(&outs[i].Signer)
		if err != nil {
			t.Fatalf("Round1[%d]: %v", i, err)
		}
		nonces[i] = no
		commitments[i] = cm
	}

	// Round 2: each signer produces a share.
	shares := make([]*frost.SignatureShare, thr)
	for i := 0; i < thr; i++ {
		sh, err := frost.Round2(&outs[i].Signer, nonces[i], commitments, message)
		if err != nil {
			t.Fatalf("Round2[%d]: %v", i, err)
		}
		shares[i] = sh
	}

	// Aggregate.
	sig, err := frost.Aggregate(commitments, shares, message)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	// Verify.
	if !frost.Verify(sig, outs[0].GroupKey, message) {
		t.Fatalf("Verify failed for %d-of-%d", thr, n)
	}
	t.Logf("%d-of-%d: OK", thr, n)
}

func TestVerify_WrongMessage(t *testing.T) {
	outs, _ := frost.RunDKG(3, 2)
	nonces := make([]*frost.Nonce, 2)
	commitments := make([]*frost.Commitment, 2)
	for i := 0; i < 2; i++ {
		nonces[i], commitments[i], _ = frost.Round1(&outs[i].Signer)
	}
	shares := make([]*frost.SignatureShare, 2)
	for i := 0; i < 2; i++ {
		shares[i], _ = frost.Round2(&outs[i].Signer, nonces[i], commitments, message)
	}
	sig, _ := frost.Aggregate(commitments, shares, message)

	// Verify with a different message — must fail.
	var other [32]byte
	other[0] = 0xFF
	if frost.Verify(sig, outs[0].GroupKey, other) {
		t.Fatal("Verify should fail for wrong message")
	}
}

func TestDKG_ThresholdGTN(t *testing.T) {
	_, err := frost.RunDKG(3, 5)
	if err == nil {
		t.Fatal("expected error when threshold > n")
	}
}

func BenchmarkFrost_10of19(b *testing.B) {
	const thr, n = 10, 19
	outs, _ := frost.RunDKG(n, thr)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		nonces := make([]*frost.Nonce, thr)
		commitments := make([]*frost.Commitment, thr)
		for j := 0; j < thr; j++ {
			nonces[j], commitments[j], _ = frost.Round1(&outs[j].Signer)
		}
		shares := make([]*frost.SignatureShare, thr)
		for j := 0; j < thr; j++ {
			shares[j], _ = frost.Round2(&outs[j].Signer, nonces[j], commitments, message)
		}
		sig, _ := frost.Aggregate(commitments, shares, message)
		if !frost.Verify(sig, outs[0].GroupKey, message) {
			b.Fatal("verify failed")
		}
	}
}