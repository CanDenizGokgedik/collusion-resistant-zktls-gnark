package onchain_test

import (
	"testing"

	"github.com/CanDenizGokgedik/tls-gnark/internal/frost"
	"github.com/CanDenizGokgedik/tls-gnark/internal/onchain"
)

var testMsg = [32]byte{0xDE, 0xAD, 0xBE, 0xEF}

func setupFrost(t *testing.T, n, thr int) ([]*frost.DKGOut, []*frost.Nonce, []*frost.Commitment, []*frost.SignatureShare) {
	t.Helper()
	outs, err := frost.RunDKG(n, thr)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}
	nonces := make([]*frost.Nonce, thr)
	commits := make([]*frost.Commitment, thr)
	for i := 0; i < thr; i++ {
		nonces[i], commits[i], _ = frost.Round1(&outs[i].Signer)
	}
	shares := make([]*frost.SignatureShare, thr)
	for i := 0; i < thr; i++ {
		shares[i], _ = frost.Round2(&outs[i].Signer, nonces[i], commits, testMsg)
	}
	return outs, nonces, commits, shares
}

func TestVerifySchnorr_Valid(t *testing.T) {
	outs, _, commits, shares := setupFrost(t, 3, 2)
	sig, err := frost.Aggregate(commits, shares, testMsg)
	if err != nil {
		t.Fatalf("Aggregate: %v", err)
	}

	res, err := onchain.VerifySchnorr(sig, outs[0].GroupKey, testMsg)
	if err != nil {
		t.Fatalf("VerifySchnorr: %v", err)
	}
	if !res.Valid {
		t.Fatal("SC.Verify: rejected a valid signature")
	}
	t.Logf("SC.Verify: OK | gas_estimate=%d | payload=%d bytes",
		res.GasEstimate, len(res.AbiPayload))
}

func TestVerifySchnorr_WrongMessage(t *testing.T) {
	outs, _, commits, shares := setupFrost(t, 3, 2)
	sig, _ := frost.Aggregate(commits, shares, testMsg)

	var wrongMsg [32]byte
	wrongMsg[0] = 0xFF

	res, err := onchain.VerifySchnorr(sig, outs[0].GroupKey, wrongMsg)
	if err != nil {
		t.Fatalf("VerifySchnorr: %v", err)
	}
	if res.Valid {
		t.Fatal("SC.Verify: should not accept a wrong message")
	}
	t.Log("SC.Verify: wrong message correctly rejected")
}

func TestVerifySchnorr_WrongPK(t *testing.T) {
	_, _, commits, shares := setupFrost(t, 3, 2)
	sig, _ := frost.Aggregate(commits, shares, testMsg)

	// Different DKG → different group key
	outs2, err := frost.RunDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG2: %v", err)
	}

	res, err := onchain.VerifySchnorr(sig, outs2[0].GroupKey, testMsg)
	if err != nil {
		t.Fatalf("VerifySchnorr: %v", err)
	}
	if res.Valid {
		t.Fatal("SC.Verify: should not verify with a wrong public key")
	}
	t.Log("SC.Verify: wrong PK correctly rejected")
}

func TestEncodeVerifyCall(t *testing.T) {
	outs, _, commits, shares := setupFrost(t, 3, 2)
	sig, _ := frost.Aggregate(commits, shares, testMsg)

	payload := onchain.EncodeVerifyCall(sig, outs[0].GroupKey, testMsg)
	if len(payload) != 4+6*32 {
		t.Fatalf("ABI payload length wrong: %d", len(payload))
	}
	// Function selector check
	if payload[0] != 0x4a || payload[1] != 0x31 || payload[2] != 0xa8 || payload[3] != 0x20 {
		t.Fatalf("Wrong function selector: %x", payload[:4])
	}
	t.Logf("ABI payload: %d bytes, selector=%x", len(payload), payload[:4])
}

func TestScVerifyGas(t *testing.T) {
	gas := onchain.ScVerifyGas()
	// Paper target: ~4,200 gas (excluding base tx: ~3,272)
	if gas > 4_200 {
		t.Errorf("Gas estimate exceeds paper target: %d > 4200", gas)
	}
	t.Logf("SC.Verify gas (verification logic): %d", gas)
}

func TestEcrecoverParams(t *testing.T) {
	outs, _, commits, shares := setupFrost(t, 3, 2)
	sig, _ := frost.Aggregate(commits, shares, testMsg)

	params := onchain.ComputeEcrecoverParams(sig, outs[0].GroupKey, testMsg)
	if params.HashFake == nil || params.SFake == nil || params.R == nil {
		t.Fatal("ecrecover parametreleri nil")
	}
	if params.V != 27 && params.V != 28 {
		t.Fatalf("v değeri 27 veya 28 olmalı, got %d", params.V)
	}
	t.Logf("ecrecover: v=%d, r=%x…, hashFake=%x…, sFake=%x…",
		params.V, params.R.Bytes()[:4], params.HashFake.Bytes()[:4], params.SFake.Bytes()[:4])
}