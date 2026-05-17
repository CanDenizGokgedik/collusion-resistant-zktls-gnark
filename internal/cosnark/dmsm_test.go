package cosnark_test

import (
	"testing"

	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
)

// TestDistributedMSM_BasicProof: a proof produced with distributed MSM
// must be verifiable by VerifyMpc.
func TestDistributedMSM_BasicProof(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}

	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xAA
	pShare[1] = 0xBB
	vShare[0] = 0x11
	vShare[1] = 0x22

	res, err := cosnark.ExecuteDistributedMSM(crsMode1, pShare, vShare, rand32)
	if err != nil {
		t.Fatalf("ExecuteDistributedMSM: %v", err)
	}
	if len(res.ProofBytes) == 0 {
		t.Fatal("distributed MSM: proof bytes are empty")
	}

	// Verify using public inputs (pShare+vShare+rand commitment).
	if err := cosnark.VerifyMpc(crsMode1, res, pShare, vShare, rand32); err != nil {
		t.Fatalf("VerifyMpc (distributed MSM): %v", err)
	}
	t.Logf("Distributed MSM: prove=%dms, proof=%d bytes", res.ProveMs, len(res.ProofBytes))
}

// TestDistributedMSM_WrongShare: verification with a wrong share must fail.
func TestDistributedMSM_WrongShare(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}

	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xCA
	vShare[0] = 0xFE

	res, err := cosnark.ExecuteDistributedMSM(crsMode1, pShare, vShare, rand32)
	if err != nil {
		t.Fatalf("ExecuteDistributedMSM: %v", err)
	}

	// Verification with a different pShare produces a wrong public input → must fail.
	var wrongShare [32]byte
	wrongShare[0] = 0xFF
	if err := cosnark.VerifyMpc(crsMode1, res, wrongShare, vShare, rand32); err == nil {
		t.Fatal("Distributed MSM: verification with a wrong share should not pass")
	}
	t.Log("Distributed MSM: wrong share correctly rejected")
}

// TestDistributedMSM_vs_Central: both distributed and central proofs must be
// verifiable with the same public inputs (proof bytes may differ —
// blinding is random).
func TestDistributedMSM_vs_Central(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}

	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0x42
	vShare[0] = 0x24

	var pms, cr, sr [32]byte

	// Central proof.
	resC, err := cosnark.Execute(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("Execute (central): %v", err)
	}

	// Distributed MSM proof.
	resD, err := cosnark.ExecuteDistributedMSM(crsMode1, pShare, vShare, rand32)
	if err != nil {
		t.Fatalf("ExecuteDistributedMSM: %v", err)
	}

	// Both must be verifiable.
	if err := cosnark.VerifyMpc(crsMode1, resC, pShare, vShare, rand32); err != nil {
		t.Fatalf("central verify: %v", err)
	}
	if err := cosnark.VerifyMpc(crsMode1, resD, pShare, vShare, rand32); err != nil {
		t.Fatalf("distributed MSM verify: %v", err)
	}

	t.Logf("Central: %dms | Distributed MSM: %dms (commit=%dms)",
		resC.ProveMs, resD.ProveMs, resD.CommitMs)
}