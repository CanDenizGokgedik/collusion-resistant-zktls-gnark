package cosnark_test

import (
	"testing"

	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
)

// shared CRS for all Mode 1 tests (setup once, reuse).
var (
	crsMode1 *cosnark.CRS
	crsErr   error
)

func init() {
	crsMode1, _, crsErr = cosnark.Setup(cosnark.ModeKey)
}

func TestSetup_ModeKey(t *testing.T) {
	if crsErr != nil {
		t.Fatalf("Setup(ModeKey): %v", crsErr)
	}
	if crsMode1 == nil {
		t.Fatal("CRS is nil")
	}
}

func TestExecute_Central(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xAA
	vShare[0] = 0x55

	var pms, cr, sr [32]byte
	res, err := cosnark.Execute(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(res.ProofBytes) == 0 {
		t.Fatal("proof bytes empty")
	}
	t.Logf("Central mode: prove=%dms, proof=%d bytes", res.ProveMs, len(res.ProofBytes))
}

func TestExecuteSplit_TwoParty(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xDE
	pShare[1] = 0xAD
	vShare[0] = 0xBE
	vShare[1] = 0xEF

	var pms, cr, sr [32]byte
	res, err := cosnark.ExecuteSplit(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("ExecuteSplit: %v", err)
	}
	if len(res.ProofBytes) == 0 {
		t.Fatal("proof bytes empty")
	}
	t.Logf("Split mode: prove=%dms, commit=%dms, proof=%d bytes",
		res.ProveMs, res.CommitMs, len(res.ProofBytes))
}

func TestVerifyMpc_Valid(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0x11
	vShare[0] = 0x22

	var pms, cr, sr [32]byte
	res, err := cosnark.ExecuteSplit(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("ExecuteSplit: %v", err)
	}
	if err := cosnark.VerifyMpc(crsMode1, res, pShare, vShare, rand32); err != nil {
		t.Fatalf("VerifyMpc: %v", err)
	}
	t.Log("VerifyMpc: OK")
}

func TestVerifyMpc_WrongShare(t *testing.T) {
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xAA

	var pms, cr, sr [32]byte
	res, err := cosnark.ExecuteSplit(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("ExecuteSplit: %v", err)
	}

	// Tamper with pShare before verification.
	var badShare [32]byte
	badShare[0] = 0xFF
	if err := cosnark.VerifyMpc(crsMode1, res, badShare, vShare, rand32); err == nil {
		t.Fatal("expected VerifyMpc to fail with wrong share")
	}
	t.Log("VerifyMpc correctly rejected tampered share")
}

func TestCentral_vs_Split_SameProof(t *testing.T) {
	// Both modes should produce verifiable proofs for the same inputs.
	if crsErr != nil {
		t.Skip("CRS setup failed:", crsErr)
	}
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0x42
	vShare[0] = 0x24

	var pms, cr, sr [32]byte

	resC, err := cosnark.Execute(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	resS, err := cosnark.ExecuteSplit(crsMode1, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		t.Fatalf("ExecuteSplit: %v", err)
	}

	// Both should verify.
	if err := cosnark.VerifyMpc(crsMode1, resC, pShare, vShare, rand32); err != nil {
		t.Fatalf("central verify: %v", err)
	}
	if err := cosnark.VerifyMpc(crsMode1, resS, pShare, vShare, rand32); err != nil {
		t.Fatalf("split verify: %v", err)
	}
	t.Logf("Central %dms  |  Split %dms (comm=%dms)",
		resC.ProveMs, resS.ProveMs, resS.CommitMs)
}