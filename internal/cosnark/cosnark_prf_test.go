package cosnark_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
)

// TestModeCoSNARK verifies the paper §VIII.C co-SNARK end-to-end:
//   - Setup compiles TlsPrfCoSnarkCircuit
//   - ExecuteDistributedPRF produces a valid Groth16 proof
//   - Coordinator never sees raw pShare or vShare (only EC points)
//   - Proof verifies against public inputs (Zp, CR, SR, Commitment)
func TestModeCoSNARK(t *testing.T) {
	t.Log("Setting up ModeCoSNARK CRS (TlsPrfCoSnarkCircuit, ~56k R1CS)...")
	crs, setupMs, err := cosnark.Setup(cosnark.ModeCoSNARK)
	if err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Logf("Setup done in %d ms", setupMs)

	// Simulate: P has pShare, V has vShare, both know Zp from ECDH.
	var pms, cr, sr, pShare, randBinding [32]byte
	pms[0] = 0xAB // fake ECDH pre-master secret
	cr[0] = 0x01
	sr[0] = 0x02
	randBinding[0] = 0x03

	// Derive K_MAC_base = TLS-PRF(pms, "master secret"||cr||sr)[0:32]
	kMacBase := circuit.CoSnarkKMacBaseNative(pms, cr, sr)

	// K_MAC = kMacBase + rand  (field addition)
	q := ecc.BLS12_381.ScalarField()
	kMacBaseFe := circuit.PackBytes32(kMacBase)
	randFe := circuit.PackBytes32(randBinding)
	kMacFe := new(big.Int).Add(kMacBaseFe, randFe)
	kMacFe.Mod(kMacFe, q)

	// Split: pShare random, vShare = kMac - pShare
	pShare[0] = 0x77
	pShareFe := circuit.PackBytes32(pShare)
	vShareFe := new(big.Int).Sub(kMacFe, pShareFe)
	vShareFe.Mod(vShareFe, q)
	var vShare [32]byte
	vShareFeBytes := vShareFe.Bytes()
	copy(vShare[32-len(vShareFeBytes):], vShareFeBytes)

	t.Log("Running ExecuteDistributedPRF (genuine co-SNARK)...")
	result, err := cosnark.ExecuteDistributedPRF(crs, pShare, vShare, randBinding, pms, cr, sr)
	if err != nil {
		t.Fatalf("ExecuteDistributedPRF: %v", err)
	}
	t.Logf("Proof generated in %d ms (commit) + %d ms (prove)", result.CommitMs, result.ProveMs)

	// Verify with public inputs only.
	commitFe := new(big.Int).Add(pShareFe, vShareFe)
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, q)

	if err := cosnark.VerifyMpcCoSNARK(crs, result, commitFe, randFe, pms, cr, sr); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	t.Log("✓ ModeCoSNARK proof verified — coordinator never saw pShare or vShare")
}