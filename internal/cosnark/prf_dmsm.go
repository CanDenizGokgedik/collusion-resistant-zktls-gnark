// prf_dmsm.go — ModeCoSNARK: paper §VIII.C co-SNARK for TlsPrfCoSnarkCircuit.
//
// Implements exactly:
//
//	co-SNARK.Execute({pShare, vShare}, Zp) → (K_MAC, πHSP)
//
// Security guarantee (from the circuit design, not MSM distribution):
//   - Zp, CR, SR are PUBLIC → aux verifiers can independently check πHSP
//   - Circuit enforces TLS-PRF(Zp) = pShare + vShare
//   - Valid proof can only be generated if both shares are correct
//   - Constraint count: ~56k R1CS (vs 1.5M for ModePRF)
//
// Distributed MSM limitation:
//   gnark's SHA2 gadget uses logderivlookup tables that produce Pedersen
//   commitment terms in the proof (Commitments + CommitmentPok fields).
//   These are handled transparently by groth16.Prove but cannot be
//   reproduced by a manual EC-only MSM construction without access to
//   gnark's internal witness solver. True distributed MSM for this
//   circuit requires gnark internal API access (future work).
//   The verifiability guarantee (Zp public, aux-verifier checkable) is
//   fully preserved.
package cosnark

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
)

// ExecuteDistributedPRF produces a verifiable Groth16 proof for
// TlsPrfCoSnarkCircuit (ModeCoSNARK).
//
// The proof is verifiable by any aux verifier holding (Zp, CR, SR, Commitment)
// without participating in the TLS session.
//
// Protocol alignment with paper §VIII.C:
//   - TlsPrfCoSnarkCircuit has Zp/CR/SR as PUBLIC inputs.
//   - Only PShare and VShare are private — the circuit enforces their sum
//     equals the TLS-PRF output, binding K_MAC to the real session.
//   - πHSP is exportable: ZKP.Verify(πHSP, rand) works for any Vi.
func ExecuteDistributedPRF(
	crs *CRS,
	pShare, vShare, randBinding [32]byte,
	pms, cr, sr [32]byte,
) (*MpcResult, error) {
	if crs.Mode != ModeCoSNARK {
		return nil, fmt.Errorf("ExecuteDistributedPRF: wrong mode %v (need ModeCoSNARK)", crs.Mode)
	}

	q := ecc.BLS12_381.ScalarField()
	pShareFe := circuit.PackBytes32(pShare)
	vShareFe := circuit.PackBytes32(vShare)
	randFe := circuit.PackBytes32(randBinding)

	commitFe := new(big.Int).Add(pShareFe, vShareFe)
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, q)

	// Build full witness.
	assignment := circuit.NewTlsPrfCoSnarkAssignment(pms, cr, sr, pShare, vShare, randBinding)
	assignment.Commitment = commitFe

	wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("ExecuteDistributedPRF: build witness: %w", err)
	}

	t0 := time.Now()
	proof, err := groth16.Prove(crs.CS, crs.PK, wit)
	if err != nil {
		return nil, fmt.Errorf("ExecuteDistributedPRF: groth16.Prove: %w", err)
	}
	proveMs := time.Since(t0).Milliseconds()

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("ExecuteDistributedPRF: serialize: %w", err)
	}

	return &MpcResult{
		ProofBytes: buf.Bytes(),
		ProveMs:    proveMs,
	}, nil
}

// VerifyMpcCoSNARK verifies a ModeCoSNARK proof against public inputs.
// Can be called by any aux verifier holding Zp, CR, SR, and the commitment.
func VerifyMpcCoSNARK(
	crs *CRS,
	result *MpcResult,
	commitFe, randFe *big.Int,
	pms, cr, sr [32]byte,
) error {
	pubAssignment := &circuit.TlsPrfCoSnarkCircuit{
		Commitment:  commitFe,
		RandBinding: randFe,
	}
	for i, b := range pms {
		pubAssignment.Zp[i].Val = frontend.Variable(int(b))
	}
	for i, b := range cr {
		pubAssignment.CR[i].Val = frontend.Variable(int(b))
	}
	for i, b := range sr {
		pubAssignment.SR[i].Val = frontend.Variable(int(b))
	}
	return Verify(crs, result.ProofBytes, pubAssignment)
}