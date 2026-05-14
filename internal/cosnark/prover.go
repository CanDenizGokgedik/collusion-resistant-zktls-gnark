// Package cosnark implements the 2-party collaborative Groth16 prover
// (co-SNARK) in central-coordinator mode using gnark/BLS12-381.
package cosnark

import (
	"bytes"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
)

// Mode selects which circuit is compiled.
type Mode int

const (
	ModeKey Mode = iota // K_MAC split only (~769 R1CS)
	ModePRF             // full TLS-PRF (~1.5 M R1CS)
)

// CRS holds the compiled constraint system and Groth16 keys.
type CRS struct {
	CS   constraint.ConstraintSystem
	PK   groth16.ProvingKey
	VK   groth16.VerifyingKey
	Mode Mode
}

// ProveResult carries the Groth16 proof bytes and timing.
type ProveResult struct {
	ProofBytes []byte
	ProveMs    int64
}

// Setup compiles the circuit and generates Groth16 keys.
func Setup(mode Mode) (*CRS, int64, error) {
	var circ frontend.Circuit
	if mode == ModeKey {
		circ = &circuit.TlsKeyCircuit{}
	} else {
		circ = &circuit.TlsPrfCircuit{}
	}

	t0 := time.Now()
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circ)
	if err != nil {
		return nil, 0, err
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, 0, err
	}
	return &CRS{CS: cs, PK: pk, VK: vk, Mode: mode}, time.Since(t0).Milliseconds(), nil
}

// Prove runs Groth16 proof generation in central mode.
func Prove(
	crs *CRS,
	pShare, vShare, randBinding [32]byte,
	pms, clientRandom, serverRandom [32]byte,
) (*ProveResult, error) {
	// commitment = pack(pShare) + pack(vShare) + pack(rand)  (field addition)
	randFe := circuit.PackBytes32(randBinding)
	commit := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commit.Add(commit, randFe)
	commit.Mod(commit, ecc.BLS12_381.ScalarField())

	var assignment frontend.Circuit
	if crs.Mode == ModeKey {
		assignment = &circuit.TlsKeyCircuit{
			PShare:      circuit.PackBytes32(pShare),
			VShare:      circuit.PackBytes32(vShare),
			Commitment:  commit,
			RandBinding: randFe,
		}
	} else {
		a := circuit.NewTlsPrfAssignment(pms, clientRandom, serverRandom, pShare, vShare, randBinding)
		// Override commitment with correct value.
		a.Commitment = commit
		a.RandBinding = randFe
		assignment = a
	}

	wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}

	t0 := time.Now()
	proof, err := groth16.Prove(crs.CS, crs.PK, wit)
	if err != nil {
		return nil, err
	}
	proveMs := time.Since(t0).Milliseconds()

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, err
	}
	return &ProveResult{ProofBytes: buf.Bytes(), ProveMs: proveMs}, nil
}

// Verify checks a Groth16 proof given the public witness assignment.
func Verify(crs *CRS, proofBytes []byte, pubAssignment frontend.Circuit) error {
	proof := groth16.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return err
	}
	wit, err := frontend.NewWitness(pubAssignment, ecc.BLS12_381.ScalarField(),
		frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof, crs.VK, wit)
}

// bytesToU8 converts a []byte to []uints.U8 constant values.
func bytesToU8(b []byte) []uints.U8 {
	out := make([]uints.U8, len(b))
	for i, v := range b {
		out[i] = uints.U8{Val: frontend.Variable(int(v))}
	}
	return out
}

var _ = bytesToU8