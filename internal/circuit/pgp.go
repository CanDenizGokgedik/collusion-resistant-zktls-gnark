// pgp.go — Groth16 circuit definition for the PGP phase.
//
// PgpCircuit corresponds to the ZKP.Prove(x, w) function from the paper (§V PGP).
//
// Public input  (x): KMacHash  = MiMC(KMacP, KMacV)
// Private witness (w): KMacP, KMacV  (prover's K_MAC shares)
//
// Proof statement: "I know the K_MAC shares whose MiMC hash equals the
// public KMacHash."
//
// MiMC was chosen because, unlike SHA-256, it maps naturally to R1CS
// and can be computed with ~200 constraints.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// PgpCircuit proves knowledge of the K_MAC shares.
//
// Public input:
//
//	KMacHash = MiMC(KMacP || KMacV)
//
// Private witness:
//
//	KMacP — prover's K_MAC share (32 bytes packed into a field element)
//	KMacV — verifier's K_MAC share (32 bytes packed into a field element)
type PgpCircuit struct {
	// Private witnesses.
	KMacP frontend.Variable `gnark:",secret"`
	KMacV frontend.Variable `gnark:",secret"`

	// Public input: MiMC(KMacP || KMacV).
	KMacHash frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
func (c *PgpCircuit) Define(api frontend.API) error {
	// MiMC hash constraint: MiMC(KMacP || KMacV) == KMacHash
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.KMacP)
	h.Write(c.KMacV)
	computed := h.Sum()
	api.AssertIsEqual(c.KMacHash, computed)
	return nil
}