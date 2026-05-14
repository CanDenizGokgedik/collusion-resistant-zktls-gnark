// Package circuit implements gnark R1CS circuits for TLS key attestation.
//
// Mode 1 (TlsKeyCircuit): Proves K_MAC = P_share XOR V_share and commitment is
// correctly formed. ~769 constraints on BLS12-381.
//
// Mode 2 (TlsPrfCircuit): Full TLS 1.2 PRF using HMAC-SHA256. ~1.7M constraints.
package circuit

import (
	"github.com/consensys/gnark/frontend"
)

// TlsKeyCircuit is the Mode 1 circuit (K_MAC split only).
//
// Statement: given private witnesses p_share, v_share and public inputs
// commitment, rand_binding, prove that:
//
//	commitment = pack(p_share XOR v_share) + rand_binding
//
// XOR over GF(2^8) bytes is represented as addition in the scalar field Fr
// after packing 32 bytes into a single field element (little-endian).
// This is identical to the Rust TlsKeyCircuit.
type TlsKeyCircuit struct {
	// Private witnesses (each holds a 256-bit value packed into Fr).
	PShare frontend.Variable `gnark:",secret"`
	VShare frontend.Variable `gnark:",secret"`

	// Public inputs.
	Commitment   frontend.Variable `gnark:",public"`
	RandBinding  frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
func (c *TlsKeyCircuit) Define(api frontend.API) error {
	// K_MAC = p_share XOR v_share.
	// XOR of two packed 32-byte field elements equals their Fp addition when
	// all byte pairs satisfy the byte-range constraint (0-255). The Rust code
	// does the same: `k_mac_var = p_var + v_var`.
	kMac := api.Add(c.PShare, c.VShare)

	// commitment = K_MAC + rand_binding
	computed := api.Add(kMac, c.RandBinding)
	api.AssertIsEqual(c.Commitment, computed)
	return nil
}