// pgp.go — Groth16 circuit definition for the PGP phase.
//
// PgpCircuit corresponds to the ZKP.Prove(x, w) function from the paper (§V PGP).
//
// Statement: "I know a K_MAC key whose HMAC-SHA256 over the transcript Q||R
//             equals the published TranscriptCommitment."
//
// Public inputs (x):
//   TCHi — bytes[0:16] of HMAC-SHA256(K_MAC, Q||R), packed big-endian into Fr
//   TCLo — bytes[16:32] of HMAC-SHA256(K_MAC, Q||R), packed big-endian into Fr
//
// Private witnesses (w):
//   IKey — K_MAC XOR ipad (64 bytes, zero-padded)
//   OKey — K_MAC XOR opad (64 bytes, zero-padded)
//   Msg  — Q||R zero-padded to PgpMsgLen bytes
//
// Constraint count:
//   inner SHA256: ceil((64 + PgpMsgLen) / 64) compressions
//   outer SHA256: ceil((64 + 32) / 64) = 2 compressions
//   For PgpMsgLen=512: inner=9+2=11 compressions × ~27 000 ≈ 297 K R1CS
//
// Split TC into two 128-bit halves because 32 bytes = 256 bits exceeds
// BLS12-381 Fr capacity (~254 bits).
package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// PgpMsgLen is the fixed padded message length (Q||R) used in PgpCircuit.
// Changing this requires regenerating the CRS.
const PgpMsgLen = 512

// PgpCircuit proves HMAC-SHA256(K_MAC, Q||R) == TranscriptCommitment.
type PgpCircuit struct {
	// Secret witnesses — HMAC key material (K_MAC XOR ipad/opad, zero-padded to 64 B)
	IKey [64]uints.U8 `gnark:",secret"`
	OKey [64]uints.U8 `gnark:",secret"`

	// Secret witness — query || response, zero-padded to PgpMsgLen bytes
	Msg [PgpMsgLen]uints.U8 `gnark:",secret"`

	// Public inputs — TranscriptCommitment split into two 128-bit halves
	// (avoids BLS12-381 Fr overflow for 256-bit HMAC output)
	TCHi frontend.Variable `gnark:",public"` // bytes[0:16]  packed big-endian
	TCLo frontend.Variable `gnark:",public"` // bytes[16:32] packed big-endian
}

// Define implements frontend.Circuit.
func (c *PgpCircuit) Define(api frontend.API) error {
	// Compute HMAC-SHA256(K_MAC, Msg) in-circuit.
	// runHMAC is defined in tls_prf.go (same package).
	hmacOut, err := runHMAC(api, c.IKey[:], c.OKey[:], c.Msg[:])
	if err != nil {
		return err
	}
	// Assert HMAC output == public TranscriptCommitment (two 128-bit halves).
	gotHi := packU8ToField(api, hmacOut[:16])
	gotLo := packU8ToField(api, hmacOut[16:])
	api.AssertIsEqual(c.TCHi, gotHi)
	api.AssertIsEqual(c.TCLo, gotLo)
	return nil
}

// PgpTCHalves splits a 32-byte TranscriptCommitment into the two field-element
// public inputs expected by PgpCircuit (big-endian 128-bit halves).
func PgpTCHalves(tc [32]byte) (hi, lo uint64) {
	// This is a native helper; actual field packing is done in deco.go.
	// We return the raw bytes here; callers convert to *big.Int for gnark.
	_ = tc
	return 0, 0 // unused — see deco.go BuildPgpPublicInputs
}

// bigFromBytes interprets b as a big-endian unsigned integer.
func bigFromBytes(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// BuildPgpWitness constructs the full PgpCircuit assignment.
// kMac is the 32-byte MAC key; msg is Q||R (will be zero-padded to PgpMsgLen).
func BuildPgpWitness(kMac [32]byte, msg []byte, tc [32]byte) *PgpCircuit {
	ikey, okey := PrepareHMACKeys(kMac)
	c := &PgpCircuit{}

	// Fill IKey / OKey.
	for i := 0; i < 64; i++ {
		c.IKey[i] = uints.U8{Val: frontend.Variable(int(ikey[i]))}
		c.OKey[i] = uints.U8{Val: frontend.Variable(int(okey[i]))}
	}

	// Fill Msg: copy msg, zero-pad remainder.
	for i := 0; i < PgpMsgLen; i++ {
		v := byte(0)
		if i < len(msg) {
			v = msg[i]
		}
		c.Msg[i] = uints.U8{Val: frontend.Variable(int(v))}
	}

	// Set public inputs: TCHi = bytes[0:16], TCLo = bytes[16:32], both big-endian.
	hiInt := bigFromBytes(tc[:16])
	loInt := bigFromBytes(tc[16:])
	c.TCHi = frontend.Variable(hiInt)
	c.TCLo = frontend.Variable(loInt)
	return c
}
