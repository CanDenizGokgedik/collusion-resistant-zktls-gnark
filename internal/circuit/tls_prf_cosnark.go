// tls_prf_cosnark.go — TLS-PRF co-SNARK circuit (paper §VIII.C).
//
// Implements exactly what the paper requires:
//
//	co-SNARK.Execute({pShare, vShare}, Zp)  →  (K_MAC, πHSP)
//
// Design:
//   - Zp, ClientRandom, ServerRandom  →  PUBLIC  (aux verifiers know these)
//   - PShare, VShare                  →  PRIVATE (each party knows only theirs)
//   - ikey, okey, HMAC chain derived in-circuit from Zp
//
// Wire layout in gnark R1CS private section:
//   w[0] = PShare   ← party P's scalar
//   w[1] = VShare   ← party V's scalar
//   (all subsequent wires are internal, derived from public Zp)
//
// Because only PShare and VShare are user-declared private inputs, dmsm.go
// can drive distributed MSM on this circuit with the same wire indices (0,1)
// it already uses for TlsKeyCircuit — no changes needed in dmsm.go.
//
// Constraint count: 2 HMAC-SHA256 ≈ 56 k R1CS  (vs 1.5 M for full PRF).
package circuit

import (
	"crypto/hmac"
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// CoSnarkSeedLen = len("master secret") + 32 + 32 = 77.
const CoSnarkSeedLen = 77

// TlsPrfCoSnarkCircuit is the HSP co-SNARK circuit from paper §VIII.C.
//
// Proves in zero knowledge:
//
//	TLS-PRF(Zp, "master secret"||CR||SR)[0:32] + RandBinding == PShare + VShare
//
// where Zp/CR/SR are public, and PShare/VShare are the only private wires.
type TlsPrfCoSnarkCircuit struct {
	// Private — one share per party (order matters for dmsm.go wire indices).
	PShare frontend.Variable `gnark:",secret"` // wire index 0 in K array
	VShare frontend.Variable `gnark:",secret"` // wire index 1 in K array

	// Public — known to all verifiers.
	Zp [32]uints.U8 `gnark:",public"` // ECDH pre-master secret
	CR [32]uints.U8 `gnark:",public"` // TLS ClientRandom
	SR [32]uints.U8 `gnark:",public"` // TLS ServerRandom

	Commitment  frontend.Variable `gnark:",public"` // PShare+VShare+RandBinding
	RandBinding frontend.Variable `gnark:",public"` // DVRF-derived rand32
}

// xorConstByteCoSnark is an alias so this file does not conflict with pgp.go.
// (Both files are in the same package; pgp.go already declares xorConstByte.)
func xorConstByteCS(api frontend.API, b frontend.Variable, c byte) frontend.Variable {
	return xorConstByte(api, b, c)
}

// Define implements frontend.Circuit.
func (c *TlsPrfCoSnarkCircuit) Define(api frontend.API) error {
	// ── 1. Derive HMAC keys from Zp in-circuit ──────────────────────────────
	// ikey[i] = Zp[i] XOR 0x36  (i<32),  0x36  (i≥32)
	// okey[i] = Zp[i] XOR 0x5c  (i<32),  0x5c  (i≥32)
	ikey := make([]uints.U8, 64)
	okey := make([]uints.U8, 64)
	for i := 0; i < 32; i++ {
		ikey[i] = uints.U8{Val: xorConstByteCS(api, c.Zp[i].Val, 0x36)}
		okey[i] = uints.U8{Val: xorConstByteCS(api, c.Zp[i].Val, 0x5c)}
	}
	for i := 32; i < 64; i++ {
		ikey[i] = uints.U8{Val: frontend.Variable(0x36)}
		okey[i] = uints.U8{Val: frontend.Variable(0x5c)}
	}

	// ── 2. Build seed = "master secret" || CR || SR ─────────────────────────
	label := []byte("master secret") // 13 bytes
	seed := make([]uints.U8, CoSnarkSeedLen)
	for i, b := range label {
		seed[i] = uints.U8{Val: frontend.Variable(int(b))}
	}
	for i := 0; i < 32; i++ {
		seed[13+i] = c.CR[i]
	}
	for i := 0; i < 32; i++ {
		seed[45+i] = c.SR[i]
	}

	// ── 3. Phase-1 HMAC pair (2 HMAC-SHA256 calls) ──────────────────────────
	// A1 = HMAC(Zp, seed)
	a1, err := runHMAC(api, ikey, okey, seed)
	if err != nil {
		return err
	}

	// msg2 = A1 || seed  (32 + 77 = 109 bytes)
	msg2 := make([]uints.U8, 32+CoSnarkSeedLen)
	copy(msg2[:32], a1)
	copy(msg2[32:], seed)

	// kMacBaseBytes = HMAC(Zp, A1||seed)
	kMacBaseBytes, err := runHMAC(api, ikey, okey, msg2)
	if err != nil {
		return err
	}

	// ── 4. Pack kMacBase to field element ────────────────────────────────────
	kMacBaseFe := packU8ToField(api, kMacBaseBytes)

	// ── 5. Binding: TLS-PRF output must equal share sum ──────────────────────
	// kMac = kMacBase + rand
	kMacFe := api.Add(kMacBaseFe, c.RandBinding)
	// kMac == PShare + VShare
	kMacFromShares := api.Add(c.PShare, c.VShare)
	api.AssertIsEqual(kMacFe, kMacFromShares)
	// Commitment == PShare + VShare + rand
	api.AssertIsEqual(c.Commitment, api.Add(kMacFromShares, c.RandBinding))

	return nil
}

// ── Native helpers ────────────────────────────────────────────────────────────

// CoSnarkKMacBaseNative computes K_MAC_base = TLS-PRF(pms, "master secret"||CR||SR)[0:32]
// natively, exactly mirroring the in-circuit computation.
func CoSnarkKMacBaseNative(pms, cr, sr [32]byte) [32]byte {
	label := []byte("master secret")
	seed := append(append([]byte{}, label...), cr[:]...)
	seed = append(seed, sr[:]...)

	mac := func(key, msg []byte) []byte {
		h := hmac.New(sha256.New, key)
		h.Write(msg)
		return h.Sum(nil)
	}

	a1 := mac(pms[:], seed)
	msg2 := append(append([]byte{}, a1...), seed...)
	kMacBase := mac(pms[:], msg2)

	var out [32]byte
	copy(out[:], kMacBase)
	return out
}

// NewTlsPrfCoSnarkAssignment builds the full circuit assignment for proof generation.
func NewTlsPrfCoSnarkAssignment(
	pms, cr, sr [32]byte,
	pShare, vShare, randBinding [32]byte,
) *TlsPrfCoSnarkCircuit {
	q := ecc.BLS12_381.ScalarField()

	pShareFe := PackBytes32(pShare)
	vShareFe := PackBytes32(vShare)
	randFe := PackBytes32(randBinding)

	commitFe := new(big.Int).Add(pShareFe, vShareFe)
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, q)

	c := &TlsPrfCoSnarkCircuit{}
	for i := 0; i < 32; i++ {
		c.Zp[i] = uints.U8{Val: frontend.Variable(int(pms[i]))}
		c.CR[i] = uints.U8{Val: frontend.Variable(int(cr[i]))}
		c.SR[i] = uints.U8{Val: frontend.Variable(int(sr[i]))}
	}
	c.PShare = pShareFe
	c.VShare = vShareFe
	c.RandBinding = randFe
	c.Commitment = commitFe
	return c
}