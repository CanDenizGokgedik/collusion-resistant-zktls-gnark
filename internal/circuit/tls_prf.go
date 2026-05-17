package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

// TlsPrfCircuit is the Mode 2 circuit — full TLS 1.2 PRF via HMAC-SHA256.
//
// The prover pre-computes all HMAC inputs natively (pre-padded ikey/okey,
// and the message for each of the 12 HMAC calls) and supplies them as
// witnesses. The circuit adds SHA256 compression constraints for each call,
// matching the Rust reference which allocates block words as witnesses.
//
// Constraint count ≈ 56 SHA256 compressions × ~27 000 ≈ 1.51 M R1CS.
type TlsPrfCircuit struct {
	// Phase 1 — master secret: 2 HMACs
	// HMAC(PMS, seed_ms):  seed_ms = label(13)||CR(32)||SR(32) = 77 B
	//   inner = ikey(64)||msg(77)=141B → 3 blocks; outer = okey(64)||h(32)=96B → 2 blocks
	P1H1IKey [64]uints.U8 `gnark:",secret"`
	P1H1OKey [64]uints.U8 `gnark:",secret"`
	P1H1Msg  [77]uints.U8 `gnark:",secret"`
	// HMAC(PMS, A1||seed_ms): inner msg = A1(32)||seed_ms(77) = 109 B
	P1H2IKey [64]uints.U8  `gnark:",secret"`
	P1H2OKey [64]uints.U8  `gnark:",secret"`
	P1H2Msg  [109]uints.U8 `gnark:",secret"`

	// Phase 2 — key expansion: 5 × 2 = 10 HMACs
	// Iter 0 A: HMAC(ms, seed_ke) — same shape as P1H1
	P2A0IKey [64]uints.U8 `gnark:",secret"`
	P2A0OKey [64]uints.U8 `gnark:",secret"`
	P2A0Msg  [77]uints.U8 `gnark:",secret"`
	// Iter 0 P: HMAC(ms, A0||seed_ke)
	P2P0IKey [64]uints.U8  `gnark:",secret"`
	P2P0OKey [64]uints.U8  `gnark:",secret"`
	P2P0Msg  [109]uints.U8 `gnark:",secret"`
	// Iters 1-4 A: HMAC(ms, A[i-1])  inner msg = prev(32)
	P2AIKey [4][64]uints.U8 `gnark:",secret"`
	P2AOKey [4][64]uints.U8 `gnark:",secret"`
	P2AMsg  [4][32]uints.U8 `gnark:",secret"`
	// Iters 1-4 P: HMAC(ms, A[i]||seed_ke)
	P2PIKey [4][64]uints.U8  `gnark:",secret"`
	P2POKey [4][64]uints.U8  `gnark:",secret"`
	P2PMsg  [4][109]uints.U8 `gnark:",secret"`

	// K_MAC commitment
	PShare      frontend.Variable `gnark:",secret"`
	VShare      frontend.Variable `gnark:",secret"`
	Commitment  frontend.Variable `gnark:",public"`
	RandBinding frontend.Variable `gnark:",public"`
}

// Define implements frontend.Circuit.
//
// Critical binding note:
//   The Phase 1 output (master secret = TLS-PRF(PMS,"master secret"||CR||SR)[0:32])
//   is bound to the K_MAC split:
//     pack(P1H2_output) == PShare + VShare
//   Without this, the prover could supply arbitrary shares unrelated to TLS-PRF.
func (c *TlsPrfCircuit) Define(api frontend.API) error {
	// Phase 1: master secret derivation
	if _, err := runHMAC(api, c.P1H1IKey[:], c.P1H1OKey[:], c.P1H1Msg[:]); err != nil {
		return err
	}
	// P1H2 output = TLS-PRF master secret = K_MAC base (before rand binding)
	kMacBytes, err := runHMAC(api, c.P1H2IKey[:], c.P1H2OKey[:], c.P1H2Msg[:])
	if err != nil {
		return err
	}

	// Phase 2: key expansion (full PRF output; K_MAC is the P1H2 output)
	if _, err := runHMAC(api, c.P2A0IKey[:], c.P2A0OKey[:], c.P2A0Msg[:]); err != nil {
		return err
	}
	if _, err := runHMAC(api, c.P2P0IKey[:], c.P2P0OKey[:], c.P2P0Msg[:]); err != nil {
		return err
	}
	for i := 0; i < 4; i++ {
		if _, err := runHMAC(api, c.P2AIKey[i][:], c.P2AOKey[i][:], c.P2AMsg[i][:]); err != nil {
			return err
		}
		if _, err := runHMAC(api, c.P2PIKey[i][:], c.P2POKey[i][:], c.P2PMsg[i][:]); err != nil {
			return err
		}
	}

	// ── Critical binding: TLS-PRF output → K_MAC split ───────────────────
	// kMacBase = pack(P1H2_output)  [big-endian, 32 bytes → Fr element]
	kMacBaseFe := packU8ToField(api, kMacBytes)
	// RandBinding is passed as a rand32 field element from deco.HSP.
	// kMac (field) = kMacBase + RandBinding  (Fr addition instead of XOR)
	kMacFe := api.Add(kMacBaseFe, c.RandBinding)
	// K_MAC split binding: kMac == PShare + VShare
	kMacFromShares := api.Add(c.PShare, c.VShare)
	api.AssertIsEqual(kMacFe, kMacFromShares)
	// Commitment consistency: Commitment == PShare + VShare + RandBinding
	api.AssertIsEqual(c.Commitment, api.Add(kMacFromShares, c.RandBinding))
	return nil
}

// packU8ToField converts a 32-byte U8 array into a BLS12-381 Fr field element.
// Encoding: big-endian (bytes[0] is the most significant byte).
// Constraint count: ~32 multiplications + 32 additions (very efficient).
func packU8ToField(api frontend.API, bytes []uints.U8) frontend.Variable {
	result := frontend.Variable(0)
	for i, b := range bytes {
		// constant multiplier 2^(8*(31-i))
		shift := new(big.Int).Lsh(big.NewInt(1), uint(8*(len(bytes)-1-i)))
		result = api.Add(result, api.Mul(b.Val, shift))
	}
	return result
}

// runHMAC computes HMAC-SHA256 inside the circuit.
// ikey / okey are pre-padded witnesses (key XOR ipad / opad, zero-padded to 64B).
func runHMAC(api frontend.API, ikey, okey, msg []uints.U8) ([]uints.U8, error) {
	h1, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	h1.Write(ikey)
	h1.Write(msg)
	inner := h1.Sum()

	h2, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	h2.Write(okey)
	h2.Write(inner)
	return h2.Sum(), nil
}

// ── Prover helpers ────────────────────────────────────────────────────────────

// PrepareHMACKeys pre-computes ikey and okey for a 32-byte secret key.
func PrepareHMACKeys(key [32]byte) (ikey, okey [64]byte) {
	for i := 0; i < 32; i++ {
		ikey[i] = key[i] ^ 0x36
		okey[i] = key[i] ^ 0x5c
	}
	for i := 32; i < 64; i++ {
		ikey[i] = 0x36
		okey[i] = 0x5c
	}
	return
}

// BytesToU8Slice converts a byte slice to []uints.U8 for circuit assignment.
func BytesToU8Slice(b []byte) []uints.U8 {
	out := make([]uints.U8, len(b))
	for i, v := range b {
		out[i] = uints.U8{Val: frontend.Variable(int(v))}
	}
	return out
}

// NewTlsPrfAssignment builds a TlsPrfCircuit assignment from raw key material.
// The Commitment field is left as 0; callers must set it after computing big.Int.
func NewTlsPrfAssignment(
	pms, clientRandom, serverRandom, pShare, vShare, randBinding [32]byte,
) *TlsPrfCircuit {
	labelMS := []byte("master secret")
	labelKE := []byte("key expansion")

	seedMS := append([]byte{}, labelMS...)
	seedMS = append(seedMS, clientRandom[:]...)
	seedMS = append(seedMS, serverRandom[:]...)

	seedKE := append([]byte{}, labelKE...)
	seedKE = append(seedKE, serverRandom[:]...)
	seedKE = append(seedKE, clientRandom[:]...)

	ikeyPMS, okeyPMS := PrepareHMACKeys(pms)
	a1 := HmacSha256Native(pms[:], seedMS)

	ms32 := MasterSecretNative(pms, clientRandom, serverRandom)
	ikeyMS, okeyMS := PrepareHMACKeys(ms32)

	a0 := HmacSha256Native(ms32[:], seedKE)

	c := &TlsPrfCircuit{}

	fill64(&c.P1H1IKey, ikeyPMS[:])
	fill64(&c.P1H1OKey, okeyPMS[:])
	fill77(&c.P1H1Msg, seedMS)

	fill64(&c.P1H2IKey, ikeyPMS[:])
	fill64(&c.P1H2OKey, okeyPMS[:])
	msg2 := append([]byte{}, a1...)
	msg2 = append(msg2, seedMS...)
	fill109(&c.P1H2Msg, msg2)

	fill64(&c.P2A0IKey, ikeyMS[:])
	fill64(&c.P2A0OKey, okeyMS[:])
	fill77(&c.P2A0Msg, seedKE)

	fill64(&c.P2P0IKey, ikeyMS[:])
	fill64(&c.P2P0OKey, okeyMS[:])
	p0Msg := append([]byte{}, a0...)
	p0Msg = append(p0Msg, seedKE...)
	fill109(&c.P2P0Msg, p0Msg)

	aPrev := a0
	for i := 0; i < 4; i++ {
		fill64(&c.P2AIKey[i], ikeyMS[:])
		fill64(&c.P2AOKey[i], okeyMS[:])
		fill32(&c.P2AMsg[i], aPrev)

		aI := HmacSha256Native(ms32[:], aPrev)
		fill64(&c.P2PIKey[i], ikeyMS[:])
		fill64(&c.P2POKey[i], okeyMS[:])
		piMsg := append([]byte{}, aI...)
		piMsg = append(piMsg, seedKE...)
		fill109(&c.P2PMsg[i], piMsg)
		aPrev = aI
	}

	c.PShare = PackBytes32(pShare)
	c.VShare = PackBytes32(vShare)
	c.RandBinding = PackBytes32(randBinding)
	c.Commitment = 0 // caller sets this
	return c
}

func fill64(dst *[64]uints.U8, src []byte) {
	for i := 0; i < 64 && i < len(src); i++ {
		dst[i] = uints.U8{Val: frontend.Variable(int(src[i]))}
	}
}
func fill77(dst *[77]uints.U8, src []byte) {
	for i := 0; i < 77 && i < len(src); i++ {
		dst[i] = uints.U8{Val: frontend.Variable(int(src[i]))}
	}
}
func fill109(dst *[109]uints.U8, src []byte) {
	for i := 0; i < 109 && i < len(src); i++ {
		dst[i] = uints.U8{Val: frontend.Variable(int(src[i]))}
	}
}
func fill32(dst *[32]uints.U8, src []byte) {
	for i := 0; i < 32 && i < len(src); i++ {
		dst[i] = uints.U8{Val: frontend.Variable(int(src[i]))}
	}
}