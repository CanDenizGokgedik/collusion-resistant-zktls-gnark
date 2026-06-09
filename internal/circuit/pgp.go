// pgp.go — Full DECO TLS 1.2 MAC-then-Encrypt PGP circuit (gnark/BLS12-381).
//
// Proves, in zero knowledge:
//
//	(1) inner = SHA256_continue(Si, Suffix)  (DECO s_i mid-state trick)
//	    mac   = SHA256( (K_MAC^opad) || inner )                    [HMAC, redacted]
//	(2) value(Suffix) >= Threshold  and  SHA256(Threshold) == OnChainCommit
//	                                                                [predicate + commit]
//	(3) AES-128-CBC(K_enc, IvLast3rd, [PrefixLast3rd|mac|Pad]) == ExpectCt
//	                                                                [MtE record binding]
//
// Only the disclosed suffix is hashed in-circuit (Si folds in ikey + the
// redacted prefix), and only the last 3 CBC blocks are encrypted — matching
// jsnark's RedactSuffixCircuitGenerator.
package circuit

import (
	"crypto/aes"
	"crypto/sha256"
	"encoding/binary"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"

	aesv2 "github.com/CanDenizGokgedik/tls-gnark/internal/circuit/aesv2"
)

// Circuit dimensions (compile-time; changing them regenerates the CRS).
const (
	PgpSufLen     = 48                            // disclosed plaintext suffix length
	PgpPrevLen    = 192                           // bytes folded into Si (mult. of 64): ikey(64)+128
	PgpPlainLen   = (PgpPrevLen - 64) + PgpSufLen // = 176 (full response plaintext)
	PgpTotalInner = 64 + PgpPlainLen              // ikey(64) + plaintext  → HMAC inner length

	PgpValOff = 4 // ASCII numeric value offset within the suffix
	PgpValLen = 8 // number of ASCII digits

	PgpPadLen    = 13
	PgpPrefixLen = 48 - 32 - PgpPadLen // = 3
)

// PgpCircuit is the full DECO PGP statement.
type PgpCircuit struct {
	KMac          [32]uints.U8           `gnark:",public"` // verifier holds K_MAC (DECO MtE)
	Suffix        [PgpSufLen]uints.U8    `gnark:",secret"`
	KEnc          [16]uints.U8           `gnark:",secret"`
	PrefixLast3rd [PgpPrefixLen]uints.U8 `gnark:",secret"`
	Pad           [PgpPadLen]uints.U8    `gnark:",secret"`
	ThresholdB    [4]uints.U8            `gnark:",secret"`

	Si            [8]frontend.Variable `gnark:",public"` // committed SHA256 mid-state
	IvLast3rd     [16]uints.U8         `gnark:",public"`
	ExpectCt      [48]uints.U8         `gnark:",public"`
	OnChainCommit [32]uints.U8         `gnark:",public"`
}

func xorConstByte(api frontend.API, b frontend.Variable, c byte) frontend.Variable {
	bits := api.ToBinary(b, 8)
	for i := 0; i < 8; i++ {
		if (c>>uint(i))&1 == 1 {
			bits[i] = api.Sub(1, bits[i])
		}
	}
	return api.FromBinary(bits...)
}

func (c *PgpCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// K_MAC is a PUBLIC input: the verifier supplies the K_MAC it already holds
	// (from HSP / handshake), so π_PGP verifies only against that exact key — no
	// commitment, matching the DECO reference (keyMac is a public circuit input).

	// (1) inner = continue(Si, Suffix); mac = SHA256(okey || inner).
	var si [8]uints.U32
	for i := 0; i < 8; i++ {
		si[i] = uapi.ValueOf(c.Si[i])
	}
	inner := sha256ContinueInner(uapi, si, c.Suffix[:], PgpPrevLen, PgpTotalInner)

	okey := make([]uints.U8, 64)
	for i := 0; i < 64; i++ {
		if i < 32 {
			okey[i] = uints.U8{Val: xorConstByte(api, c.KMac[i].Val, 0x5c)}
		} else {
			okey[i] = uints.U8{Val: frontend.Variable(0x5c)}
		}
	}
	ho, err := sha2.New(api)
	if err != nil {
		return err
	}
	ho.Write(okey)
	ho.Write(inner)
	mac := ho.Sum()

	// (2) predicate: parse ASCII value from suffix, value >= threshold; commit threshold.
	val := frontend.Variable(0)
	for i := 0; i < PgpValLen; i++ {
		d := c.Suffix[PgpValOff+i].Val
		api.AssertIsLessOrEqual(frontend.Variable('0'), d)
		api.AssertIsLessOrEqual(d, frontend.Variable('9'))
		val = api.Add(api.Mul(val, 10), api.Sub(d, frontend.Variable('0')))
	}
	thInt := frontend.Variable(0)
	for i := 0; i < 4; i++ {
		thInt = api.Add(api.Mul(thInt, 256), c.ThresholdB[i].Val)
	}
	api.AssertIsLessOrEqual(thInt, val) // threshold <= value

	hoc, err := sha2.New(api)
	if err != nil {
		return err
	}
	hoc.Write(c.ThresholdB[:])
	oc := hoc.Sum()
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(oc[i].Val, c.OnChainCommit[i].Val)
	}

	// (3) AES-128-CBC over last 3 blocks → bind to on-wire ciphertext.
	var pt [48]frontend.Variable
	idx := 0
	for i := 0; i < PgpPrefixLen; i++ {
		pt[idx] = c.PrefixLast3rd[i].Val
		idx++
	}
	for i := 0; i < 32; i++ {
		pt[idx] = mac[i].Val
		idx++
	}
	for i := 0; i < PgpPadLen; i++ {
		pt[idx] = c.Pad[i].Val
		idx++
	}
	g := aesv2.NewAES128(api)
	key := make([]frontend.Variable, 16)
	for i := 0; i < 16; i++ {
		key[i] = c.KEnc[i].Val
	}
	var prev [16]frontend.Variable
	for i := 0; i < 16; i++ {
		prev[i] = c.IvLast3rd[i].Val
	}
	for b := 0; b < 3; b++ {
		var blk [16]frontend.Variable
		for i := 0; i < 16; i++ {
			blk[i] = g.VariableXor(pt[b*16+i], prev[i], 8)
		}
		ct := g.Encrypt(key, blk)
		for i := 0; i < 16; i++ {
			api.AssertIsEqual(ct[i], c.ExpectCt[b*16+i].Val)
			prev[i] = ct[i]
		}
	}
	return nil
}

// ── Native helpers ────────────────────────────────────────────────────────────

func u8b(b byte) uints.U8 { return uints.U8{Val: frontend.Variable(int(b))} }

func AesCbcEncryptNative(key, iv, pt []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(pt))
	prev := make([]byte, 16)
	copy(prev, iv)
	for off := 0; off < len(pt); off += 16 {
		var x [16]byte
		for i := 0; i < 16; i++ {
			x[i] = pt[off+i] ^ prev[i]
		}
		blk.Encrypt(ct[off:off+16], x[:])
		copy(prev, ct[off:off+16])
	}
	return ct, nil
}

// PgpInputs bundles everything needed to build a witness (sim or real).
type PgpInputs struct {
	KMac      [32]byte
	KEnc      [16]byte
	Plaintext []byte // full response plaintext (len PgpPlainLen)
	IvLast3rd [16]byte
	Prefix3   []byte // PgpPrefixLen
	Pad       []byte // PgpPadLen
	Threshold uint32 // committed threshold
}

// PgpPublic holds the Groth16 public-input values for verification.
type PgpPublic struct {
	Si            [8]uint64
	IvLast3rd     [16]byte
	ExpectCt      [48]byte
	OnChainCommit [32]byte
}

// BuildPgpAll derives all witness + public values consistently.
func BuildPgpAll(in PgpInputs) (*PgpCircuit, PgpPublic, error) {
	ikey, _ := PrepareHMACKeys(in.KMac)

	// Si = SHA256 state after ikey(64) || plaintext[:PrevLen-64].
	pre := append(append([]byte{}, ikey[:]...), in.Plaintext[:PgpPrevLen-64]...)
	si := SiStateNative(pre)

	// mac over the full inner input (== continue(Si,suffix) by construction).
	padded := make([]byte, PgpMsgLenInner())
	copy(padded, in.Plaintext)
	mac := HmacSha256Native(in.KMac[:], in.Plaintext) // full HMAC over plaintext

	// last-3-block plaintext and on-wire ciphertext.
	ptCBC := append(append(append([]byte{}, in.Prefix3...), mac...), in.Pad...)
	ct, err := AesCbcEncryptNative(in.KEnc[:], in.IvLast3rd[:], ptCBC)
	if err != nil {
		return nil, PgpPublic{}, err
	}

	var thB [4]byte
	binary.BigEndian.PutUint32(thB[:], in.Threshold)
	onCommit := sha256.Sum256(thB[:])

	c := &PgpCircuit{}
	for i := 0; i < 32; i++ {
		c.KMac[i] = u8b(in.KMac[i])
		c.OnChainCommit[i] = u8b(onCommit[i])
	}
	suffix := in.Plaintext[PgpPrevLen-64:]
	for i := 0; i < PgpSufLen; i++ {
		c.Suffix[i] = u8b(suffix[i])
	}
	for i := 0; i < 16; i++ {
		c.KEnc[i] = u8b(in.KEnc[i])
		c.IvLast3rd[i] = u8b(in.IvLast3rd[i])
	}
	for i := 0; i < PgpPrefixLen; i++ {
		c.PrefixLast3rd[i] = u8b(in.Prefix3[i])
	}
	for i := 0; i < PgpPadLen; i++ {
		c.Pad[i] = u8b(in.Pad[i])
	}
	for i := 0; i < 4; i++ {
		c.ThresholdB[i] = u8b(thB[i])
	}
	for i := 0; i < 8; i++ {
		c.Si[i] = frontend.Variable(uint64(si[i]))
	}
	for i := 0; i < 48; i++ {
		c.ExpectCt[i] = u8b(ct[i])
	}
	_ = mac
	var pub PgpPublic
	for i := 0; i < 8; i++ {
		pub.Si[i] = uint64(si[i])
	}
	pub.IvLast3rd = in.IvLast3rd
	copy(pub.ExpectCt[:], ct)
	pub.OnChainCommit = onCommit
	return c, pub, nil
}

// PgpMsgLenInner returns the full HMAC inner-input plaintext length.
func PgpMsgLenInner() int { return PgpPlainLen }
