package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

func mkPgpInputs(value string) PgpInputs {
	var kMac [32]byte
	var kEnc, iv [16]byte
	for i := range kMac {
		kMac[i] = byte(i + 1)
	}
	for i := range kEnc {
		kEnc[i] = byte(i*3 + 7)
	}
	for i := range iv {
		iv[i] = byte(i*5 + 2)
	}
	pt := make([]byte, PgpPlainLen)
	for i := range pt {
		pt[i] = byte('a' + i%26)
	}
	// place ASCII value in the suffix at PgpValOff..+PgpValLen
	off := (PgpPrevLen - 64) + PgpValOff
	copy(pt[off:off+PgpValLen], []byte(value))
	prefix := make([]byte, PgpPrefixLen)
	copy(prefix, pt)
	pad := make([]byte, PgpPadLen)
	for i := range pad {
		pad[i] = byte(PgpPadLen - 1)
	}
	return PgpInputs{KMac: kMac, KEnc: kEnc, Plaintext: pt, IvLast3rd: iv, Prefix3: prefix, Pad: pad, Threshold: 30000}
}

func TestPgpFull(t *testing.T) {
	assert := test.NewAssert(t)

	// value 38000 >= threshold 30000 → valid.
	good, _, err := BuildPgpAll(mkPgpInputs("00038000"))
	if err != nil {
		t.Fatal(err)
	}
	assert.SolvingSucceeded(&PgpCircuit{}, good, test.WithCurves(ecc.BLS12_381))

	// value 00029999 < 30000 → predicate must fail.
	low, _, _ := BuildPgpAll(mkPgpInputs("00029999"))
	assert.SolvingFailed(&PgpCircuit{}, low, test.WithCurves(ecc.BLS12_381))

	// tamper on-wire ciphertext → MtE binding fails.
	badCt, _, _ := BuildPgpAll(mkPgpInputs("00038000"))
	badCt.ExpectCt[0] = u8b(byte(badCt.ExpectCt[0].Val.(int) ^ 0xff))
	assert.SolvingFailed(&PgpCircuit{}, badCt, test.WithCurves(ecc.BLS12_381))

	// wrong K_MAC (public input) → HMAC/ciphertext mismatch, proof fails.
	badK, _, _ := BuildPgpAll(mkPgpInputs("00038000"))
	badK.KMac[0] = u8b(byte(badK.KMac[0].Val.(int) ^ 0xff))
	assert.SolvingFailed(&PgpCircuit{}, badK, test.WithCurves(ecc.BLS12_381))
}
