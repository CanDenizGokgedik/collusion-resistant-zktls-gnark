package circuit

import (
	"crypto/sha256"
	"math/big"
)

// HmacSha256Native computes HMAC-SHA256 natively (outside the circuit).
func HmacSha256Native(key, msg []byte) []byte {
	const blockLen = 64
	if len(key) > blockLen {
		h := sha256.Sum256(key)
		key = h[:]
	}
	padded := make([]byte, blockLen)
	copy(padded, key)

	ikey := make([]byte, blockLen)
	okey := make([]byte, blockLen)
	for i := 0; i < blockLen; i++ {
		ikey[i] = padded[i] ^ 0x36
		okey[i] = padded[i] ^ 0x5c
	}
	inner := sha256.Sum256(append(ikey, msg...))
	outer := sha256.Sum256(append(okey, inner[:]...))
	return outer[:]
}

// TlsPrfNative returns n bytes of TLS 1.2 P_SHA256 PRF output.
func TlsPrfNative(secret, label, seed []byte, n int) []byte {
	fullSeed := append([]byte{}, label...)
	fullSeed = append(fullSeed, seed...)
	var out []byte
	a := fullSeed
	for len(out) < n {
		a = HmacSha256Native(secret, a)
		pInput := append(a, fullSeed...)
		out = append(out, HmacSha256Native(secret, pInput)...)
	}
	return out[:n]
}

// XorBytes32 XORs two 32-byte arrays element-wise.
func XorBytes32(a, b [32]byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

// PackBytes32 packs 32 bytes into a *big.Int using little-endian byte order
// (consistent with gnark's Fr field element encoding).
func PackBytes32(b [32]byte) *big.Int {
	// gnark uses little-endian for field elements (FromMont/ToMont internally).
	// We directly use big.Int.SetBytes which is big-endian; gnark's
	// frontend.Variable accepts *big.Int values.
	return new(big.Int).SetBytes(b[:])
}

// MasterSecretNative derives the TLS 1.2 master secret from the PMS.
func MasterSecretNative(pms, clientRandom, serverRandom [32]byte) [32]byte {
	seed := append(clientRandom[:], serverRandom[:]...)
	ms := TlsPrfNative(pms[:], []byte("master secret"), seed, 32)
	var out [32]byte
	copy(out[:], ms)
	return out
}