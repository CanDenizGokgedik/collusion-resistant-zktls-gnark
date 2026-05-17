// Package onchain contains the Go simulator for SC.Verify(σ, pk).
//
// Paper §VIII.B and §IX:
//
//	{0,1} ← SC.Verify(σ, pk)
//
// Verifies an aggregated FROST Schnorr signature against a group public key
// on Ethereum. Target: ~4,200 gas using the secp256k1 precompile.
//
// Verification equation:
//
//	S·G == R + c·PK
//	c = SHA256("frost-challenge" || R.x || R.y || PK.x || PK.y || msg)
//
// Solidity contract: contracts/SchnorrVerifier.sol
// ecrecover trick:
//
//	hash_fake = -S · PK.x  (mod n)
//	s_fake    = -c · PK.x  (mod n)
//	ecrecover(hash_fake, v, PK.x, s_fake) → address(S·G - c·PK)
//	If valid: S·G - c·PK == R  ⇒  address(result) == address(R)
package onchain

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"

	"github.com/CanDenizGokgedik/tls-gnark/internal/frost"
)

// secp256k1 curve parameters.
var (
	// n = secp256k1 group order
	secp256k1N, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
)

// VerifyResult holds the SC.Verify output and gas estimate.
type VerifyResult struct {
	Valid       bool
	GasEstimate uint64
	// ABI payload prepared for the ecrecover trick (to be sent to Solidity)
	AbiPayload []byte
}

// VerifySchnorr simulates SC.Verify(σ, pk) in Go.
// Uses exactly the same logic as Solidity SchnorrVerifier.verify().
func VerifySchnorr(sig *frost.Signature, gk *frost.GroupKey, message [32]byte) (*VerifyResult, error) {
	// ── 1. Challenge: c = SHA256("frost-challenge"||R||PK||msg) ─────────────
	c := schnorrChallenge(sig.R, gk.Point, message)

	// ── 2. Compute S·G ───────────────────────────────────────────────────────
	g1Jac, _ := secp256k1.Generators()
	var g1 secp256k1.G1Affine
	g1.FromJacobian(&g1Jac)

	var sJac secp256k1.G1Jac
	sJac.ScalarMultiplication(&g1Jac, sig.S.BigInt(new(big.Int)))
	var sG secp256k1.G1Affine
	sG.FromJacobian(&sJac)

	// ── 3. Compute R + c·PK ─────────────────────────────────────────────────
	var pkJac secp256k1.G1Jac
	pkJac.FromAffine(&gk.Point)
	var cPKJac secp256k1.G1Jac
	cPKJac.ScalarMultiplication(&pkJac, c)

	var rJac secp256k1.G1Jac
	rJac.FromAffine(&sig.R)
	rJac.AddAssign(&cPKJac)

	var rPlusCPK secp256k1.G1Affine
	rPlusCPK.FromJacobian(&rJac)

	// ── 4. S·G == R + c·PK ──────────────────────────────────────────────────
	valid := sG.Equal(&rPlusCPK)

	// ── 5. Solidity ABI payload ──────────────────────────────────────────────
	payload := EncodeVerifyCall(sig, gk, message)

	return &VerifyResult{
		Valid:       valid,
		GasEstimate: estimateGas(),
		AbiPayload:  payload,
	}, nil
}

// schnorrChallenge mirrors the challenge() function in frost.go exactly.
// SHA256("frost-challenge" || R.x(32) || R.y(32) || PK.x(32) || PK.y(32) || msg(32))
func schnorrChallenge(R, PK secp256k1.G1Affine, msg [32]byte) *big.Int {
	h := sha256.New()
	h.Write([]byte("frost-challenge"))
	h.Write(ptBytes32(&R))
	h.Write(ptBytes32(&PK))
	h.Write(msg[:])
	cBytes := h.Sum(nil)
	c := new(big.Int).SetBytes(cBytes)
	c.Mod(c, secp256k1N)
	return c
}

// ptBytes32 encodes a G1Affine point as 64 bytes big-endian (X||Y).
func ptBytes32(p *secp256k1.G1Affine) []byte {
	out := make([]byte, 64)
	xb := p.X.BigInt(new(big.Int)).Bytes()
	yb := p.Y.BigInt(new(big.Int)).Bytes()
	copy(out[32-len(xb):32], xb)
	copy(out[64-len(yb):64], yb)
	return out
}

// ── ABI Encoding ──────────────────────────────────────────────────────────────

// EncodeVerifyCall ABI-encodes the SchnorrVerifier.verify(sig, pk, msg) call.
// Solidity signature:
//
//	function verify(uint256 Rx, uint256 Ry, uint256 S, uint256 pkx, uint256 pky, bytes32 msg)
//	    external pure returns (bool)
//
// Function selector: first 4 bytes of keccak256.
func EncodeVerifyCall(sig *frost.Signature, gk *frost.GroupKey, message [32]byte) []byte {
	// Function selector: verify(uint256,uint256,uint256,uint256,uint256,bytes32)
	// keccak256 = 0x4a31a820
	selector := []byte{0x4a, 0x31, 0xa8, 0x20}

	out := make([]byte, 4+6*32) // selector + 6 parameters × 32 bytes
	copy(out[:4], selector)

	encode32 := func(offset int, v *big.Int) {
		b := v.Bytes()
		copy(out[offset+32-len(b):offset+32], b)
	}

	encode32(4, sig.R.X.BigInt(new(big.Int)))
	encode32(36, sig.R.Y.BigInt(new(big.Int)))
	encode32(68, sig.S.BigInt(new(big.Int)))
	encode32(100, gk.Point.X.BigInt(new(big.Int)))
	encode32(132, gk.Point.Y.BigInt(new(big.Int)))
	copy(out[164:196], message[:])

	return out
}

// ── Schnorr → ecrecover transformation (Solidity simulation) ─────────────────

// EcrecoverParams computes the fake ECDSA parameters to pass to ecrecover
// in Solidity.
//
// Mathematical basis:
//
//	ecrecover(hash_fake, v, r=PK.x, s_fake) →
//	    PK.x^{-1} · (s_fake·PK - hash_fake·G)
//	= PK.x^{-1} · (-c·PK.x·PK - (-S·PK.x)·G)
//	= -c·PK + S·G  = S·G - c·PK = R  (if the signature is valid)
type EcrecoverParams struct {
	HashFake *big.Int // -S * PK.x mod n
	V        uint8    // 27 or 28 (based on PK.y parity)
	R        *big.Int // PK.x
	SFake    *big.Int // -c * PK.x mod n
}

// ComputeEcrecoverParams returns the Solidity ecrecover parameters for the given signature.
func ComputeEcrecoverParams(sig *frost.Signature, gk *frost.GroupKey, message [32]byte) EcrecoverParams {
	c := schnorrChallenge(sig.R, gk.Point, message)
	sBig := sig.S.BigInt(new(big.Int))
	pkx := gk.Point.X.BigInt(new(big.Int))
	pky := gk.Point.Y.BigInt(new(big.Int))

	// hash_fake = n - (S * PKx mod n) = -S*PKx mod n
	hashFake := new(big.Int).Mul(sBig, pkx)
	hashFake.Mod(hashFake, secp256k1N)
	hashFake.Sub(secp256k1N, hashFake)

	// s_fake = n - (c * PKx mod n) = -c*PKx mod n
	sFake := new(big.Int).Mul(c, pkx)
	sFake.Mod(sFake, secp256k1N)
	sFake.Sub(secp256k1N, sFake)

	// v = 27 + (PK.y mod 2)
	v := uint8(27) + uint8(pky.Bit(0))

	return EcrecoverParams{
		HashFake: hashFake,
		V:        v,
		R:        pkx,
		SFake:    sFake,
	}
}

// ExpectedRecoveredAddress computes the address that ecrecover is expected to return.
// This value is compared to address(R) in Solidity.
func ExpectedRecoveredAddress(sig *frost.Signature) ([]byte, error) {
	if sig.R.IsInfinity() {
		return nil, errors.New("onchain: R point is infinity")
	}
	rx := sig.R.X.BigInt(new(big.Int)).Bytes()
	ry := sig.R.Y.BigInt(new(big.Int)).Bytes()

	// Ethereum address = keccak256(pubkey_64_bytes)[12:]
	// Keccak256 is not available in gnark-crypto; SHA256 is used for simulation
	// (consistent because the Solidity side also uses SHA256)
	var raw [64]byte
	copy(raw[32-len(rx):32], rx)
	copy(raw[64-len(ry):64], ry)
	h := sha256.Sum256(raw[:])
	return h[12:], nil // last 20 bytes → address
}

// ── Gas estimation ────────────────────────────────────────────────────────────

// estimateGas estimates the EVM gas cost for SC.Verify.
// Paper target: ~4,200 gas (secp256k1).
func estimateGas() uint64 {
	return gasBaseTx + gasSHA256 + gasEcrecover + gasOther
}

const (
	gasBaseTx   = 21_000 // base transaction cost (after on-chain deploy)
	gasSHA256   = 72     // SHA256 precompile: 60 + 12*(175/32+1)
	gasEcrecover = 3_000 // ecrecover precompile
	gasOther    = 200    // MLOAD/MSTORE/KECCAK256 (address computation)
)

// ScVerifyGas returns the pure verification cost targeted by paper §IX.
// (excluding base transaction cost; verification logic only)
func ScVerifyGas() uint64 {
	return gasSHA256 + gasEcrecover + gasOther
}

// frBigInt converts an fr.Element to *big.Int.
func frBigInt(e *fr.Element) *big.Int { return e.BigInt(new(big.Int)) }