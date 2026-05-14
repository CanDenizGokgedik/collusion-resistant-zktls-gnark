// Package dvrf implements a DDH-based DVRF on secp256k1 (paper §III).
package dvrf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fp "github.com/consensys/gnark-crypto/ecc/secp256k1/fp"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

// ── Types ────────────────────────────────────────────────────────────────────

type GroupKey struct{ Point secp256k1.G1Affine }

type Participant struct {
	Index int
	SK    fr.Element
	VK    secp256k1.G1Affine
	Group *GroupKey
}

type Eval struct {
	Index  int
	Gamma  secp256k1.G1Affine
	ProofC fr.Element
	ProofS fr.Element
}

type Output struct {
	Rand  [32]byte
	Proof [32]byte
}

type DKGOut struct {
	Participant Participant
	GroupKey    *GroupKey
}

// ── DKG ──────────────────────────────────────────────────────────────────────

func RunDKG(n, t int) ([]*DKGOut, error) {
	if t > n {
		return nil, errors.New("dvrf: threshold > n")
	}
	coeffs := make([]fr.Element, t)
	for i := range coeffs {
		if _, err := coeffs[i].SetRandom(); err != nil {
			return nil, err
		}
	}

	g1Aff := g1Generator()
	var gkJac secp256k1.G1Jac
	gkJac.ScalarMultiplication(affToJac(&g1Aff), coeffs[0].BigInt(new(big.Int)))
	var gkAff secp256k1.G1Affine
	gkAff.FromJacobian(&gkJac)
	gk := &GroupKey{Point: gkAff}

	outs := make([]*DKGOut, n)
	for i := 0; i < n; i++ {
		var x fr.Element
		x.SetUint64(uint64(i + 1))
		sk := evalPoly(coeffs, x)
		var vkJac secp256k1.G1Jac
		vkJac.ScalarMultiplication(affToJac(&g1Aff), sk.BigInt(new(big.Int)))
		var vkAff secp256k1.G1Affine
		vkAff.FromJacobian(&vkJac)
		outs[i] = &DKGOut{
			Participant: Participant{Index: i + 1, SK: sk, VK: vkAff, Group: gk},
			GroupKey:    gk,
		}
	}
	return outs, nil
}

// ── PartialEval ───────────────────────────────────────────────────────────────

func PartialEval(p *Participant, alpha [32]byte) (*Eval, error) {
	h := hashToG1(alpha)
	var gammaJac secp256k1.G1Jac
	gammaJac.ScalarMultiplication(affToJac(&h), p.SK.BigInt(new(big.Int)))
	var gamma secp256k1.G1Affine
	gamma.FromJacobian(&gammaJac)

	g := g1Generator()
	c, s, err := dleqProve(p.SK, &h, &p.VK, &gamma, &g)
	if err != nil {
		return nil, err
	}
	return &Eval{Index: p.Index, Gamma: gamma, ProofC: c, ProofS: s}, nil
}

// ── Combine ───────────────────────────────────────────────────────────────────

func Combine(evals []*Eval, alpha [32]byte) (*Output, error) {
	if len(evals) == 0 {
		return nil, errors.New("dvrf: no evaluations")
	}
	h := hashToG1(alpha)

	indices := make([]fr.Element, len(evals))
	for i, ev := range evals {
		indices[i].SetUint64(uint64(ev.Index))
	}

	var combined secp256k1.G1Jac
	for i, ev := range evals {
		lam := lagrange(indices, i)
		var tmp secp256k1.G1Jac
		tmp.ScalarMultiplication(affToJac(&ev.Gamma), lam.BigInt(new(big.Int)))
		combined.AddAssign(&tmp)
	}
	var combinedAff secp256k1.G1Affine
	combinedAff.FromJacobian(&combined)

	return &Output{
		Rand:  vrfHash(combinedAff, h, alpha),
		Proof: vrfProofHash(combinedAff, alpha),
	}, nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func g1Generator() secp256k1.G1Affine {
	g1Jac, _ := secp256k1.Generators()
	var aff secp256k1.G1Affine
	aff.FromJacobian(&g1Jac)
	return aff
}

func evalPoly(coeffs []fr.Element, x fr.Element) fr.Element {
	var result, xPow fr.Element
	xPow.SetOne()
	for _, c := range coeffs {
		var term fr.Element
		term.Mul(&c, &xPow)
		result.Add(&result, &term)
		xPow.Mul(&xPow, &x)
	}
	return result
}

func lagrange(xs []fr.Element, i int) fr.Element {
	var num, den fr.Element
	num.SetOne()
	den.SetOne()
	for j, xj := range xs {
		if j == i {
			continue
		}
		var negXj, diff fr.Element
		negXj.Neg(&xj)
		diff.Sub(&xs[i], &xj)
		num.Mul(&num, &negXj)
		den.Mul(&den, &diff)
	}
	den.Inverse(&den)
	num.Mul(&num, &den)
	return num
}

// hashToG1 maps alpha to a secp256k1 point using hash-and-try (try-and-increment).
func hashToG1(alpha [32]byte) secp256k1.G1Affine {
	// secp256k1: y² = x³ + 7 (mod p)
	seven := new(big.Int).SetUint64(7)
	p := fp.Modulus()

	buf := make([]byte, 36)
	copy(buf[:32], alpha[:])
	for ctr := uint32(0); ; ctr++ {
		binary.BigEndian.PutUint32(buf[32:], ctr)
		h := sha256.Sum256(buf)

		// Interpret hash as x coordinate.
		xBig := new(big.Int).SetBytes(h[:])
		xBig.Mod(xBig, p)

		// y² = x³ + 7
		x3 := new(big.Int).Mul(xBig, xBig)
		x3.Mul(x3, xBig)
		x3.Mod(x3, p)
		y2 := new(big.Int).Add(x3, seven)
		y2.Mod(y2, p)

		// Check quadratic residue: y = sqrt(y²) mod p.
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2) // (p+1)/4
		y := new(big.Int).Exp(y2, exp, p)
		if new(big.Int).Mul(y, y).Mod(new(big.Int).Mul(y, y), p).Cmp(y2) == 0 {
			var pt secp256k1.G1Affine
			pt.X.SetBigInt(xBig)
			pt.Y.SetBigInt(y)
			return pt
		}
	}
}

func dleqProve(
	sk fr.Element,
	h, vk, gamma, g *secp256k1.G1Affine,
) (fr.Element, fr.Element, error) {
	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		return fr.Element{}, fr.Element{}, err
	}

	rG := scalarMulAff(g, &r)
	rH := scalarMulAff(h, &r)

	cBytes := dleqHash(&rG, &rH, vk, gamma, g)
	var c fr.Element
	c.SetBytes(cBytes[:])

	var cs, s fr.Element
	cs.Mul(&c, &sk)
	s.Sub(&r, &cs)
	return c, s, nil
}

func dleqHash(rG, rH, vk, gamma, g *secp256k1.G1Affine) [32]byte {
	var buf []byte
	buf = append(buf, ptBytes(rG)...)
	buf = append(buf, ptBytes(rH)...)
	buf = append(buf, ptBytes(vk)...)
	buf = append(buf, ptBytes(gamma)...)
	buf = append(buf, ptBytes(g)...)
	return sha256.Sum256(buf)
}

func vrfHash(combined, h secp256k1.G1Affine, alpha [32]byte) [32]byte {
	var buf []byte
	buf = append(buf, ptBytes(&combined)...)
	buf = append(buf, ptBytes(&h)...)
	buf = append(buf, alpha[:]...)
	return sha256.Sum256(buf)
}

func vrfProofHash(combined secp256k1.G1Affine, alpha [32]byte) [32]byte {
	var buf []byte
	buf = append(buf, ptBytes(&combined)...)
	buf = append(buf, alpha[:]...)
	buf = append(buf, 0xff)
	return sha256.Sum256(buf)
}

// ptBytes encodes an affine point as 64 raw bytes (X||Y, each 32B big-endian).
func ptBytes(p *secp256k1.G1Affine) []byte {
	out := make([]byte, 64)
	xb := p.X.BigInt(new(big.Int)).Bytes()
	yb := p.Y.BigInt(new(big.Int)).Bytes()
	copy(out[32-len(xb):32], xb)
	copy(out[64-len(yb):64], yb)
	return out
}

func scalarMulAff(p *secp256k1.G1Affine, s *fr.Element) secp256k1.G1Affine {
	var jac secp256k1.G1Jac
	jac.ScalarMultiplication(affToJac(p), s.BigInt(new(big.Int)))
	var aff secp256k1.G1Affine
	aff.FromJacobian(&jac)
	return aff
}

func affToJac(a *secp256k1.G1Affine) *secp256k1.G1Jac {
	var j secp256k1.G1Jac
	j.FromAffine(a)
	return &j
}

var _ = rand.Read