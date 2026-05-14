// Package frost implements FROST threshold Schnorr signatures on secp256k1.
package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

// ── Types ────────────────────────────────────────────────────────────────────

type GroupKey struct{ Point secp256k1.G1Affine }

type Signer struct {
	Index int
	SK    fr.Element
	VK    secp256k1.G1Affine
	Group *GroupKey
	N, T  int
}

type Nonce struct{ D, E fr.Element }

type Commitment struct {
	Index          int
	PointD, PointE secp256k1.G1Affine
}

type SignatureShare struct {
	Index int
	Z     fr.Element
}

type Signature struct {
	R secp256k1.G1Affine
	S fr.Element
}

type DKGOut struct {
	Signer   Signer
	GroupKey *GroupKey
}

// ── DKG ──────────────────────────────────────────────────────────────────────

func RunDKG(n, t int) ([]*DKGOut, error) {
	if t > n {
		return nil, errors.New("frost: threshold > n")
	}
	coeffs := make([]fr.Element, t)
	for i := range coeffs {
		if _, err := coeffs[i].SetRandom(); err != nil {
			return nil, err
		}
	}

	g1 := g1Gen()
	var gkJac secp256k1.G1Jac
	gkJac.ScalarMultiplication(affToJac(&g1), coeffs[0].BigInt(new(big.Int)))
	var gkAff secp256k1.G1Affine
	gkAff.FromJacobian(&gkJac)
	gk := &GroupKey{Point: gkAff}

	outs := make([]*DKGOut, n)
	for i := 0; i < n; i++ {
		var x fr.Element
		x.SetUint64(uint64(i + 1))
		sk := evalPoly(coeffs, x)
		vk := scalarMul(&g1, &sk)
		outs[i] = &DKGOut{
			Signer:   Signer{Index: i + 1, SK: sk, VK: vk, Group: gk, N: n, T: t},
			GroupKey: gk,
		}
	}
	return outs, nil
}

// ── Round 1 ───────────────────────────────────────────────────────────────────

func Round1(s *Signer) (*Nonce, *Commitment, error) {
	var d, e fr.Element
	if _, err := d.SetRandom(); err != nil {
		return nil, nil, err
	}
	if _, err := e.SetRandom(); err != nil {
		return nil, nil, err
	}
	g := g1Gen()
	D := scalarMul(&g, &d)
	E := scalarMul(&g, &e)
	return &Nonce{D: d, E: e},
		&Commitment{Index: s.Index, PointD: D, PointE: E},
		nil
}

// ── Round 2 ───────────────────────────────────────────────────────────────────

func Round2(
	s *Signer,
	nonce *Nonce,
	commitments []*Commitment,
	message [32]byte,
) (*SignatureShare, error) {
	rho := bindingFactor(s.Index, message, commitments)
	R := aggregateR(commitments, message)
	c := challenge(R, s.Group.Point, message)

	indices := make([]fr.Element, len(commitments))
	for k, cm := range commitments {
		indices[k].SetUint64(uint64(cm.Index))
	}
	lambda := lagrange(indices, idxPos(s.Index, commitments))

	var z, rhoE, lambdaSkC fr.Element
	rhoE.Mul(&rho, &nonce.E)
	z.Add(&nonce.D, &rhoE)
	lambdaSkC.Mul(&lambda, &s.SK)
	lambdaSkC.Mul(&lambdaSkC, &c)
	z.Add(&z, &lambdaSkC)

	return &SignatureShare{Index: s.Index, Z: z}, nil
}

// ── Aggregate ─────────────────────────────────────────────────────────────────

func Aggregate(
	commitments []*Commitment,
	shares []*SignatureShare,
	message [32]byte,
) (*Signature, error) {
	R := aggregateR(commitments, message)
	var s fr.Element
	for _, sh := range shares {
		s.Add(&s, &sh.Z)
	}
	return &Signature{R: R, S: s}, nil
}

// ── Verify ────────────────────────────────────────────────────────────────────

func Verify(sig *Signature, gk *GroupKey, message [32]byte) bool {
	c := challenge(sig.R, gk.Point, message)
	g := g1Gen()
	sG := scalarMul(&g, &sig.S)
	cPK := scalarMul(&gk.Point, &c)

	var cPKJac secp256k1.G1Jac
	cPKJac.FromAffine(&cPK)
	cPKJac.Neg(&cPKJac)
	var sGJac secp256k1.G1Jac
	sGJac.FromAffine(&sG)
	sGJac.AddAssign(&cPKJac)
	var rPrime secp256k1.G1Affine
	rPrime.FromJacobian(&sGJac)
	return rPrime.Equal(&sig.R)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func g1Gen() secp256k1.G1Affine {
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

func bindingFactor(idx int, msg [32]byte, cms []*Commitment) fr.Element {
	h := sha256.New()
	h.Write([]byte("frost-binding"))
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(idx))
	h.Write(b[:])
	h.Write(msg[:])
	for _, cm := range cms {
		h.Write(ptBytes(&cm.PointD))
		h.Write(ptBytes(&cm.PointE))
	}
	var e fr.Element
	e.SetBytes(h.Sum(nil))
	return e
}

func aggregateR(cms []*Commitment, msg [32]byte) secp256k1.G1Affine {
	var R secp256k1.G1Jac
	for _, cm := range cms {
		rho := bindingFactor(cm.Index, msg, cms)
		rhoE := scalarMul(&cm.PointE, &rho)
		var dJac, rhoEJac secp256k1.G1Jac
		dJac.FromAffine(&cm.PointD)
		rhoEJac.FromAffine(&rhoE)
		dJac.AddAssign(&rhoEJac)
		R.AddAssign(&dJac)
	}
	var aff secp256k1.G1Affine
	aff.FromJacobian(&R)
	return aff
}

func challenge(R, PK secp256k1.G1Affine, msg [32]byte) fr.Element {
	h := sha256.New()
	h.Write([]byte("frost-challenge"))
	h.Write(ptBytes(&R))
	h.Write(ptBytes(&PK))
	h.Write(msg[:])
	var c fr.Element
	c.SetBytes(h.Sum(nil))
	return c
}

func idxPos(idx int, cms []*Commitment) int {
	for i, cm := range cms {
		if cm.Index == idx {
			return i
		}
	}
	return 0
}

func scalarMul(p *secp256k1.G1Affine, s *fr.Element) secp256k1.G1Affine {
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

func ptBytes(p *secp256k1.G1Affine) []byte {
	out := make([]byte, 64)
	xb := p.X.BigInt(new(big.Int)).Bytes()
	yb := p.Y.BigInt(new(big.Int)).Bytes()
	copy(out[32-len(xb):32], xb)
	copy(out[64-len(yb):64], yb)
	return out
}

var _ = rand.Read