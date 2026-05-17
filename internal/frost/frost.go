// Package frost implements FROST threshold Schnorr signatures on secp256k1.
//
// DKG — Feldman VSS (paper §C): each signer generates its own polynomial,
// broadcasts coefficient commitments, and verifies received shares.
// No trusted dealer is used.
package frost

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

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
	// FeldmanCommits[i][j] = A_{i,j} = coeffs[j]*G for signer i+1.
	FeldmanCommits [][]secp256k1.G1Affine
}

// ── Feldman VSS DKG ───────────────────────────────────────────────────────────
//
// Protocol (FROST §2.1 and paper §C):
//  1. Each signer i generates a random degree-(t-1) polynomial f_i(x).
//  2. Coefficient commitments A_{i,k} = coeffs[k]*G are broadcast.
//  3. Signer i sends s_{i→j} = f_i(j) to each signer j.
//  4. Each j verifies s_{i→j} against the Feldman commitments.
//  5. Each signer computes sk_j = Σ_i s_{i→j}.
//  6. Group public key: pk = Σ_i A_{i,0}

func RunDKG(n, t int) ([]*DKGOut, error) {
	if t > n {
		return nil, errors.New("frost: threshold > n")
	}

	g1 := g1Gen()

	type localPoly struct {
		coeffs  []fr.Element
		commits []secp256k1.G1Affine
	}

	// Step 1 & 2: Polynomial generation and Feldman commitments.
	polys := make([]localPoly, n)
	for i := 0; i < n; i++ {
		coeffs := make([]fr.Element, t)
		commits := make([]secp256k1.G1Affine, t)
		for k := range coeffs {
			if _, err := coeffs[k].SetRandom(); err != nil {
				return nil, fmt.Errorf("frost: DKG signer %d coeff %d: %w", i+1, k, err)
			}
			commits[k] = scalarMul(&g1, &coeffs[k])
		}
		polys[i] = localPoly{coeffs: coeffs, commits: commits}
	}

	// Step 3 & 4: Share distribution and Feldman verification.
	// Each sender i is independent; parallelized with goroutines.
	shares := make([][]fr.Element, n)
	for i := 0; i < n; i++ {
		shares[i] = make([]fr.Element, n)
	}
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < n; j++ {
				var xj fr.Element
				xj.SetUint64(uint64(j + 1))
				shares[i][j] = evalPoly(polys[i].coeffs, xj)
				if err := feldmanVerify(shares[i][j], polys[i].commits, j+1, &g1); err != nil {
					errCh <- fmt.Errorf("frost: Feldman VSS verification failed (signer %d → %d): %w", i+1, j+1, err)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return nil, err
	}

	// Step 5 & 6: Final SK shares and group public key.
	var gkJac secp256k1.G1Jac
	for i := 0; i < n; i++ {
		var term secp256k1.G1Jac
		term.FromAffine(&polys[i].commits[0])
		gkJac.AddAssign(&term)
	}
	var gkAff secp256k1.G1Affine
	gkAff.FromJacobian(&gkJac)
	gk := &GroupKey{Point: gkAff}

	allCommits := make([][]secp256k1.G1Affine, n)
	for i := 0; i < n; i++ {
		allCommits[i] = polys[i].commits
	}

	outs := make([]*DKGOut, n)
	for j := 0; j < n; j++ {
		var skJ fr.Element
		for i := 0; i < n; i++ {
			skJ.Add(&skJ, &shares[i][j])
		}
		vkJ := scalarMul(&g1, &skJ)
		outs[j] = &DKGOut{
			Signer: Signer{
				Index: j + 1,
				SK:    skJ,
				VK:    vkJ,
				Group: gk,
				N:     n,
				T:     t,
			},
			GroupKey:       gk,
			FeldmanCommits: allCommits,
		}
	}
	return outs, nil
}

// SignersFromKeyMaterial implements the paper §V "DKG Reload" step:
// constructs FROST signers from secp256k1 key material shared with DVRF,
// without running a new DKG.
//
// Parameters:
//   indices  — signer indices (1-based, same as dvrf.Participant.Index)
//   sks      — secret key shares (same as dvrf.Participant.SK)
//   vks      — verification keys (same as dvrf.Participant.VK)
//   groupKey — group public key point (same as dvrf.GroupKey.Point)
//   n, t     — total participant count and threshold
func SignersFromKeyMaterial(
	indices []int,
	sks []fr.Element,
	vks []secp256k1.G1Affine,
	groupKey secp256k1.G1Affine,
	n, t int,
) ([]*DKGOut, error) {
	if len(indices) != len(sks) || len(sks) != len(vks) {
		return nil, errors.New("frost: SignersFromKeyMaterial: length mismatch")
	}
	gk := &GroupKey{Point: groupKey}
	outs := make([]*DKGOut, len(indices))
	for i, idx := range indices {
		outs[i] = &DKGOut{
			Signer: Signer{
				Index: idx,
				SK:    sks[i],
				VK:    vks[i],
				Group: gk,
				N:     n,
				T:     t,
			},
			GroupKey: gk,
		}
	}
	return outs, nil
}

// feldmanVerify checks s*G == Σ_k commits[k] * x^k.
func feldmanVerify(s fr.Element, commits []secp256k1.G1Affine, x int, g *secp256k1.G1Affine) error {
	sG := scalarMul(g, &s)

	var xFr fr.Element
	xFr.SetUint64(uint64(x))

	var acc secp256k1.G1Jac
	var xPow fr.Element
	xPow.SetOne()
	for _, ck := range commits {
		ckCopy := ck
		term := scalarMul(&ckCopy, &xPow)
		var termJac secp256k1.G1Jac
		termJac.FromAffine(&term)
		acc.AddAssign(&termJac)
		xPow.Mul(&xPow, &xFr)
	}
	var expected secp256k1.G1Affine
	expected.FromJacobian(&acc)

	if !sG.Equal(&expected) {
		return errors.New("Feldman VSS share invalid: s*G ≠ Σ A_k * x^k")
	}
	return nil
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

// ── VerifySignatureShare ──────────────────────────────────────────────────────

// VerifySignatureShare implements the individual share verification from paper §III.C.
// Each share must be verified with this function before calling Aggregate;
// a malicious share would otherwise silently produce an invalid signature.
//
// Verification equation (FROST §5, Equation 5):
//
//	z_i · G == D_i + ρ_i · E_i + λ_i · c · VK_i
//
// Parameters:
//
//	share          — the signature share to verify
//	cm             — signer i's Round1 commitment (D_i, E_i)
//	vk             — signer i's verification key (VK_i = sk_i · G)
//	allCommitments — Round1 commitments from all participants
//	gk             — group public key
//	message        — the message being signed
func VerifySignatureShare(
	share *SignatureShare,
	cm *Commitment,
	vk secp256k1.G1Affine,
	allCommitments []*Commitment,
	gk *GroupKey,
	message [32]byte,
) bool {
	g := g1Gen()

	// Left-hand side: z_i · G
	zG := scalarMul(&g, &share.Z)

	// c = challenge(R_agg, GroupPK, msg)
	R := aggregateR(allCommitments, message)
	c := challenge(R, gk.Point, message)

	// λ_i: Lagrange coefficient for the participant set
	indices := make([]fr.Element, len(allCommitments))
	for k, acm := range allCommitments {
		indices[k].SetUint64(uint64(acm.Index))
	}
	lambda := lagrange(indices, idxPos(share.Index, allCommitments))

	// ρ_i: per-signer binding factor
	rho := bindingFactor(share.Index, message, allCommitments)

	// Right-hand side: D_i + ρ_i·E_i + λ_i·c·VK_i
	rhoE := scalarMul(&cm.PointE, &rho)
	var lambdaC fr.Element
	lambdaC.Mul(&lambda, &c)
	lambdaCVK := scalarMul(&vk, &lambdaC)

	var rhs secp256k1.G1Jac
	var dJac, rhoEJac, lambdaCVKJac secp256k1.G1Jac
	dJac.FromAffine(&cm.PointD)
	rhoEJac.FromAffine(&rhoE)
	lambdaCVKJac.FromAffine(&lambdaCVK)
	rhs.AddAssign(&dJac)
	rhs.AddAssign(&rhoEJac)
	rhs.AddAssign(&lambdaCVKJac)

	var rhsAff secp256k1.G1Affine
	rhsAff.FromJacobian(&rhs)
	return zG.Equal(&rhsAff)
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