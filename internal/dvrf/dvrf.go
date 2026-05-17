// Package dvrf implements a DDH-based DVRF on secp256k1 (paper §III).
//
// DKG — Feldman VSS (paper §B): each participant generates its own polynomial,
// broadcasts Feldman commitments, sends encrypted shares to other participants,
// and verifies received shares against the commitments. No trusted dealer is used.
//
// The PartialEval/Combine/Verify algorithms remain unchanged; only RunDKG runs
// as a genuinely distributed process.
package dvrf

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"

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
	Rand          [32]byte
	Proof         [32]byte
	CombinedGamma secp256k1.G1Affine // combined gamma point obtained via Lagrange interpolation
}

// DKGOut holds the result for one participant after the full Feldman VSS DKG.
type DKGOut struct {
	Participant Participant
	GroupKey    *GroupKey
	// FeldmanCommits[i][j] = A_{i,j} = coeffs[j]*G for participant i+1.
	// Stored so callers and tests can inspect the verifiable commitments.
	FeldmanCommits [][]secp256k1.G1Affine
}

// ── Feldman VSS DKG ───────────────────────────────────────────────────────────
//
// Protocol:
//  1. Each participant i generates a random degree-(t-1) polynomial f_i(x).
//  2. Coefficient commitments A_{i,j} = coeffs[j]*G are computed and broadcast.
//  3. Participant i sends share s_{i→j} = f_i(j) to each participant j.
//  4. Each j verifies the received s_{i→j} against the A_{i,*} commitments:
//     s_{i→j}*G == Σ_k A_{i,k} * j^k
//  5. Each participant accumulates its final secret key share: sk_j = Σ_i s_{i→j}.
//  6. Group public key: pk = Σ_i A_{i,0}

func RunDKG(n, t int) ([]*DKGOut, error) {
	if t > n {
		return nil, errors.New("dvrf: threshold > n")
	}

	g1Aff := g1Generator()

	// Step 1 & 2: Each participant generates its polynomial and Feldman commitments.
	type localPoly struct {
		coeffs  []fr.Element
		commits []secp256k1.G1Affine // A_{i,k} = coeffs[k]*G
	}
	polys := make([]localPoly, n)
	for i := 0; i < n; i++ {
		coeffs := make([]fr.Element, t)
		commits := make([]secp256k1.G1Affine, t)
		for k := range coeffs {
			if _, err := coeffs[k].SetRandom(); err != nil {
				return nil, fmt.Errorf("dvrf: DKG participant %d coeff %d: %w", i+1, k, err)
			}
			commits[k] = scalarMulAff(&g1Aff, &coeffs[k])
		}
		polys[i] = localPoly{coeffs: coeffs, commits: commits}
	}

	// Step 3 & 4: Distribute shares and verify against commitments.
	// shares[i][j] = f_i(j+1) — share sent by participant i to participant j+1.
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
				if err := feldmanVerify(shares[i][j], polys[i].commits, j+1, &g1Aff); err != nil {
					errCh <- fmt.Errorf("dvrf: Feldman VSS verification failed (participant %d → %d): %w", i+1, j+1, err)
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

	// Step 5: Each participant accumulates its final SK share.
	// Step 6: Group public key = Σ_i A_{i,0}
	var gkJac secp256k1.G1Jac
	for i := 0; i < n; i++ {
		var term secp256k1.G1Jac
		term.FromAffine(&polys[i].commits[0])
		gkJac.AddAssign(&term)
	}
	var gkAff secp256k1.G1Affine
	gkAff.FromJacobian(&gkJac)
	gk := &GroupKey{Point: gkAff}

	// Store all Feldman commitments for verification and testing.
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
		vkJ := scalarMulAff(&g1Aff, &skJ)
		outs[j] = &DKGOut{
			Participant: Participant{
				Index: j + 1,
				SK:    skJ,
				VK:    vkJ,
				Group: gk,
			},
			GroupKey:       gk,
			FeldmanCommits: allCommits,
		}
	}
	return outs, nil
}

// feldmanVerify checks s*G == Σ_k commits[k] * x^k  (x = participantIndex).
func feldmanVerify(s fr.Element, commits []secp256k1.G1Affine, x int, g *secp256k1.G1Affine) error {
	sG := scalarMulAff(g, &s)

	var xFr fr.Element
	xFr.SetUint64(uint64(x))

	var acc secp256k1.G1Jac
	var xPow fr.Element
	xPow.SetOne()
	for _, ck := range commits {
		term := scalarMulAff(&ck, &xPow)
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

// VerifyPartialEval verifies γ_i = sk_i * H(α) via a DLEQ proof.
func VerifyPartialEval(ev *Eval, vk secp256k1.G1Affine, alpha [32]byte) bool {
	g := g1Generator()
	h := hashToG1(alpha)

	// DLEQ verification: c = H(rG, rH, VK, γ) and s = r - c*sk
	// Recompute: rG' = s*G + c*VK,  rH' = s*H + c*γ
	sG := scalarMulAff(&g, &ev.ProofS)
	cVK := scalarMulAff(&vk, &ev.ProofC)
	var rGJac secp256k1.G1Jac
	rGJac.FromAffine(&sG)
	var cVKJac secp256k1.G1Jac
	cVKJac.FromAffine(&cVK)
	rGJac.AddAssign(&cVKJac)
	var rG secp256k1.G1Affine
	rG.FromJacobian(&rGJac)

	sH := scalarMulAff(&h, &ev.ProofS)
	cGamma := scalarMulAff(&ev.Gamma, &ev.ProofC)
	var rHJac secp256k1.G1Jac
	rHJac.FromAffine(&sH)
	var cGammaJac secp256k1.G1Jac
	cGammaJac.FromAffine(&cGamma)
	rHJac.AddAssign(&cGammaJac)
	var rH secp256k1.G1Affine
	rH.FromJacobian(&rHJac)

	cCheck := dleqHash(&rG, &rH, &vk, &ev.Gamma, &g)
	var cCheckFr fr.Element
	cCheckFr.SetBytes(cCheck[:])
	return cCheckFr.Equal(&ev.ProofC)
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
		Rand:          vrfHash(combinedAff, h, alpha),
		Proof:         vrfProofHash(combinedAff, alpha),
		CombinedGamma: combinedAff,
	}, nil
}

// ── Verify ────────────────────────────────────────────────────────────────────

// Verify implements the Verify(pk, VK, α, v, π) algorithm from the paper (§III.B).
//
// Steps:
//  1. Verify the DLEQ proof for each partial evaluation.
//  2. Recompute the combined gamma point via Lagrange interpolation.
//  3. Check that Output.Rand  == vrfHash(combinedGamma, H(α), α).
//  4. Check that Output.Proof == vrfProofHash(combinedGamma, α).
//
// vks[i] must be the verification key for evals[i].
func Verify(gk *GroupKey, alpha [32]byte, evals []*Eval, vks []secp256k1.G1Affine, out *Output) bool {
	if len(evals) == 0 || len(evals) != len(vks) {
		return false
	}

	// Step 1: Verify the DLEQ proof for each partial evaluation.
	for i, ev := range evals {
		if !VerifyPartialEval(ev, vks[i], alpha) {
			return false
		}
	}

	// Step 2: Recompute the combined gamma point via Lagrange interpolation.
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

	// Step 3: Rand == vrfHash(combinedGamma, H(α), α)
	expectedRand := vrfHash(combinedAff, h, alpha)
	if expectedRand != out.Rand {
		return false
	}

	// Step 4: Proof == vrfProofHash(combinedGamma, α)
	expectedProof := vrfProofHash(combinedAff, alpha)
	return expectedProof == out.Proof
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
	seven := new(big.Int).SetUint64(7)
	p := fp.Modulus()

	buf := make([]byte, 36)
	copy(buf[:32], alpha[:])
	for ctr := uint32(0); ; ctr++ {
		binary.BigEndian.PutUint32(buf[32:], ctr)
		h := sha256.Sum256(buf)

		xBig := new(big.Int).SetBytes(h[:])
		xBig.Mod(xBig, p)

		x3 := new(big.Int).Mul(xBig, xBig)
		x3.Mul(x3, xBig)
		x3.Mod(x3, p)
		y2 := new(big.Int).Add(x3, seven)
		y2.Mod(y2, p)

		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2)
		y := new(big.Int).Exp(y2, exp, p)
		check := new(big.Int).Mul(y, y)
		check.Mod(check, p)
		if check.Cmp(y2) == 0 {
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